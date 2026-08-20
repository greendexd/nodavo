#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/hidsystem/ev_keymap.h>
#import <IOKit/hidsystem/IOLLEvent.h>
#import <Security/Security.h>
#import <xpc/xpc.h>

#include <arpa/inet.h>
#include <bsm/libbsm.h>
#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <dispatch/dispatch.h>
#include <limits.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

enum {
    NDV_IPC_OK = 0,
    NDV_IPC_REJECTED = 1,
};

enum {
    NDV_RECEIVE_DESTINATION_OK = 0,
    NDV_RECEIVE_DESTINATION_UNAVAILABLE = 1,
    NDV_RECEIVE_DESTINATION_PERMISSION_DENIED = 2,
    NDV_RECEIVE_DESTINATION_INVALID = 3,
};

enum {
    NDV_UPDATE_OK = 0,
    NDV_UPDATE_ENTRY_REJECTED = 1,
    NDV_UPDATE_LAYOUT_REJECTED = 2,
    NDV_UPDATE_IDENTITY_REJECTED = 3,
    NDV_UPDATE_SIGNATURE_REJECTED = 4,
    NDV_UPDATE_SYSTEM_POLICY_REJECTED = 9,
    NDV_UPDATE_VERSION_CAPACITY = 129,
    NDV_UPDATE_BUILD_CAPACITY = 65,
    NDV_UPDATE_CDHASH_BYTES = 20,
    NDV_UPDATE_TREE_HASH_BYTES = CC_SHA256_DIGEST_LENGTH,
    NDV_UPDATE_CRITICAL_HANDLES = 6,
    NDV_UPDATE_MAX_TREE_ENTRIES = 65536,
    NDV_UPDATE_MAX_TREE_DEPTH = 64,
};

typedef struct {
    uint64_t device;
    uint64_t inode;
} NdvUpdateIdentity;

typedef struct {
    NdvUpdateIdentity identity;
    uint8_t app_code_directory_hash[NDV_UPDATE_CDHASH_BYTES];
    uint8_t agent_code_directory_hash[NDV_UPDATE_CDHASH_BYTES];
    uint8_t tree_hash[NDV_UPDATE_TREE_HASH_BYTES];
    uint8_t tree_generation_hash[NDV_UPDATE_TREE_HASH_BYTES];
    int32_t critical_fds[NDV_UPDATE_CRITICAL_HANDLES];
    uint8_t require_effective_user_owner;
    char version[NDV_UPDATE_VERSION_CAPACITY];
    char build[NDV_UPDATE_BUILD_CAPACITY];
} NdvUpdateBundleClaims;

enum {
    NDV_AUDIT_TOKEN_WORDS = 8,
    NDV_SIGNING_IDENTIFIER_CAPACITY = 128,
    NDV_TEAM_IDENTIFIER_CAPACITY = 32,
    NDV_APPLICATION_IDENTIFIER_CAPACITY = 192,
};

typedef struct {
    uint32_t words[NDV_AUDIT_TOKEN_WORDS];
} NdvAuditToken;

typedef struct {
    uint32_t static_flags;
    uint32_t dynamic_status;
    uint8_t external_requirement_valid;
    uint8_t designated_requirement_valid;
    uint8_t certificate_chain_present;
    uint8_t cms_present;
    uint8_t get_task_allow;
    char signing_identifier[NDV_SIGNING_IDENTIFIER_CAPACITY];
    char team_identifier[NDV_TEAM_IDENTIFIER_CAPACITY];
    char secured_bundle_identifier[NDV_SIGNING_IDENTIFIER_CAPACITY];
    char application_identifier[NDV_APPLICATION_IDENTIFIER_CAPACITY];
} NdvCodeSignatureClaims;

_Static_assert(sizeof(audit_token_t) == sizeof(NdvAuditToken),
               "audit token ABI size mismatch");

static bool ndv_update_no_extended_acl(int descriptor);

static bool ndv_receive_destination_permission_error(NSError *error) {
    if (error == nil) {
        return false;
    }
    if ([error.domain isEqualToString:NSCocoaErrorDomain]) {
        return error.code == NSFileReadNoPermissionError ||
               error.code == NSFileWriteNoPermissionError;
    }
    if ([error.domain isEqualToString:NSPOSIXErrorDomain]) {
        return error.code == EACCES || error.code == EPERM;
    }
    return false;
}

int32_t ndv_resolve_user_downloads_directory(char *output_utf8,
                                             size_t output_capacity) {
    if (output_utf8 == NULL || output_capacity < 2) {
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    memset(output_utf8, 0, output_capacity);
    @autoreleasepool {
        NSError *error = nil;
        NSURL *downloads = [[NSFileManager defaultManager]
            URLForDirectory:NSDownloadsDirectory
                   inDomain:NSUserDomainMask
          appropriateForURL:nil
                     create:NO
                      error:&error];
        if (downloads == nil) {
            return ndv_receive_destination_permission_error(error)
                       ? NDV_RECEIVE_DESTINATION_PERMISSION_DENIED
                       : NDV_RECEIVE_DESTINATION_UNAVAILABLE;
        }
        if (!downloads.isFileURL ||
            ![downloads getFileSystemRepresentation:output_utf8
                                           maxLength:output_capacity] ||
            output_utf8[0] == '\0') {
            memset(output_utf8, 0, output_capacity);
            return NDV_RECEIVE_DESTINATION_INVALID;
        }
        return NDV_RECEIVE_DESTINATION_OK;
    }
}

static int32_t ndv_receive_destination_status_for_errno(int error) {
    if (error == EACCES || error == EPERM) {
        return NDV_RECEIVE_DESTINATION_PERMISSION_DENIED;
    }
    if (error == ELOOP || error == ENOTDIR || error == EINVAL ||
        error == ENAMETOOLONG) {
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    return NDV_RECEIVE_DESTINATION_UNAVAILABLE;
}

static int32_t ndv_open_absolute_directory_no_follow(const char *path_utf8,
                                                     int *out_descriptor) {
    if (path_utf8 == NULL || out_descriptor == NULL) {
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    *out_descriptor = -1;
    size_t path_length = strnlen(path_utf8, 4096);
    if (path_length < 2 || path_length >= 4096 || path_utf8[0] != '/' ||
        path_utf8[path_length - 1] == '/') {
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) {
        return ndv_receive_destination_status_for_errno(errno);
    }
    const char *cursor = path_utf8 + 1;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, '/');
        size_t length = separator == NULL
                            ? strlen(cursor)
                            : (size_t)(separator - cursor);
        if (length == 0 || length > NAME_MAX ||
            (length == 1 && cursor[0] == '.') ||
            (length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
            close(current);
            return NDV_RECEIVE_DESTINATION_INVALID;
        }
        char component[NAME_MAX + 1];
        memcpy(component, cursor, length);
        component[length] = '\0';
        int next = openat(current,
                          component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            int saved_error = errno;
            close(current);
            return ndv_receive_destination_status_for_errno(saved_error);
        }
        close(current);
        current = next;
        if (separator == NULL) {
            break;
        }
        cursor = separator + 1;
    }
    *out_descriptor = current;
    return NDV_RECEIVE_DESTINATION_OK;
}

int32_t ndv_prepare_receive_destination(const char *downloads_path_utf8,
                                        int32_t *out_descriptor) {
    if (out_descriptor == NULL) {
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    *out_descriptor = -1;
    int downloads = -1;
    int32_t status = ndv_open_absolute_directory_no_follow(downloads_path_utf8,
                                                           &downloads);
    if (status != NDV_RECEIVE_DESTINATION_OK) {
        return status;
    }
    bool created = false;
    if (mkdirat(downloads, "Nodavo", 0700) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        int saved_error = errno;
        close(downloads);
        return ndv_receive_destination_status_for_errno(saved_error);
    }
    int destination = openat(downloads,
                             "Nodavo",
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved_error = errno;
    close(downloads);
    if (destination < 0) {
        return ndv_receive_destination_status_for_errno(saved_error);
    }
    if (created && fchmod(destination, 0700) != 0) {
        saved_error = errno;
        close(destination);
        return ndv_receive_destination_status_for_errno(saved_error);
    }
    struct stat metadata;
    if (fstat(destination, &metadata) != 0) {
        saved_error = errno;
        close(destination);
        return ndv_receive_destination_status_for_errno(saved_error);
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0777) != 0700 ||
        !ndv_update_no_extended_acl(destination)) {
        close(destination);
        return NDV_RECEIVE_DESTINATION_INVALID;
    }
    *out_descriptor = destination;
    return NDV_RECEIVE_DESTINATION_OK;
}

static bool ndv_copy_optional_utf8(id value, char *output, size_t capacity) {
    if (output == NULL || capacity == 0) {
        return false;
    }
    memset(output, 0, capacity);
    if (value == nil) {
        return true;
    }
    if (![value isKindOfClass:NSString.class]) {
        return false;
    }
    NSData *encoded = [(NSString *)value dataUsingEncoding:NSUTF8StringEncoding
                                      allowLossyConversion:NO];
    if (encoded == nil || encoded.length == 0 || encoded.length >= capacity ||
        memchr(encoded.bytes, '\0', encoded.length) != NULL) {
        return false;
    }
    memcpy(output, encoded.bytes, encoded.length);
    return true;
}

static bool ndv_copy_u32(id value, uint32_t *output) {
    if (output == NULL || ![value isKindOfClass:NSNumber.class]) {
        return false;
    }
    unsigned long long scalar = [(NSNumber *)value unsignedLongLongValue];
    if (scalar > UINT32_MAX) {
        return false;
    }
    *output = (uint32_t)scalar;
    return true;
}

static bool ndv_update_valid_leaf(const char *leaf) {
    if (leaf == NULL || leaf[0] == '\0' || strcmp(leaf, ".") == 0 ||
        strcmp(leaf, "..") == 0 || strlen(leaf) > NAME_MAX) {
        return false;
    }
    return strchr(leaf, '/') == NULL;
}

#define NDV_UPDATE_MAX_FILE_BYTES (1ULL << 30)
#define NDV_UPDATE_MAX_TREE_BYTES (4ULL << 30)

typedef struct {
    char **values;
    size_t count;
    size_t capacity;
} NdvUpdateNameList;

typedef struct {
    CC_SHA256_CTX stable;
    CC_SHA256_CTX tree_generation;
    uint64_t entries;
    uint64_t bytes;
    bool require_effective_user_owner;
} NdvUpdateTreeHasher;

static const char *const ndv_update_critical_paths[NDV_UPDATE_CRITICAL_HANDLES] = {
    "Contents/MacOS/Nodavo",
    "Contents/Info.plist",
    "Contents/Library/Helpers/NodavoAgent.app",
    "Contents/Library/Helpers/NodavoAgent.app/Contents/MacOS/nodavo-agent",
    "Contents/Library/Helpers/NodavoAgent.app/Contents/Info.plist",
    "Contents/Library/LaunchAgents/dev.nodavo.agent.plist",
};

static const bool ndv_update_critical_directories[NDV_UPDATE_CRITICAL_HANDLES] = {
    false, false, true, false, false, false,
};

static bool ndv_update_no_extended_acl(int descriptor) {
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        /* APFS reports ENOENT when the vnode has no extended ACL. */
        return errno == ENOENT;
    }
    acl_entry_t entry = NULL;
    errno = 0;
    int entry_status = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    bool empty = entry_status < 0 && errno == EINVAL;
    acl_free(acl);
    return empty;
}

static bool ndv_update_owner_is_allowed(uid_t owner,
                                        bool require_effective_user_owner) {
    uid_t effective_user = geteuid();
    return require_effective_user_owner
               ? owner == effective_user
               : owner == effective_user || owner == 0;
}

static bool ndv_update_sealed_status(const struct stat *status,
                                     bool directory,
                                     bool require_effective_user_owner) {
    if (status == NULL ||
        (directory ? !S_ISDIR(status->st_mode) : !S_ISREG(status->st_mode)) ||
        !ndv_update_owner_is_allowed(status->st_uid,
                                     require_effective_user_owner) ||
        (status->st_mode & 0222) != 0) {
        return false;
    }
    return directory || status->st_nlink == 1;
}

static bool ndv_update_same_vnode(const struct stat *first,
                                  const struct stat *second) {
    return first->st_dev == second->st_dev &&
           first->st_ino == second->st_ino &&
           first->st_mode == second->st_mode &&
           first->st_uid == second->st_uid &&
           first->st_gid == second->st_gid &&
           first->st_size == second->st_size &&
           first->st_flags == second->st_flags &&
           first->st_mtimespec.tv_sec == second->st_mtimespec.tv_sec &&
           first->st_mtimespec.tv_nsec == second->st_mtimespec.tv_nsec &&
           first->st_ctimespec.tv_sec == second->st_ctimespec.tv_sec &&
           first->st_ctimespec.tv_nsec == second->st_ctimespec.tv_nsec;
}

static bool ndv_update_hash_bytes(CC_SHA256_CTX *context,
                                  const void *bytes,
                                  size_t length) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        CC_LONG chunk = length > UINT32_MAX ? UINT32_MAX : (CC_LONG)length;
        if (CC_SHA256_Update(context, cursor, chunk) != 1) {
            return false;
        }
        cursor += chunk;
        length -= chunk;
    }
    return true;
}

static bool ndv_update_hash_u64(CC_SHA256_CTX *context, uint64_t value) {
    uint8_t encoded[8];
    for (size_t index = 0; index < sizeof(encoded); ++index) {
        encoded[sizeof(encoded) - index - 1] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
    return ndv_update_hash_bytes(context, encoded, sizeof(encoded));
}

static bool ndv_update_hash_stat(CC_SHA256_CTX *context,
                                 const struct stat *status,
                                 uint8_t kind,
                                 bool include_generation) {
    if (!ndv_update_hash_bytes(context, &kind, sizeof(kind)) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_dev) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_ino) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_mode) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_uid) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_gid) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_size) ||
        !ndv_update_hash_u64(context, (uint64_t)status->st_flags)) {
        return false;
    }
    return !include_generation ||
           (ndv_update_hash_u64(context, (uint64_t)status->st_mtimespec.tv_sec) &&
            ndv_update_hash_u64(context, (uint64_t)status->st_mtimespec.tv_nsec) &&
            ndv_update_hash_u64(context, (uint64_t)status->st_ctimespec.tv_sec) &&
            ndv_update_hash_u64(context, (uint64_t)status->st_ctimespec.tv_nsec));
}

static int ndv_update_compare_names(const void *left, const void *right) {
    const char *const *left_name = left;
    const char *const *right_name = right;
    return strcmp(*left_name, *right_name);
}

static void ndv_update_free_names(NdvUpdateNameList *names) {
    if (names == NULL) {
        return;
    }
    for (size_t index = 0; index < names->count; ++index) {
        free(names->values[index]);
    }
    free(names->values);
    names->values = NULL;
    names->count = 0;
    names->capacity = 0;
}

static bool ndv_update_list_names(int directory_fd, NdvUpdateNameList *out_names) {
    memset(out_names, 0, sizeof(*out_names));
    /* `dup` would share the directory-stream offset and poison later scans. */
    int duplicate = openat(directory_fd,
                           ".",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (duplicate < 0) {
        return false;
    }
    DIR *directory = fdopendir(duplicate);
    if (directory == NULL) {
        close(duplicate);
        return false;
    }
    bool valid = true;
    errno = 0;
    for (struct dirent *entry = readdir(directory);
         entry != NULL;
         entry = readdir(directory)) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            errno = 0;
            continue;
        }
        if (!ndv_update_valid_leaf(entry->d_name) ||
            out_names->count >= NDV_UPDATE_MAX_TREE_ENTRIES) {
            valid = false;
            break;
        }
        if (out_names->count == out_names->capacity) {
            size_t next_capacity = out_names->capacity == 0
                                       ? 16
                                       : out_names->capacity * 2;
            if (next_capacity > NDV_UPDATE_MAX_TREE_ENTRIES) {
                next_capacity = NDV_UPDATE_MAX_TREE_ENTRIES;
            }
            char **grown = realloc(out_names->values,
                                   next_capacity * sizeof(*grown));
            if (grown == NULL) {
                valid = false;
                break;
            }
            out_names->values = grown;
            out_names->capacity = next_capacity;
        }
        out_names->values[out_names->count] = strdup(entry->d_name);
        if (out_names->values[out_names->count] == NULL) {
            valid = false;
            break;
        }
        out_names->count += 1;
        errno = 0;
    }
    if (errno != 0) {
        valid = false;
    }
    closedir(directory);
    if (!valid) {
        ndv_update_free_names(out_names);
        return false;
    }
    qsort(out_names->values,
          out_names->count,
          sizeof(*out_names->values),
          ndv_update_compare_names);
    return true;
}

static bool ndv_update_hash_tree_fd(int descriptor,
                                    bool directory,
                                    const char *name,
                                    uint32_t depth,
                                    NdvUpdateTreeHasher *hasher);

static bool ndv_update_hash_regular_file(int descriptor,
                                         const struct stat *before,
                                         NdvUpdateTreeHasher *hasher) {
    if (before->st_size < 0 ||
        (uint64_t)before->st_size > NDV_UPDATE_MAX_FILE_BYTES ||
        hasher->bytes > NDV_UPDATE_MAX_TREE_BYTES - (uint64_t)before->st_size) {
        return false;
    }
    uint8_t buffer[64 * 1024];
    off_t offset = 0;
    while (offset < before->st_size) {
        size_t requested = (uint64_t)(before->st_size - offset) > sizeof(buffer)
                               ? sizeof(buffer)
                               : (size_t)(before->st_size - offset);
        ssize_t count = pread(descriptor, buffer, requested, offset);
        if (count <= 0 ||
            !ndv_update_hash_bytes(&hasher->stable, buffer, (size_t)count)) {
            return false;
        }
        offset += count;
    }
    hasher->bytes += (uint64_t)before->st_size;
    return true;
}

static bool ndv_update_hash_tree_fd(int descriptor,
                                    bool directory,
                                    const char *name,
                                    uint32_t depth,
                                    NdvUpdateTreeHasher *hasher) {
    if (descriptor < 0 || name == NULL || hasher == NULL ||
        depth > NDV_UPDATE_MAX_TREE_DEPTH ||
        hasher->entries >= NDV_UPDATE_MAX_TREE_ENTRIES) {
        return false;
    }
    struct stat before;
    memset(&before, 0, sizeof(before));
    if (fstat(descriptor, &before) != 0 ||
        !ndv_update_sealed_status(&before,
                                  directory,
                                  hasher->require_effective_user_owner) ||
        !ndv_update_no_extended_acl(descriptor)) {
        return false;
    }
    size_t name_length = strlen(name);
    uint8_t kind = directory ? 'D' : 'F';
    if (!ndv_update_hash_u64(&hasher->stable, name_length) ||
        !ndv_update_hash_bytes(&hasher->stable, name, name_length) ||
        !ndv_update_hash_stat(&hasher->stable, &before, kind, false) ||
        !ndv_update_hash_u64(&hasher->tree_generation, name_length) ||
        !ndv_update_hash_bytes(&hasher->tree_generation, name, name_length) ||
        !ndv_update_hash_stat(&hasher->tree_generation,
                              &before,
                              kind,
                              true)) {
        return false;
    }
    hasher->entries += 1;

    bool valid = true;
    if (directory) {
        NdvUpdateNameList names;
        if (!ndv_update_list_names(descriptor, &names)) {
            return false;
        }
        for (size_t index = 0; valid && index < names.count; ++index) {
            struct stat named;
            memset(&named, 0, sizeof(named));
            if (fstatat(descriptor,
                        names.values[index],
                        &named,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                (!S_ISDIR(named.st_mode) && !S_ISREG(named.st_mode))) {
                valid = false;
                break;
            }
            bool child_directory = S_ISDIR(named.st_mode);
            int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
            if (child_directory) {
                flags |= O_DIRECTORY;
            }
            int child = openat(descriptor, names.values[index], flags);
            struct stat opened;
            memset(&opened, 0, sizeof(opened));
            if (child < 0 || fstat(child, &opened) != 0 ||
                named.st_dev != opened.st_dev || named.st_ino != opened.st_ino ||
                !ndv_update_hash_tree_fd(child,
                                         child_directory,
                                         names.values[index],
                                         depth + 1,
                                         hasher)) {
                valid = false;
            }
            if (child >= 0) {
                close(child);
            }
        }
        ndv_update_free_names(&names);
    } else {
        valid = ndv_update_hash_regular_file(descriptor, &before, hasher);
    }

    struct stat after;
    memset(&after, 0, sizeof(after));
    return valid && fstat(descriptor, &after) == 0 &&
           ndv_update_same_vnode(&before, &after);
}

static bool ndv_update_observe_sealed_tree_fd(
    int bundle_fd,
    bool require_effective_user_owner,
    uint8_t out_tree_hash[NDV_UPDATE_TREE_HASH_BYTES],
    uint8_t out_tree_generation_hash[NDV_UPDATE_TREE_HASH_BYTES]) {
    NdvUpdateTreeHasher hasher;
    memset(&hasher, 0, sizeof(hasher));
    hasher.require_effective_user_owner = require_effective_user_owner;
    static const uint8_t stable_domain[] = "Nodavo sealed app tree v1";
    static const uint8_t generation_domain[] = "Nodavo sealed tree generation v1";
    if (CC_SHA256_Init(&hasher.stable) != 1 ||
        CC_SHA256_Init(&hasher.tree_generation) != 1 ||
        !ndv_update_hash_bytes(&hasher.stable,
                               stable_domain,
                               sizeof(stable_domain) - 1) ||
        !ndv_update_hash_bytes(&hasher.tree_generation,
                               generation_domain,
                               sizeof(generation_domain) - 1) ||
        !ndv_update_hash_tree_fd(bundle_fd, true, "", 0, &hasher) ||
        CC_SHA256_Final(out_tree_hash, &hasher.stable) != 1 ||
        CC_SHA256_Final(out_tree_generation_hash,
                        &hasher.tree_generation) != 1) {
        return false;
    }
    return true;
}

static int ndv_update_open_relative(int root_fd,
                                    const char *relative_path,
                                    bool final_directory) {
    if (root_fd < 0 || relative_path == NULL || relative_path[0] == '/' ||
        relative_path[0] == '\0' || strlen(relative_path) >= PATH_MAX) {
        return -1;
    }
    char mutable_path[PATH_MAX];
    strlcpy(mutable_path, relative_path, sizeof(mutable_path));
    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0) {
        return -1;
    }
    char *save = NULL;
    char *component = strtok_r(mutable_path, "/", &save);
    while (component != NULL) {
        char *next = strtok_r(NULL, "/", &save);
        if (!ndv_update_valid_leaf(component)) {
            close(current);
            return -1;
        }
        bool directory = next != NULL || final_directory;
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        if (directory) {
            flags |= O_DIRECTORY;
        }
        int child = openat(current, component, flags);
        close(current);
        if (child < 0) {
            return -1;
        }
        current = child;
        component = next;
    }
    return current;
}

static void ndv_update_close_critical_fds(
    int32_t descriptors[NDV_UPDATE_CRITICAL_HANDLES]) {
    for (size_t index = 0; index < NDV_UPDATE_CRITICAL_HANDLES; ++index) {
        if (descriptors[index] >= 0) {
            close(descriptors[index]);
            descriptors[index] = -1;
        }
    }
}

static bool ndv_update_open_critical_fds(
    int bundle_fd,
    int32_t out_descriptors[NDV_UPDATE_CRITICAL_HANDLES]) {
    for (size_t index = 0; index < NDV_UPDATE_CRITICAL_HANDLES; ++index) {
        out_descriptors[index] = -1;
    }
    for (size_t index = 0; index < NDV_UPDATE_CRITICAL_HANDLES; ++index) {
        int descriptor = ndv_update_open_relative(
            bundle_fd,
            ndv_update_critical_paths[index],
            ndv_update_critical_directories[index]);
        if (descriptor < 0) {
            ndv_update_close_critical_fds(out_descriptors);
            return false;
        }
        out_descriptors[index] = descriptor;
    }
    return true;
}

static bool ndv_update_same_open_vnode(int first_fd, int second_fd) {
    struct stat first;
    struct stat second;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    return first_fd >= 0 && second_fd >= 0 &&
           fstat(first_fd, &first) == 0 && fstat(second_fd, &second) == 0 &&
           first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

static bool ndv_update_copy_required_utf8(id value,
                                          const char *expected,
                                          char *output,
                                          size_t capacity) {
    if (expected == NULL || !ndv_copy_optional_utf8(value, output, capacity)) {
        return false;
    }
    return strcmp(output, expected) == 0;
}

static bool ndv_update_identity_at(int directory_fd,
                                   const char *leaf,
                                   NdvUpdateIdentity *out_identity) {
    if (directory_fd < 0 || !ndv_update_valid_leaf(leaf) ||
        out_identity == NULL) {
        return false;
    }
    struct stat status;
    memset(&status, 0, sizeof(status));
    if (fstatat(directory_fd, leaf, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(status.st_mode)) {
        return false;
    }
    out_identity->device = (uint64_t)status.st_dev;
    out_identity->inode = (uint64_t)status.st_ino;
    return true;
}

int32_t ndv_update_open_directory(const char *path_utf8,
                                  bool require_private,
                                  int *out_fd,
                                  NdvUpdateIdentity *out_identity) {
    if (path_utf8 == NULL || path_utf8[0] != '/' ||
        (strlen(path_utf8) > 1 && path_utf8[strlen(path_utf8) - 1] == '/') ||
        out_fd == NULL ||
        out_identity == NULL) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    *out_fd = -1;
    memset(out_identity, 0, sizeof(*out_identity));
    int descriptor = open(path_utf8, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    struct stat status;
    memset(&status, 0, sizeof(status));
    if (fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) {
        close(descriptor);
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    if (require_private) {
        bool rejected = status.st_uid != geteuid() ||
                        (status.st_mode & 0077) != 0 ||
                        !ndv_update_no_extended_acl(descriptor);
        if (rejected) {
            close(descriptor);
            return NDV_UPDATE_ENTRY_REJECTED;
        }
    }
    out_identity->device = (uint64_t)status.st_dev;
    out_identity->inode = (uint64_t)status.st_ino;
    *out_fd = descriptor;
    return NDV_UPDATE_OK;
}

static bool ndv_update_path_has_type(NSString *path, bool directory) {
    struct stat status;
    memset(&status, 0, sizeof(status));
    if (lstat(path.fileSystemRepresentation, &status) != 0) {
        return false;
    }
    return directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode);
}

static uint32_t ndv_update_fat_u32(uint32_t value, bool swap) {
    return swap ? ntohl(value) : value;
}

static uint64_t ndv_update_fat_u64(uint64_t value, bool swap) {
    return swap ? __builtin_bswap64(value) : value;
}

/* Production bundles must contain exactly one arm64 and one x86_64 slice. */
static bool ndv_update_exact_universal_binary(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    struct stat status;
    struct fat_header header;
    bool valid = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
                 pread(fd, &header, sizeof(header), 0) == sizeof(header);
    bool is_64 = false;
    bool swap = false;
    if (valid) {
        if (header.magic == FAT_MAGIC || header.magic == FAT_MAGIC_64) {
            is_64 = header.magic == FAT_MAGIC_64;
        } else if (header.magic == FAT_CIGAM || header.magic == FAT_CIGAM_64) {
            swap = true;
            is_64 = header.magic == FAT_CIGAM_64;
        } else {
            valid = false;
        }
    }
    uint32_t count = valid ? ndv_update_fat_u32(header.nfat_arch, swap) : 0;
    valid = valid && count == 2;
    bool arm64 = false;
    bool x86_64 = false;
    for (uint32_t index = 0; valid && index < count; ++index) {
        cpu_type_t cpu = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
        if (is_64) {
            struct fat_arch_64 architecture;
            off_t position = sizeof(header) + (off_t)index * sizeof(architecture);
            if (pread(fd, &architecture, sizeof(architecture), position) != sizeof(architecture)) {
                valid = false;
                break;
            }
            cpu = (cpu_type_t)ndv_update_fat_u32((uint32_t)architecture.cputype, swap);
            offset = ndv_update_fat_u64(architecture.offset, swap);
            size = ndv_update_fat_u64(architecture.size, swap);
        } else {
            struct fat_arch architecture;
            off_t position = sizeof(header) + (off_t)index * sizeof(architecture);
            if (pread(fd, &architecture, sizeof(architecture), position) != sizeof(architecture)) {
                valid = false;
                break;
            }
            cpu = (cpu_type_t)ndv_update_fat_u32((uint32_t)architecture.cputype, swap);
            offset = ndv_update_fat_u32(architecture.offset, swap);
            size = ndv_update_fat_u32(architecture.size, swap);
        }
        if (size == 0 || offset > (uint64_t)status.st_size ||
            size > (uint64_t)status.st_size - offset) {
            valid = false;
        } else if (cpu == CPU_TYPE_ARM64 && !arm64) {
            arm64 = true;
        } else if (cpu == CPU_TYPE_X86_64 && !x86_64) {
            x86_64 = true;
        } else {
            valid = false;
        }
    }
    close(fd);
    return valid && arm64 && x86_64;
}

static bool ndv_update_copy_code_hash(NSDictionary *information,
                                      uint8_t output[NDV_UPDATE_CDHASH_BYTES]) {
    id value = information[(__bridge NSString *)kSecCodeInfoUnique];
    if (![value isKindOfClass:NSData.class] ||
        [(NSData *)value length] != NDV_UPDATE_CDHASH_BYTES) {
        return false;
    }
    memcpy(output, [(NSData *)value bytes], NDV_UPDATE_CDHASH_BYTES);
    return true;
}

static bool ndv_update_exact_string(id value, const char *expected) {
    return expected != NULL && [value isKindOfClass:NSString.class] &&
           [(NSString *)value isEqualToString:@(expected)];
}

static bool ndv_update_exact_bool(id value, bool expected) {
    return [value isKindOfClass:NSNumber.class] &&
           [(NSNumber *)value boolValue] == expected;
}

/* Fixed, non-shell System Policy assessment. No caller controls the executable. */
static bool ndv_update_assess_system_policy(NSString *bundle_path) {
    NSString *tool_path = @"/usr/sbin/spctl";
    if (access(tool_path.fileSystemRepresentation, X_OK) != 0) {
        return false;
    }
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:tool_path];
    task.arguments = @[@"--assess", @"--type", @"execute", @"--ignore-cache",
                       @"--no-cache", @"--", bundle_path];
    task.environment = @{};
    NSFileHandle *null_device = [NSFileHandle fileHandleWithNullDevice];
    task.standardInput = null_device;
    task.standardOutput = null_device;
    task.standardError = null_device;
    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    task.terminationHandler = ^(__unused NSTask *finished) {
        dispatch_semaphore_signal(completed);
    };
    NSError *launch_error = nil;
    if (![task launchAndReturnError:&launch_error]) {
        return false;
    }
    if (dispatch_semaphore_wait(completed,
                                dispatch_time(DISPATCH_TIME_NOW,
                                              30LL * NSEC_PER_SEC)) != 0) {
        [task terminate];
        return false;
    }
    return task.terminationReason == NSTaskTerminationReasonExit &&
           task.terminationStatus == 0;
}

static int32_t ndv_update_validate_code(
    NSString *path,
    const char *requirement_utf8,
    const char *identifier_utf8,
    const char *executable_utf8,
    const char *team_identifier_utf8,
    const char *version_utf8,
    const char *build_utf8,
    const char *nullable_keychain_access_group_utf8,
    bool require_stapled_notarization,
    NSDictionary **out_secured_plist,
    uint8_t out_code_directory_hash[NDV_UPDATE_CDHASH_BYTES]) {
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef signing_information = NULL;
    CFErrorRef validation_error = NULL;
    int32_t result = NDV_UPDATE_SIGNATURE_REJECTED;
    @try {
        do {
            if (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],
                                            kSecCSDefaultFlags,
                                            &code) != errSecSuccess ||
                code == NULL) {
                break;
            }
            NSString *requirement_string = @(requirement_utf8);
            if (SecRequirementCreateWithString((__bridge CFStringRef)requirement_string,
                                               kSecCSDefaultFlags,
                                               &requirement) != errSecSuccess ||
                requirement == NULL) {
                break;
            }
            SecCSFlags validation_flags =
                kSecCSCheckAllArchitectures | kSecCSCheckNestedCode |
                kSecCSStrictValidate | kSecCSRestrictSymlinks |
                kSecCSRestrictToAppLike;
            if (SecStaticCodeCheckValidityWithErrors(code,
                                                     validation_flags,
                                                     requirement,
                                                     &validation_error) !=
                errSecSuccess) {
                break;
            }
            if (SecCodeCopySigningInformation(code,
                                              kSecCSSigningInformation |
                                                  kSecCSContentInformation,
                                              &signing_information) != errSecSuccess ||
                signing_information == NULL) {
                break;
            }
            NSDictionary *information = (__bridge NSDictionary *)signing_information;
            NSDictionary *secured_plist = information[(__bridge NSString *)kSecCodeInfoPList];
            NSDictionary *entitlements =
                information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
            NSNumber *code_flags =
                information[(__bridge NSString *)kSecCodeInfoFlags];
            NSUInteger expected_entitlement_count =
                nullable_keychain_access_group_utf8 == NULL ? 2 : 3;
            if (![secured_plist isKindOfClass:NSDictionary.class] ||
                ![entitlements isKindOfClass:NSDictionary.class] ||
                entitlements.count != expected_entitlement_count ||
                ![code_flags isKindOfClass:NSNumber.class] ||
                (code_flags.unsignedIntValue & kSecCodeSignatureRuntime) == 0 ||
                !ndv_update_exact_string(
                    information[(__bridge NSString *)kSecCodeInfoIdentifier],
                    identifier_utf8) ||
                !ndv_update_exact_string(
                    information[(__bridge NSString *)kSecCodeInfoTeamIdentifier],
                    team_identifier_utf8) ||
                !ndv_update_exact_string(secured_plist[@"CFBundleIdentifier"],
                                         identifier_utf8) ||
                !ndv_update_exact_string(secured_plist[@"CFBundleExecutable"],
                                         executable_utf8) ||
                !ndv_update_exact_string(secured_plist[@"CFBundlePackageType"], "APPL") ||
                !ndv_update_exact_string(secured_plist[@"CFBundleShortVersionString"],
                                         version_utf8) ||
                !ndv_update_exact_string(secured_plist[@"CFBundleVersion"], build_utf8)) {
                result = NDV_UPDATE_IDENTITY_REJECTED;
                break;
            }
            NSString *application_identifier =
                [NSString stringWithFormat:@"%s.%s",
                                           team_identifier_utf8,
                                           identifier_utf8];
            if (![entitlements[@"com.apple.application-identifier"]
                    isEqual:application_identifier] ||
                !ndv_update_exact_string(
                    entitlements[@"com.apple.developer.team-identifier"],
                    team_identifier_utf8) ||
                entitlements[@"com.apple.security.get-task-allow"] != nil) {
                result = NDV_UPDATE_IDENTITY_REJECTED;
                break;
            }
            id keychain_groups = entitlements[@"keychain-access-groups"];
            if (nullable_keychain_access_group_utf8 == NULL) {
                if (keychain_groups != nil) {
                    result = NDV_UPDATE_IDENTITY_REJECTED;
                    break;
                }
            } else {
                NSString *expected_group = @(nullable_keychain_access_group_utf8);
                if (![keychain_groups isKindOfClass:NSArray.class] ||
                    [(NSArray *)keychain_groups count] != 1 ||
                    ![[(NSArray *)keychain_groups firstObject] isEqual:expected_group]) {
                    result = NDV_UPDATE_IDENTITY_REJECTED;
                    break;
                }
            }
            if (![information[(__bridge NSString *)kSecCodeInfoCertificates]
                    isKindOfClass:NSArray.class] ||
                [(NSArray *)information[(__bridge NSString *)kSecCodeInfoCertificates]
                    count] == 0 ||
                ![information[(__bridge NSString *)kSecCodeInfoCMS]
                    isKindOfClass:NSData.class] ||
                [(NSData *)information[(__bridge NSString *)kSecCodeInfoCMS] length] == 0) {
                break;
            }
            id ticket = information[(__bridge NSString *)kSecCodeInfoStapledNotarizationTicket];
            if ((require_stapled_notarization &&
                 (![ticket isKindOfClass:NSData.class] || [(NSData *)ticket length] == 0)) ||
                out_code_directory_hash == NULL ||
                !ndv_update_copy_code_hash(information, out_code_directory_hash)) {
                break;
            }
            if (out_secured_plist != NULL) {
                *out_secured_plist = [secured_plist copy];
            }
            result = NDV_UPDATE_OK;
        } while (false);
    } @catch (__unused NSException *exception) {
        result = NDV_UPDATE_SIGNATURE_REJECTED;
    } @finally {
        if (validation_error != NULL) {
            CFRelease(validation_error);
        }
        if (signing_information != NULL) {
            CFRelease(signing_information);
        }
        if (requirement != NULL) {
            CFRelease(requirement);
        }
        if (code != NULL) {
            CFRelease(code);
        }
    }
    return result;
}

static bool ndv_update_validate_launch_agent(NSString *bundle_path) {
    NSString *plist_path = [bundle_path
        stringByAppendingPathComponent:
            @"Contents/Library/LaunchAgents/dev.nodavo.agent.plist"];
    if (!ndv_update_path_has_type(plist_path, false)) {
        return false;
    }
    NSData *data = [NSData dataWithContentsOfFile:plist_path
                                          options:NSDataReadingMappedIfSafe
                                            error:nil];
    if (data == nil || data.length == 0 || data.length > 64 * 1024) {
        return false;
    }
    id decoded = [NSPropertyListSerialization propertyListWithData:data
                                                           options:NSPropertyListImmutable
                                                            format:nil
                                                             error:nil];
    if (![decoded isKindOfClass:NSDictionary.class]) {
        return false;
    }
    NSDictionary *plist = decoded;
    NSDictionary *keep_alive = plist[@"KeepAlive"];
    NSDictionary *mach_services = plist[@"MachServices"];
    NSArray *associated = plist[@"AssociatedBundleIdentifiers"];
    return plist.count == 10 &&
           [associated isKindOfClass:NSArray.class] && associated.count == 1 &&
           [associated.firstObject isEqual:@"dev.nodavo.macos"] &&
           ndv_update_exact_string(plist[@"BundleProgram"],
                                   "Contents/Library/Helpers/NodavoAgent.app/Contents/MacOS/nodavo-agent") &&
           [keep_alive isKindOfClass:NSDictionary.class] &&
           keep_alive.count == 1 &&
           ndv_update_exact_bool(keep_alive[@"SuccessfulExit"], false) &&
           ndv_update_exact_string(plist[@"Label"], "dev.nodavo.agent") &&
           ndv_update_exact_string(plist[@"LimitLoadToSessionType"], "Aqua") &&
           [mach_services isKindOfClass:NSDictionary.class] &&
           mach_services.count == 1 &&
           ndv_update_exact_bool(mach_services[@"dev.nodavo.agent.ipc"], true) &&
           ndv_update_exact_string(plist[@"ProcessType"], "Interactive") &&
           ndv_update_exact_bool(plist[@"RunAtLoad"], true) &&
           [plist[@"ThrottleInterval"] isEqual:@30] &&
           [plist[@"Umask"] isEqual:@63];
}

int32_t ndv_update_validate_nodavo_bundle(
    int directory_fd,
    const char *leaf_utf8,
    const char *team_identifier_utf8,
    const char *version_utf8,
    const char *build_utf8,
    const char *app_requirement_utf8,
    const char *agent_requirement_utf8,
    const char *keychain_access_group_utf8,
    bool require_effective_user_owner,
    NdvUpdateBundleClaims *out_claims) {
    if (directory_fd < 0 || !ndv_update_valid_leaf(leaf_utf8) ||
        team_identifier_utf8 == NULL || version_utf8 == NULL ||
        build_utf8 == NULL || app_requirement_utf8 == NULL ||
        agent_requirement_utf8 == NULL || keychain_access_group_utf8 == NULL ||
        out_claims == NULL) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    memset(out_claims, 0, sizeof(*out_claims));
    for (size_t index = 0; index < NDV_UPDATE_CRITICAL_HANDLES; ++index) {
        out_claims->critical_fds[index] = -1;
    }
    out_claims->require_effective_user_owner =
        require_effective_user_owner ? 1 : 0;
    NdvUpdateIdentity before;
    if (!ndv_update_identity_at(directory_fd, leaf_utf8, &before)) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    int bundle_fd = openat(directory_fd,
                           leaf_utf8,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (bundle_fd < 0) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    int32_t result = NDV_UPDATE_LAYOUT_REJECTED;
    uint8_t tree_before[NDV_UPDATE_TREE_HASH_BYTES];
    uint8_t generation_before[NDV_UPDATE_TREE_HASH_BYTES];
    if (!ndv_update_observe_sealed_tree_fd(bundle_fd,
                                           require_effective_user_owner,
                                           tree_before,
                                           generation_before) ||
        !ndv_update_open_critical_fds(bundle_fd,
                                      out_claims->critical_fds)) {
        close(bundle_fd);
        ndv_update_close_critical_fds(out_claims->critical_fds);
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    @autoreleasepool {
        char bundle_path_bytes[PATH_MAX];
        memset(bundle_path_bytes, 0, sizeof(bundle_path_bytes));
        if (fcntl(bundle_fd, F_GETPATH, bundle_path_bytes) != 0) {
            result = NDV_UPDATE_ENTRY_REJECTED;
        } else {
            NSString *bundle_path =
                [[NSFileManager defaultManager]
                    stringWithFileSystemRepresentation:bundle_path_bytes
                                                length:strlen(bundle_path_bytes)];
            NSString *app_executable =
                [bundle_path stringByAppendingPathComponent:@"Contents/MacOS/Nodavo"];
            NSString *app_info =
                [bundle_path stringByAppendingPathComponent:@"Contents/Info.plist"];
            NSString *agent_path = [bundle_path
                stringByAppendingPathComponent:
                    @"Contents/Library/Helpers/NodavoAgent.app"];
            NSString *agent_executable = [agent_path
                stringByAppendingPathComponent:@"Contents/MacOS/nodavo-agent"];
            NSString *agent_info =
                [agent_path stringByAppendingPathComponent:@"Contents/Info.plist"];
            if (bundle_path == nil ||
                !ndv_update_path_has_type(app_executable, false) ||
                !ndv_update_exact_universal_binary(app_executable) ||
                !ndv_update_path_has_type(app_info, false) ||
                !ndv_update_path_has_type(agent_path, true) ||
                !ndv_update_path_has_type(agent_executable, false) ||
                !ndv_update_exact_universal_binary(agent_executable) ||
                !ndv_update_path_has_type(agent_info, false) ||
                !ndv_update_validate_launch_agent(bundle_path)) {
                result = NDV_UPDATE_LAYOUT_REJECTED;
            } else {
                NSDictionary *app_plist = nil;
                result = ndv_update_validate_code(bundle_path,
                                                  app_requirement_utf8,
                                                  "dev.nodavo.macos",
                                                  "Nodavo",
                                                  team_identifier_utf8,
                                                  version_utf8,
                                                  build_utf8,
                                                  NULL,
                                                  true,
                                                  &app_plist,
                                                  out_claims->app_code_directory_hash);
                if (result == NDV_UPDATE_OK &&
                    (!ndv_update_exact_string(app_plist[@"NodavoAgentBundleIdentifier"],
                                              "dev.nodavo.agent") ||
                     !ndv_update_exact_string(app_plist[@"NodavoAgentMachService"],
                                              "dev.nodavo.agent.ipc") ||
                     !ndv_update_exact_string(app_plist[@"NodavoAppleTeamIdentifier"],
                                              team_identifier_utf8) ||
                     !ndv_update_exact_string(app_plist[@"LSMinimumSystemVersion"],
                                              "13.0") ||
                     !ndv_update_exact_bool(app_plist[@"LSUIElement"], true) ||
                     !ndv_update_exact_bool(app_plist[@"NodavoDevelopmentBuild"], false))) {
                    result = NDV_UPDATE_IDENTITY_REJECTED;
                }
                if (result == NDV_UPDATE_OK) {
                    NSDictionary *agent_plist = nil;
                    result = ndv_update_validate_code(agent_path,
                                                      agent_requirement_utf8,
                                                      "dev.nodavo.agent",
                                                      "nodavo-agent",
                                                      team_identifier_utf8,
                                                      version_utf8,
                                                      build_utf8,
                                                      keychain_access_group_utf8,
                                                      false,
                                                      &agent_plist,
                                                      out_claims->agent_code_directory_hash);
                    if (result == NDV_UPDATE_OK &&
                        (!ndv_update_exact_string(agent_plist[@"NodavoKeychainAccessGroup"],
                                                  keychain_access_group_utf8) ||
                         !ndv_update_exact_string(agent_plist[@"LSMinimumSystemVersion"],
                                                  "13.0") ||
                         !ndv_update_exact_bool(agent_plist[@"LSBackgroundOnly"], true))) {
                        result = NDV_UPDATE_IDENTITY_REJECTED;
                    }
                }
                if (result == NDV_UPDATE_OK &&
                    (!ndv_update_copy_required_utf8(app_plist[@"CFBundleShortVersionString"],
                                                    version_utf8,
                                                    out_claims->version,
                                                    sizeof(out_claims->version)) ||
                     !ndv_update_copy_required_utf8(app_plist[@"CFBundleVersion"],
                                                    build_utf8,
                                                    out_claims->build,
                                                    sizeof(out_claims->build)))) {
                    result = NDV_UPDATE_IDENTITY_REJECTED;
                }
                if (result == NDV_UPDATE_OK &&
                    !ndv_update_assess_system_policy(bundle_path)) {
                    result = NDV_UPDATE_SYSTEM_POLICY_REJECTED;
                }
            }
        }
    }
    uint8_t tree_after[NDV_UPDATE_TREE_HASH_BYTES];
    uint8_t generation_after[NDV_UPDATE_TREE_HASH_BYTES];
    int32_t current_critical[NDV_UPDATE_CRITICAL_HANDLES];
    for (size_t index = 0; index < NDV_UPDATE_CRITICAL_HANDLES; ++index) {
        current_critical[index] = -1;
    }
    bool tree_unchanged =
        result == NDV_UPDATE_OK &&
        ndv_update_observe_sealed_tree_fd(bundle_fd,
                                          require_effective_user_owner,
                                          tree_after,
                                          generation_after) &&
        memcmp(tree_before, tree_after, sizeof(tree_before)) == 0 &&
        memcmp(generation_before,
               generation_after,
               sizeof(generation_before)) == 0 &&
        ndv_update_open_critical_fds(bundle_fd, current_critical);
    for (size_t index = 0;
         tree_unchanged && index < NDV_UPDATE_CRITICAL_HANDLES;
         ++index) {
        tree_unchanged = ndv_update_same_open_vnode(
            out_claims->critical_fds[index],
            current_critical[index]);
    }
    ndv_update_close_critical_fds(current_critical);
    close(bundle_fd);
    NdvUpdateIdentity after;
    if (result == NDV_UPDATE_OK &&
        (!tree_unchanged ||
        (!ndv_update_identity_at(directory_fd, leaf_utf8, &after) ||
         before.device != after.device || before.inode != after.inode))) {
        result = NDV_UPDATE_ENTRY_REJECTED;
    }
    if (result == NDV_UPDATE_OK) {
        out_claims->identity = before;
        memcpy(out_claims->tree_hash, tree_before, sizeof(tree_before));
        memcpy(out_claims->tree_generation_hash,
               generation_before,
               sizeof(generation_before));
    } else {
        ndv_update_close_critical_fds(out_claims->critical_fds);
    }
    return result;
}

int32_t ndv_update_observe_sealed_tree(
    int directory_fd,
    const char *leaf_utf8,
    bool require_effective_user_owner,
    uint8_t out_tree_hash[NDV_UPDATE_TREE_HASH_BYTES],
    uint8_t out_tree_generation_hash[NDV_UPDATE_TREE_HASH_BYTES]) {
    if (directory_fd < 0 || !ndv_update_valid_leaf(leaf_utf8) ||
        out_tree_hash == NULL || out_tree_generation_hash == NULL) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    int bundle_fd = openat(directory_fd,
                           leaf_utf8,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (bundle_fd < 0) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    uint8_t first_tree_hash[NDV_UPDATE_TREE_HASH_BYTES];
    uint8_t first_generation_hash[NDV_UPDATE_TREE_HASH_BYTES];
    bool valid = ndv_update_observe_sealed_tree_fd(
                     bundle_fd,
                     require_effective_user_owner,
                     first_tree_hash,
                     first_generation_hash) &&
                 ndv_update_observe_sealed_tree_fd(
                     bundle_fd,
                     require_effective_user_owner,
                     out_tree_hash,
                     out_tree_generation_hash) &&
                 memcmp(first_tree_hash,
                        out_tree_hash,
                        sizeof(first_tree_hash)) == 0 &&
                 memcmp(first_generation_hash,
                        out_tree_generation_hash,
                        sizeof(first_generation_hash)) == 0;
    close(bundle_fd);
    return valid ? NDV_UPDATE_OK : NDV_UPDATE_ENTRY_REJECTED;
}

int32_t ndv_update_test_code_hash_length(const char *path_utf8,
                                         size_t *out_length) {
    if (path_utf8 == NULL || out_length == NULL) {
        return NDV_UPDATE_ENTRY_REJECTED;
    }
    *out_length = 0;
    int32_t result = NDV_UPDATE_SIGNATURE_REJECTED;
    @autoreleasepool {
        NSString *path = [[NSFileManager defaultManager]
            stringWithFileSystemRepresentation:path_utf8
                                        length:strlen(path_utf8)];
        SecStaticCodeRef code = NULL;
        CFDictionaryRef signing_information = NULL;
        if (path != nil &&
            SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],
                                        kSecCSDefaultFlags,
                                        &code) == errSecSuccess &&
            code != NULL &&
            SecCodeCopySigningInformation(code,
                                          kSecCSSigningInformation |
                                              kSecCSContentInformation,
                                          &signing_information) == errSecSuccess &&
            signing_information != NULL) {
            NSDictionary *information = (__bridge NSDictionary *)signing_information;
            id value = information[(__bridge NSString *)kSecCodeInfoUnique];
            if ([value isKindOfClass:NSData.class]) {
                *out_length = [(NSData *)value length];
                result = NDV_UPDATE_OK;
            }
        }
        if (signing_information != NULL) {
            CFRelease(signing_information);
        }
        if (code != NULL) {
            CFRelease(code);
        }
    }
    return result;
}

bool ndv_update_test_exact_universal_binary(const char *path_utf8) {
    if (path_utf8 == NULL) {
        return false;
    }
    @autoreleasepool {
        NSString *path = [[NSFileManager defaultManager]
            stringWithFileSystemRepresentation:path_utf8
                                        length:strlen(path_utf8)];
        return path != nil && ndv_update_exact_universal_binary(path);
    }
}

bool ndv_update_test_assess_system_policy(const char *path_utf8) {
    if (path_utf8 == NULL) {
        return false;
    }
    @autoreleasepool {
        NSString *path = [[NSFileManager defaultManager]
            stringWithFileSystemRepresentation:path_utf8
                                        length:strlen(path_utf8)];
        return path != nil && ndv_update_assess_system_policy(path);
    }
}

int32_t ndv_copy_local_peer_token(int socket_fd,
                                  NdvAuditToken *out_token,
                                  uint32_t *out_effective_uid) {
    if (socket_fd < 0 || out_token == NULL || out_effective_uid == NULL) {
        return NDV_IPC_REJECTED;
    }

    audit_token_t token;
    memset(&token, 0, sizeof(token));
    socklen_t length = sizeof(token);
    if (getsockopt(socket_fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) != 0 ||
        length != sizeof(token)) {
        return NDV_IPC_REJECTED;
    }

    memset(out_token, 0, sizeof(*out_token));
    memcpy(out_token, &token, sizeof(token));
    *out_effective_uid = (uint32_t)audit_token_to_euid(token);
    return NDV_IPC_OK;
}

int32_t ndv_copy_peer_code_signature_claims(
    const NdvAuditToken *token_words,
    const char *requirement_utf8,
    NdvCodeSignatureClaims *out_claims) {
    if (token_words == NULL || requirement_utf8 == NULL || out_claims == NULL) {
        return NDV_IPC_REJECTED;
    }
    memset(out_claims, 0, sizeof(*out_claims));

    SecCodeRef code = NULL;
    SecRequirementRef external_requirement = NULL;
    CFDictionaryRef signing_information = NULL;
    int32_t result = NDV_IPC_REJECTED;

    @autoreleasepool {
        @try {
            do {
                audit_token_t token;
                memcpy(&token, token_words, sizeof(token));
                NSData *audit_data = [NSData dataWithBytes:&token length:sizeof(token)];
                NSDictionary *attributes = @{
                    (__bridge NSString *)kSecGuestAttributeAudit : audit_data,
                };
                if (SecCodeCopyGuestWithAttributes(
                        NULL,
                        (__bridge CFDictionaryRef)attributes,
                        kSecCSDefaultFlags,
                        &code) != errSecSuccess ||
                    code == NULL) {
                    break;
                }

                NSString *requirement_text =
                    [[NSString alloc] initWithUTF8String:requirement_utf8];
                if (requirement_text == nil ||
                    SecRequirementCreateWithString(
                        (__bridge CFStringRef)requirement_text,
                        kSecCSDefaultFlags,
                        &external_requirement) != errSecSuccess ||
                    external_requirement == NULL) {
                    break;
                }

                SecCSFlags validation_flags =
                    kSecCSCheckAllArchitectures | kSecCSStrictValidate |
                    kSecCSNoNetworkAccess;
                if (SecCodeCheckValidity(code,
                                         validation_flags,
                                         external_requirement) != errSecSuccess) {
                    break;
                }
                out_claims->external_requirement_valid = 1;

                SecCSFlags information_flags =
                    kSecCSSigningInformation | kSecCSRequirementInformation |
                    kSecCSDynamicInformation;
                if (SecCodeCopySigningInformation((SecStaticCodeRef)code,
                                                  information_flags,
                                                  &signing_information) != errSecSuccess ||
                    signing_information == NULL) {
                    break;
                }
                NSDictionary *information =
                    (__bridge NSDictionary *)signing_information;

                id signing_identifier =
                    information[(__bridge NSString *)kSecCodeInfoIdentifier];
                id team_identifier =
                    information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
                if (!ndv_copy_optional_utf8(
                        signing_identifier,
                        out_claims->signing_identifier,
                        sizeof(out_claims->signing_identifier)) ||
                    !ndv_copy_optional_utf8(
                        team_identifier,
                        out_claims->team_identifier,
                        sizeof(out_claims->team_identifier)) ||
                    !ndv_copy_u32(
                        information[(__bridge NSString *)kSecCodeInfoFlags],
                        &out_claims->static_flags) ||
                    !ndv_copy_u32(
                        information[(__bridge NSString *)kSecCodeInfoStatus],
                        &out_claims->dynamic_status)) {
                    break;
                }

                id secured_plist_value =
                    information[(__bridge NSString *)kSecCodeInfoPList];
                if (secured_plist_value != nil &&
                    ![secured_plist_value isKindOfClass:NSDictionary.class]) {
                    break;
                }
                NSDictionary *secured_plist = (NSDictionary *)secured_plist_value;
                if (!ndv_copy_optional_utf8(
                        secured_plist[@"CFBundleIdentifier"],
                        out_claims->secured_bundle_identifier,
                        sizeof(out_claims->secured_bundle_identifier))) {
                    break;
                }

                id entitlements_value =
                    information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
                if (entitlements_value != nil &&
                    ![entitlements_value isKindOfClass:NSDictionary.class]) {
                    break;
                }
                NSDictionary *entitlements = (NSDictionary *)entitlements_value;
                if (!ndv_copy_optional_utf8(
                        entitlements[@"com.apple.application-identifier"],
                        out_claims->application_identifier,
                        sizeof(out_claims->application_identifier))) {
                    break;
                }
                id get_task_allow =
                    entitlements[@"com.apple.security.get-task-allow"];
                if (get_task_allow != nil) {
                    if (![get_task_allow isKindOfClass:NSNumber.class]) {
                        break;
                    }
                    out_claims->get_task_allow =
                        [(NSNumber *)get_task_allow boolValue] ? 1 : 0;
                }

                id certificates =
                    information[(__bridge NSString *)kSecCodeInfoCertificates];
                if ([certificates isKindOfClass:NSArray.class] &&
                    [(NSArray *)certificates count] > 0) {
                    out_claims->certificate_chain_present = 1;
                }
                id cms = information[(__bridge NSString *)kSecCodeInfoCMS];
                if ([cms isKindOfClass:NSData.class] &&
                    [(NSData *)cms length] > 0) {
                    out_claims->cms_present = 1;
                }

                id designated_requirement =
                    information[(__bridge NSString *)
                                    kSecCodeInfoDesignatedRequirement];
                if (designated_requirement != nil &&
                    CFGetTypeID((__bridge CFTypeRef)designated_requirement) ==
                        SecRequirementGetTypeID() &&
                    SecCodeCheckValidity(
                        code,
                        validation_flags,
                        (__bridge SecRequirementRef)designated_requirement) ==
                        errSecSuccess) {
                    out_claims->designated_requirement_valid = 1;
                }

                result = NDV_IPC_OK;
            } while (false);
        } @catch (__unused NSException *exception) {
            result = NDV_IPC_REJECTED;
        } @finally {
            if (signing_information != NULL) {
                CFRelease(signing_information);
            }
            if (external_requirement != NULL) {
                CFRelease(external_requirement);
            }
            if (code != NULL) {
                CFRelease(code);
            }
        }
    }
    return result;
}

enum {
    NDV_XPC_EVENT_REQUEST = 1,
    NDV_XPC_EVENT_LISTENER_INVALID = 2,
};

typedef void (*NdvXpcEventCallback)(void *context,
                                    uint32_t event_kind,
                                    const uint8_t *nullable_bytes,
                                    size_t length,
                                    void *nullable_reply);

static char ndv_xpc_queue_specific_key;

static void ndv_dispatch_sync_on_queue(dispatch_queue_t queue,
                                       dispatch_block_t block) {
    if (dispatch_get_specific(&ndv_xpc_queue_specific_key) ==
        (__bridge void *)queue) {
        block();
    } else {
        dispatch_sync(queue, block);
    }
}

@class NdvXpcListenerHandle;

@interface NdvXpcPeer : NSObject
@property(nonatomic, weak) NdvXpcListenerHandle *listener;
@property(nonatomic, strong) xpc_connection_t connection;
@property(nonatomic) NSUInteger outstanding;
@property(nonatomic) BOOL closed;
@end

@interface NdvXpcReplyHandle : NSObject
@property(nonatomic, strong) NdvXpcPeer *peer;
@property(nonatomic, strong) xpc_object_t reply;
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic) BOOL finished;
- (void)scheduleDeadlineMilliseconds:(uint64_t)milliseconds;
- (BOOL)finishWithData:(NSData *)data cancelPeer:(BOOL)cancel_peer;
@end

@interface NdvXpcListenerHandle : NSObject
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, strong) xpc_connection_t listener;
@property(nonatomic, copy) NSString *peerRequirement;
@property(nonatomic, strong) NSMutableSet<NdvXpcPeer *> *peers;
@property(nonatomic) NdvXpcEventCallback callback;
@property(nonatomic) void *callbackContext;
@property(nonatomic) size_t maximumMessageBytes;
@property(nonatomic) NSUInteger maximumPeers;
@property(nonatomic) NSUInteger maximumPeerOutstanding;
@property(nonatomic) NSUInteger maximumGlobalOutstanding;
@property(nonatomic) NSUInteger globalOutstanding;
@property(nonatomic) uint64_t replyDeadlineMilliseconds;
@property(nonatomic) BOOL stopping;
@property(nonatomic) BOOL activated;
- (void)acceptPeer:(xpc_connection_t)connection;
- (void)handlePeer:(NdvXpcPeer *)peer event:(xpc_object_t)event;
- (void)completeReplyForPeer:(NdvXpcPeer *)peer;
- (void)closePeer:(NdvXpcPeer *)peer;
@end

@implementation NdvXpcPeer
@end

@implementation NdvXpcReplyHandle

- (void)scheduleDeadlineMilliseconds:(uint64_t)milliseconds {
    __weak NdvXpcReplyHandle *weak_self = self;
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
                      (int64_t)(milliseconds * NSEC_PER_MSEC)),
        self.queue,
        ^{
            NdvXpcReplyHandle *strong_self = weak_self;
            if (strong_self != nil && !strong_self.finished) {
                [strong_self finishWithData:nil cancelPeer:YES];
            }
        });
}

- (BOOL)finishWithData:(NSData *)data cancelPeer:(BOOL)cancel_peer {
    if (self.finished) {
        return NO;
    }
    self.finished = YES;
    BOOL sent = NO;
    NdvXpcPeer *peer = self.peer;
    if (peer != nil) {
        [peer.listener completeReplyForPeer:peer];
        if (data != nil && !peer.closed) {
            xpc_object_t boxed = xpc_data_create(data.bytes, data.length);
            if (boxed != NULL) {
                xpc_dictionary_set_value(self.reply, "frame", boxed);
                xpc_connection_send_message(peer.connection, self.reply);
                sent = YES;
            } else {
                cancel_peer = YES;
            }
        }
        if (cancel_peer && !peer.closed) {
            xpc_connection_cancel(peer.connection);
        }
    }
    self.reply = nil;
    self.peer = nil;
    return sent;
}

@end


@implementation NdvXpcListenerHandle

- (void)acceptPeer:(xpc_connection_t)connection {
    if (self.stopping || self.peers.count >= self.maximumPeers) {
        xpc_connection_cancel(connection);
        return;
    }
    if (xpc_connection_set_peer_code_signing_requirement(
            connection,
            self.peerRequirement.UTF8String) != 0) {
        xpc_connection_cancel(connection);
        return;
    }

    NdvXpcPeer *peer = [[NdvXpcPeer alloc] init];
    peer.listener = self;
    peer.connection = connection;
    [self.peers addObject:peer];

    __weak NdvXpcPeer *weak_peer = peer;
    xpc_connection_set_target_queue(connection, self.queue);
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        NdvXpcPeer *strong_peer = weak_peer;
        if (strong_peer != nil) {
            [strong_peer.listener handlePeer:strong_peer event:event];
        }
    });
    xpc_connection_activate(connection);
}

- (void)handlePeer:(NdvXpcPeer *)peer event:(xpc_object_t)event {
    if (self.stopping || peer.closed) {
        return;
    }
    xpc_type_t type = xpc_get_type(event);
    if (type == XPC_TYPE_ERROR) {
        [self closePeer:peer];
        return;
    }
    if (type != XPC_TYPE_DICTIONARY ||
        xpc_dictionary_get_count(event) != 1 ||
        peer.outstanding >= self.maximumPeerOutstanding ||
        self.globalOutstanding >= self.maximumGlobalOutstanding) {
        [self closePeer:peer];
        return;
    }

    xpc_object_t frame = xpc_dictionary_get_value(event, "frame");
    if (frame == NULL || xpc_get_type(frame) != XPC_TYPE_DATA) {
        [self closePeer:peer];
        return;
    }
    size_t length = xpc_data_get_length(frame);
    const uint8_t *bytes = xpc_data_get_bytes_ptr(frame);
    if (length == 0 || length > self.maximumMessageBytes || bytes == NULL) {
        [self closePeer:peer];
        return;
    }
    xpc_object_t reply_dictionary = xpc_dictionary_create_reply(event);
    if (reply_dictionary == NULL) {
        [self closePeer:peer];
        return;
    }

    peer.outstanding += 1;
    self.globalOutstanding += 1;
    NdvXpcReplyHandle *reply = [[NdvXpcReplyHandle alloc] init];
    reply.peer = peer;
    reply.reply = reply_dictionary;
    reply.queue = self.queue;
    [reply scheduleDeadlineMilliseconds:self.replyDeadlineMilliseconds];

    void *opaque_reply = (void *)CFBridgingRetain(reply);
    self.callback(self.callbackContext,
                  NDV_XPC_EVENT_REQUEST,
                  bytes,
                  length,
                  opaque_reply);
}

- (void)completeReplyForPeer:(NdvXpcPeer *)peer {
    if (peer.outstanding > 0) {
        peer.outstanding -= 1;
    }
    if (self.globalOutstanding > 0) {
        self.globalOutstanding -= 1;
    }
}

- (void)closePeer:(NdvXpcPeer *)peer {
    if (peer.closed) {
        return;
    }
    peer.closed = YES;
    xpc_connection_cancel(peer.connection);
    [self.peers removeObject:peer];
}

@end


void *ndv_xpc_listener_create(const char *service_name,
                              const char *peer_requirement,
                              size_t maximum_message_bytes,
                              size_t maximum_peers,
                              size_t maximum_peer_outstanding,
                              size_t maximum_global_outstanding,
                              uint64_t reply_deadline_milliseconds,
                              NdvXpcEventCallback callback,
                              void *callback_context) {
    if (service_name == NULL || service_name[0] == '\0' ||
        peer_requirement == NULL || peer_requirement[0] == '\0' ||
        maximum_message_bytes == 0 || maximum_peers == 0 ||
        maximum_peer_outstanding == 0 || maximum_global_outstanding == 0 ||
        maximum_peer_outstanding > maximum_global_outstanding ||
        reply_deadline_milliseconds == 0 || callback == NULL ||
        callback_context == NULL) {
        return NULL;
    }

    @autoreleasepool {
        NdvXpcListenerHandle *handle = [[NdvXpcListenerHandle alloc] init];
        handle.queue = dispatch_queue_create("dev.nodavo.agent.ipc", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(handle.queue,
                                    &ndv_xpc_queue_specific_key,
                                    (__bridge void *)handle.queue,
                                    NULL);
        handle.peers = [[NSMutableSet alloc] init];
        handle.peerRequirement = [[NSString alloc] initWithUTF8String:peer_requirement];
        if (handle.peerRequirement == nil) {
            return NULL;
        }
        handle.callback = callback;
        handle.callbackContext = callback_context;
        handle.maximumMessageBytes = maximum_message_bytes;
        handle.maximumPeers = maximum_peers;
        handle.maximumPeerOutstanding = maximum_peer_outstanding;
        handle.maximumGlobalOutstanding = maximum_global_outstanding;
        handle.replyDeadlineMilliseconds = reply_deadline_milliseconds;
        handle.listener = xpc_connection_create_mach_service(
            service_name,
            handle.queue,
            XPC_CONNECTION_MACH_SERVICE_LISTENER);
        if (handle.listener == NULL ||
            xpc_connection_set_peer_code_signing_requirement(
                handle.listener,
                peer_requirement) != 0) {
            if (handle.listener != NULL) {
                xpc_connection_set_event_handler(handle.listener, ^(__unused xpc_object_t event) {});
                xpc_connection_activate(handle.listener);
                xpc_connection_cancel(handle.listener);
            }
            return NULL;
        }

        __weak NdvXpcListenerHandle *weak_handle = handle;
        xpc_connection_set_event_handler(handle.listener, ^(xpc_object_t event) {
            NdvXpcListenerHandle *strong_handle = weak_handle;
            if (strong_handle == nil || strong_handle.stopping) {
                if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
                    xpc_connection_cancel((xpc_connection_t)event);
                }
                return;
            }
            xpc_type_t type = xpc_get_type(event);
            if (type == XPC_TYPE_CONNECTION) {
                [strong_handle acceptPeer:(xpc_connection_t)event];
            } else if (type == XPC_TYPE_ERROR) {
                strong_handle.callback(
                    strong_handle.callbackContext,
                    NDV_XPC_EVENT_LISTENER_INVALID,
                    NULL,
                    0,
                    NULL);
            }
        });
        return (void *)CFBridgingRetain(handle);
    }
}

int32_t ndv_xpc_listener_activate(void *opaque_handle) {
    if (opaque_handle == NULL) {
        return NDV_IPC_REJECTED;
    }
    NdvXpcListenerHandle *handle = (__bridge NdvXpcListenerHandle *)opaque_handle;
    __block int32_t result = NDV_IPC_REJECTED;
    ndv_dispatch_sync_on_queue(handle.queue, ^{
        if (!handle.stopping && !handle.activated && handle.listener != NULL) {
            handle.activated = YES;
            xpc_connection_activate(handle.listener);
            result = NDV_IPC_OK;
        }
    });
    return result;
}

void ndv_xpc_listener_destroy(void *opaque_handle) {
    if (opaque_handle == NULL) {
        return;
    }
    NdvXpcListenerHandle *handle = CFBridgingRelease(opaque_handle);
    ndv_dispatch_sync_on_queue(handle.queue, ^{
        handle.stopping = YES;
        for (NdvXpcPeer *peer in handle.peers.allObjects) {
            [handle closePeer:peer];
        }
        if (handle.listener != NULL) {
            xpc_connection_cancel(handle.listener);
            handle.listener = nil;
        }
    });
}

int32_t ndv_xpc_reply_send(void *opaque_reply,
                           const uint8_t *bytes,
                           size_t length,
                           size_t maximum_message_bytes) {
    if (opaque_reply == NULL) {
        return NDV_IPC_REJECTED;
    }
    NdvXpcReplyHandle *reply = CFBridgingRelease(opaque_reply);
    __block BOOL sent = NO;
    if (bytes == NULL || length == 0 || length > maximum_message_bytes) {
        ndv_dispatch_sync_on_queue(reply.queue, ^{
            [reply finishWithData:nil cancelPeer:YES];
        });
        return NDV_IPC_REJECTED;
    }
    NSData *data = [NSData dataWithBytes:bytes length:length];
    if (data == nil) {
        ndv_dispatch_sync_on_queue(reply.queue, ^{
            [reply finishWithData:nil cancelPeer:YES];
        });
        return NDV_IPC_REJECTED;
    }
    ndv_dispatch_sync_on_queue(reply.queue, ^{
        sent = [reply finishWithData:data cancelPeer:NO];
    });
    return sent ? NDV_IPC_OK : NDV_IPC_REJECTED;
}

void ndv_xpc_reply_abandon(void *opaque_reply) {
    if (opaque_reply == NULL) {
        return;
    }
    NdvXpcReplyHandle *reply = CFBridgingRelease(opaque_reply);
    dispatch_async(reply.queue, ^{
        [reply finishWithData:nil cancelPeer:YES];
    });
}

enum {
    NDV_PASTEBOARD_OK = 0,
    NDV_PASTEBOARD_UNAVAILABLE = 1,
    NDV_PASTEBOARD_INVALID_REVISION = 2,
    NDV_PASTEBOARD_READ_REJECTED = 3,
    NDV_PASTEBOARD_TOO_LARGE = 4,
    NDV_PASTEBOARD_WRITE_REJECTED = 5,
    NDV_PASTEBOARD_EXCEPTION = 6,
    NDV_PASTEBOARD_CHANGED = 7,
    NDV_PASTEBOARD_INVALID_KIND = 8,
};

enum {
    NDV_PASTEBOARD_UTF8_TEXT = 1,
    NDV_PASTEBOARD_HTML = 2,
    NDV_PASTEBOARD_PNG = 3,
};

typedef struct {
    int64_t change_count;
    uint8_t types_empty;
    CFDataRef utf8_text;
    CFDataRef html;
    CFDataRef png;
} NdvPasteboardSnapshot;

static NSPasteboard *ndv_pasteboard(CFStringRef nullable_name) {
    if (nullable_name == NULL) {
        return NSPasteboard.generalPasteboard;
    }
    return [NSPasteboard pasteboardWithName:(__bridge NSString *)nullable_name];
}

static NSPasteboardType ndv_pasteboard_type(uint8_t kind) {
    switch (kind) {
    case NDV_PASTEBOARD_UTF8_TEXT:
        return NSPasteboardTypeString;
    case NDV_PASTEBOARD_HTML:
        return NSPasteboardTypeHTML;
    case NDV_PASTEBOARD_PNG:
        return NSPasteboardTypePNG;
    default:
        return nil;
    }
}

static int32_t ndv_validate_data(NSData *data, size_t maximum) {
    if (data == nil) {
        return NDV_PASTEBOARD_READ_REJECTED;
    }
    if (data.length > maximum) {
        return NDV_PASTEBOARD_TOO_LARGE;
    }
    return NDV_PASTEBOARD_OK;
}

int32_t ndv_pasteboard_copy_snapshot(CFStringRef nullable_name,
                                     size_t max_text,
                                     size_t max_html,
                                     size_t max_png,
                                     NdvPasteboardSnapshot *out_snapshot) {
    if (out_snapshot == NULL) {
        return NDV_PASTEBOARD_READ_REJECTED;
    }
    memset(out_snapshot, 0, sizeof(*out_snapshot));

    @autoreleasepool {
        @try {
            NSPasteboard *pasteboard = ndv_pasteboard(nullable_name);
            if (pasteboard == nil) {
                return NDV_PASTEBOARD_UNAVAILABLE;
            }
            NSInteger before = pasteboard.changeCount;
            if (before < 0) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }

            NSArray<NSPasteboardType> *types = pasteboard.types;
            out_snapshot->types_empty = (types == nil || types.count == 0) ? 1 : 0;
            NSData *text = nil;
            NSData *html = nil;
            NSData *png = nil;

            if ([types containsObject:NSPasteboardTypeString]) {
                text = [pasteboard dataForType:NSPasteboardTypeString];
                int32_t status = ndv_validate_data(text, max_text);
                if (status != NDV_PASTEBOARD_OK) {
                    return status;
                }
            }
            if ([types containsObject:NSPasteboardTypeHTML]) {
                html = [pasteboard dataForType:NSPasteboardTypeHTML];
                int32_t status = ndv_validate_data(html, max_html);
                if (status != NDV_PASTEBOARD_OK) {
                    return status;
                }
            }
            if ([types containsObject:NSPasteboardTypePNG]) {
                png = [pasteboard dataForType:NSPasteboardTypePNG];
                int32_t status = ndv_validate_data(png, max_png);
                if (status != NDV_PASTEBOARD_OK) {
                    return status;
                }
            }

            NSInteger after = pasteboard.changeCount;
            if (after < 0) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }
            if (after != before) {
                return NDV_PASTEBOARD_CHANGED;
            }

            out_snapshot->change_count = (int64_t)after;
            // Ownership crosses the C ABI only here. Each non-null result is
            // retained exactly once and must be released exactly once by Rust.
            out_snapshot->utf8_text = text == nil
                                          ? NULL
                                          : (CFDataRef)CFBridgingRetain(text);
            out_snapshot->html = html == nil
                                     ? NULL
                                     : (CFDataRef)CFBridgingRetain(html);
            out_snapshot->png = png == nil
                                    ? NULL
                                    : (CFDataRef)CFBridgingRetain(png);
            return NDV_PASTEBOARD_OK;
        } @catch (__unused NSException *exception) {
            return NDV_PASTEBOARD_EXCEPTION;
        }
    }
}

int32_t ndv_pasteboard_write(CFStringRef nullable_name,
                             uint8_t kind,
                             const uint8_t *bytes,
                             size_t length,
                             int64_t *out_change_count) {
    if (out_change_count == NULL || (length != 0 && bytes == NULL)) {
        return NDV_PASTEBOARD_WRITE_REJECTED;
    }

    @autoreleasepool {
        @try {
            NSPasteboardType type = ndv_pasteboard_type(kind);
            if (type == nil) {
                return NDV_PASTEBOARD_INVALID_KIND;
            }
            NSPasteboard *pasteboard = ndv_pasteboard(nullable_name);
            if (pasteboard == nil) {
                return NDV_PASTEBOARD_UNAVAILABLE;
            }
            NSData *data = length == 0 ? NSData.data
                                       : [NSData dataWithBytes:bytes length:length];
            if (data == nil) {
                return NDV_PASTEBOARD_WRITE_REJECTED;
            }

            NSInteger cleared = [pasteboard clearContents];
            if (cleared < 0) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }
            if (![pasteboard setData:data forType:type]) {
                return NDV_PASTEBOARD_WRITE_REJECTED;
            }
            NSInteger after = pasteboard.changeCount;
            if (after < cleared) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }
            *out_change_count = (int64_t)after;
            return NDV_PASTEBOARD_OK;
        } @catch (__unused NSException *exception) {
            return NDV_PASTEBOARD_EXCEPTION;
        }
    }
}

int32_t ndv_pasteboard_clear(CFStringRef nullable_name,
                             int64_t *out_change_count) {
    if (out_change_count == NULL) {
        return NDV_PASTEBOARD_WRITE_REJECTED;
    }

    @autoreleasepool {
        @try {
            NSPasteboard *pasteboard = ndv_pasteboard(nullable_name);
            if (pasteboard == nil) {
                return NDV_PASTEBOARD_UNAVAILABLE;
            }
            NSInteger count = [pasteboard clearContents];
            if (count < 0) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }
            *out_change_count = (int64_t)count;
            return NDV_PASTEBOARD_OK;
        } @catch (__unused NSException *exception) {
            return NDV_PASTEBOARD_EXCEPTION;
        }
    }
}

int32_t ndv_pasteboard_change_count(CFStringRef nullable_name,
                                    int64_t *out_change_count) {
    if (out_change_count == NULL) {
        return NDV_PASTEBOARD_READ_REJECTED;
    }

    @autoreleasepool {
        @try {
            NSPasteboard *pasteboard = ndv_pasteboard(nullable_name);
            if (pasteboard == nil) {
                return NDV_PASTEBOARD_UNAVAILABLE;
            }
            NSInteger count = pasteboard.changeCount;
            if (count < 0) {
                return NDV_PASTEBOARD_INVALID_REVISION;
            }
            *out_change_count = (int64_t)count;
            return NDV_PASTEBOARD_OK;
        } @catch (__unused NSException *exception) {
            return NDV_PASTEBOARD_EXCEPTION;
        }
    }
}

void ndv_pasteboard_release_named(CFStringRef name) {
    if (name == NULL) {
        return;
    }
    @autoreleasepool {
        @try {
            [[NSPasteboard pasteboardWithName:(__bridge NSString *)name] releaseGlobally];
        } @catch (__unused NSException *exception) {
            // Test pasteboard cleanup is best-effort and never logs content.
        }
    }
}

// The input runtime deliberately exposes only bounded scalar metadata across
// the C ABI. Keyboard text, filenames, pasteboard data, and stable identifiers
// never cross this boundary.
enum {
    NDV_INPUT_KEYBOARD = 1,
    NDV_INPUT_CONSUMER = 2,
    NDV_INPUT_POINTER_MOTION = 3,
    NDV_INPUT_POINTER_BUTTON = 4,
    NDV_INPUT_SCROLL = 5,
    NDV_INPUT_LIFECYCLE = 6,
};

enum {
    NDV_LIFECYCLE_SYSTEM_WILL_SLEEP = 1,
    NDV_LIFECYCLE_SYSTEM_DID_WAKE = 2,
    NDV_LIFECYCLE_SCREENS_DID_SLEEP = 3,
    NDV_LIFECYCLE_SCREENS_DID_WAKE = 4,
    NDV_LIFECYCLE_SESSION_DID_RESIGN_ACTIVE = 5,
    NDV_LIFECYCLE_SESSION_DID_BECOME_ACTIVE = 6,
    NDV_LIFECYCLE_TAP_DISABLED_BY_TIMEOUT = 7,
    NDV_LIFECYCLE_TAP_DISABLED_BY_USER_INPUT = 8,
};

enum {
    NDV_CALLBACK_KEEP = 0,
    NDV_CALLBACK_SUPPRESS = 1,
    NDV_CALLBACK_ABORT = 2,
};

enum {
    NDV_CAPTURE_STOP_REQUESTED = 0,
    NDV_CAPTURE_TAP_DISABLED_BY_TIMEOUT = 1,
    NDV_CAPTURE_TAP_DISABLED_BY_USER_INPUT = 2,
    NDV_CAPTURE_CALLBACK_FAILED = 3,
    NDV_CAPTURE_NATIVE_FAILURE = 4,
};

enum {
    NDV_MODIFIER_LEFT_CONTROL = 1u << 0,
    NDV_MODIFIER_LEFT_SHIFT = 1u << 1,
    NDV_MODIFIER_LEFT_ALT = 1u << 2,
    NDV_MODIFIER_LEFT_META = 1u << 3,
    NDV_MODIFIER_RIGHT_CONTROL = 1u << 4,
    NDV_MODIFIER_RIGHT_SHIFT = 1u << 5,
    NDV_MODIFIER_RIGHT_ALT = 1u << 6,
    NDV_MODIFIER_RIGHT_META = 1u << 7,
    NDV_MODIFIER_CAPS_LOCK = 1u << 9,
};

typedef struct {
    uint32_t kind;
    uint32_t code;
    int64_t value1;
    int64_t value2;
    uint64_t flags;
    double x;
    double y;
} NdvInputEvent;

typedef int32_t (*NdvInputCallback)(void *context,
                                    const NdvInputEvent *event);

typedef struct {
    CFRunLoopRef run_loop;
    _Atomic uint32_t reference_count;
    _Atomic bool stop_requested;
    _Atomic int32_t exit_reason;
} NdvInputCaptureControl;

typedef struct NdvInputCapture {
    CFMachPortRef event_tap;
    CFRunLoopSourceRef run_loop_source;
    NdvInputCaptureControl *control;
    CFTypeRef lifecycle_observer;
    NdvInputCallback callback;
    void *callback_context;
} NdvInputCapture;

static void ndv_input_capture_stop_internal(NdvInputCaptureControl *control,
                                            int32_t reason);

static int32_t ndv_emit_input(NdvInputCapture *capture,
                              const NdvInputEvent *event) {
    if (capture == NULL || capture->callback == NULL || event == NULL) {
        return NDV_CALLBACK_ABORT;
    }
    int32_t action = capture->callback(capture->callback_context, event);
    if (action == NDV_CALLBACK_ABORT) {
        ndv_input_capture_stop_internal(capture->control,
                                        NDV_CAPTURE_CALLBACK_FAILED);
    }
    if (action != NDV_CALLBACK_KEEP && action != NDV_CALLBACK_SUPPRESS &&
        action != NDV_CALLBACK_ABORT) {
        ndv_input_capture_stop_internal(capture->control,
                                        NDV_CAPTURE_CALLBACK_FAILED);
        return NDV_CALLBACK_ABORT;
    }
    return action;
}

static uint64_t ndv_modifier_state(CGEventRef event) {
    uint64_t state = 0;
    CGEventSourceStateID source = kCGEventSourceStateCombinedSessionState;
    if (CGEventSourceKeyState(source, kVK_Control)) {
        state |= NDV_MODIFIER_LEFT_CONTROL;
    }
    if (CGEventSourceKeyState(source, kVK_Shift)) {
        state |= NDV_MODIFIER_LEFT_SHIFT;
    }
    if (CGEventSourceKeyState(source, kVK_Option)) {
        state |= NDV_MODIFIER_LEFT_ALT;
    }
    if (CGEventSourceKeyState(source, kVK_Command)) {
        state |= NDV_MODIFIER_LEFT_META;
    }
    if (CGEventSourceKeyState(source, kVK_RightControl)) {
        state |= NDV_MODIFIER_RIGHT_CONTROL;
    }
    if (CGEventSourceKeyState(source, kVK_RightShift)) {
        state |= NDV_MODIFIER_RIGHT_SHIFT;
    }
    if (CGEventSourceKeyState(source, kVK_RightOption)) {
        state |= NDV_MODIFIER_RIGHT_ALT;
    }
    if (CGEventSourceKeyState(source, kVK_RightCommand)) {
        state |= NDV_MODIFIER_RIGHT_META;
    }
    if ((CGEventGetFlags(event) & kCGEventFlagMaskAlphaShift) != 0) {
        state |= NDV_MODIFIER_CAPS_LOCK;
    }
    return state;
}

static uint32_t ndv_consumer_usage(NSInteger key_type) {
    switch (key_type) {
    case NX_KEYTYPE_PLAY:
        return 0x00cd;
    case NX_KEYTYPE_NEXT:
        return 0x00b5;
    case NX_KEYTYPE_PREVIOUS:
        return 0x00b6;
    case NX_KEYTYPE_FAST:
        return 0x00b3;
    case NX_KEYTYPE_REWIND:
        return 0x00b4;
    case NX_KEYTYPE_MUTE:
        return 0x00e2;
    case NX_KEYTYPE_SOUND_UP:
        return 0x00e9;
    case NX_KEYTYPE_SOUND_DOWN:
        return 0x00ea;
    default:
        return 0;
    }
}

static int32_t ndv_decode_and_emit(NdvInputCapture *capture,
                                   CGEventType type,
                                   CGEventRef event) {
    NdvInputEvent input = {0};
    switch (type) {
    case kCGEventKeyDown:
    case kCGEventKeyUp:
    case kCGEventFlagsChanged: {
        int64_t key_code = CGEventGetIntegerValueField(
            event, kCGKeyboardEventKeycode);
        if (key_code < 0 || key_code > UINT16_MAX) {
            return NDV_CALLBACK_KEEP;
        }
        input.kind = NDV_INPUT_KEYBOARD;
        input.code = (uint32_t)key_code;
        input.value1 = type == kCGEventKeyDown
                           ? 1
                           : type == kCGEventKeyUp
                                 ? 0
                                 : CGEventSourceKeyState(
                                       kCGEventSourceStateCombinedSessionState,
                                       (CGKeyCode)key_code);
        input.flags = ndv_modifier_state(event);
        return ndv_emit_input(capture, &input);
    }
    case kCGEventMouseMoved:
    case kCGEventLeftMouseDragged:
    case kCGEventRightMouseDragged:
    case kCGEventOtherMouseDragged: {
        CGPoint location = CGEventGetLocation(event);
        input.kind = NDV_INPUT_POINTER_MOTION;
        input.value1 = CGEventGetIntegerValueField(
            event, kCGMouseEventDeltaX);
        input.value2 = CGEventGetIntegerValueField(
            event, kCGMouseEventDeltaY);
        input.x = location.x;
        input.y = location.y;
        return ndv_emit_input(capture, &input);
    }
    case kCGEventLeftMouseDown:
    case kCGEventLeftMouseUp:
    case kCGEventRightMouseDown:
    case kCGEventRightMouseUp:
    case kCGEventOtherMouseDown:
    case kCGEventOtherMouseUp: {
        int64_t button = CGEventGetIntegerValueField(
            event, kCGMouseEventButtonNumber);
        if (button < 0 || button >= UINT8_MAX) {
            return NDV_CALLBACK_KEEP;
        }
        input.kind = NDV_INPUT_POINTER_BUTTON;
        input.code = (uint32_t)button + 1;
        input.value1 = type == kCGEventLeftMouseDown ||
                               type == kCGEventRightMouseDown ||
                               type == kCGEventOtherMouseDown;
        return ndv_emit_input(capture, &input);
    }
    case kCGEventScrollWheel: {
        bool precise = CGEventGetIntegerValueField(
                           event, kCGScrollWheelEventIsContinuous) != 0;
        input.kind = NDV_INPUT_SCROLL;
        input.code = precise ? 1 : 0;
        input.value1 = CGEventGetIntegerValueField(
            event, precise ? kCGScrollWheelEventPointDeltaAxis2
                           : kCGScrollWheelEventDeltaAxis2);
        input.value2 = CGEventGetIntegerValueField(
            event, precise ? kCGScrollWheelEventPointDeltaAxis1
                           : kCGScrollWheelEventDeltaAxis1);
        return ndv_emit_input(capture, &input);
    }
    default:
        if ((NSUInteger)type != NSEventTypeSystemDefined) {
            return NDV_CALLBACK_KEEP;
        }
        NSEvent *native_event = [NSEvent eventWithCGEvent:event];
        if (native_event == nil ||
            native_event.subtype != NX_SUBTYPE_AUX_CONTROL_BUTTONS) {
            return NDV_CALLBACK_KEEP;
        }
        NSInteger data = native_event.data1;
        uint32_t usage = ndv_consumer_usage((data >> 16) & 0xffff);
        NSInteger key_state = (data >> 8) & 0xff;
        if (usage == 0 || (key_state != NX_KEYDOWN && key_state != NX_KEYUP)) {
            return NDV_CALLBACK_KEEP;
        }
        input.kind = NDV_INPUT_CONSUMER;
        input.code = usage;
        input.value1 = key_state == NX_KEYDOWN;
        input.flags = ndv_modifier_state(event);
        return ndv_emit_input(capture, &input);
    }
}

static CGEventRef ndv_event_tap_callback(__unused CGEventTapProxy proxy,
                                         CGEventType type,
                                         CGEventRef event,
                                         void *context) {
    NdvInputCapture *capture = context;
    if (capture == NULL) {
        return event;
    }
    if (type == kCGEventTapDisabledByTimeout ||
        type == kCGEventTapDisabledByUserInput) {
        NdvInputEvent lifecycle = {0};
        lifecycle.kind = NDV_INPUT_LIFECYCLE;
        lifecycle.code = type == kCGEventTapDisabledByTimeout
                             ? NDV_LIFECYCLE_TAP_DISABLED_BY_TIMEOUT
                             : NDV_LIFECYCLE_TAP_DISABLED_BY_USER_INPUT;
        (void)ndv_emit_input(capture, &lifecycle);
        ndv_input_capture_stop_internal(
            capture->control, type == kCGEventTapDisabledByTimeout
                         ? NDV_CAPTURE_TAP_DISABLED_BY_TIMEOUT
                         : NDV_CAPTURE_TAP_DISABLED_BY_USER_INPUT);
        return event;
    }
    if (event == NULL || atomic_load_explicit(&capture->control->stop_requested,
                                               memory_order_acquire)) {
        return event;
    }
    if (CGEventGetIntegerValueField(event, kCGEventSourceUserData) ==
        0x4E4F4441564FLL) {
        return event;
    }
    int32_t action = ndv_decode_and_emit(capture, type, event);
    return action == NDV_CALLBACK_SUPPRESS ? NULL : event;
}

@interface NdvInputLifecycleObserver : NSObject {
    NSLock *_lock;
    NdvInputCapture *_capture;
}
- (instancetype)initWithCapture:(NdvInputCapture *)capture;
- (void)invalidate;
- (void)systemWillSleep:(NSNotification *)notification;
- (void)systemDidWake:(NSNotification *)notification;
- (void)screensDidSleep:(NSNotification *)notification;
- (void)screensDidWake:(NSNotification *)notification;
- (void)sessionDidResignActive:(NSNotification *)notification;
- (void)sessionDidBecomeActive:(NSNotification *)notification;
@end

static void ndv_emit_lifecycle(NdvInputCapture *capture, uint32_t code) {
    NdvInputEvent event = {0};
    event.kind = NDV_INPUT_LIFECYCLE;
    event.code = code;
    (void)ndv_emit_input(capture, &event);
}

@implementation NdvInputLifecycleObserver
- (instancetype)initWithCapture:(NdvInputCapture *)capture {
    self = [super init];
    if (self != nil) {
        _lock = [NSLock new];
        _capture = capture;
    }
    return self;
}
- (void)emitLifecycle:(uint32_t)code {
    [_lock lock];
    if (_capture != NULL) {
        ndv_emit_lifecycle(_capture, code);
    }
    [_lock unlock];
}
- (void)invalidate {
    [_lock lock];
    _capture = NULL;
    [_lock unlock];
}
- (void)systemWillSleep:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SYSTEM_WILL_SLEEP];
}
- (void)systemDidWake:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SYSTEM_DID_WAKE];
}
- (void)screensDidSleep:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SCREENS_DID_SLEEP];
}
- (void)screensDidWake:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SCREENS_DID_WAKE];
}
- (void)sessionDidResignActive:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SESSION_DID_RESIGN_ACTIVE];
}
- (void)sessionDidBecomeActive:(__unused NSNotification *)notification {
    [self emitLifecycle:NDV_LIFECYCLE_SESSION_DID_BECOME_ACTIVE];
}
@end

static bool ndv_register_lifecycle(NdvInputCapture *capture) {
    @try {
        NdvInputLifecycleObserver *observer =
            [[NdvInputLifecycleObserver alloc] initWithCapture:capture];
        NSNotificationCenter *center =
            NSWorkspace.sharedWorkspace.notificationCenter;
        [center addObserver:observer selector:@selector(systemWillSleep:)
                       name:NSWorkspaceWillSleepNotification object:nil];
        [center addObserver:observer selector:@selector(systemDidWake:)
                       name:NSWorkspaceDidWakeNotification object:nil];
        [center addObserver:observer selector:@selector(screensDidSleep:)
                       name:NSWorkspaceScreensDidSleepNotification object:nil];
        [center addObserver:observer selector:@selector(screensDidWake:)
                       name:NSWorkspaceScreensDidWakeNotification object:nil];
        [center addObserver:observer selector:@selector(sessionDidResignActive:)
                       name:NSWorkspaceSessionDidResignActiveNotification
                     object:nil];
        [center addObserver:observer selector:@selector(sessionDidBecomeActive:)
                       name:NSWorkspaceSessionDidBecomeActiveNotification
                     object:nil];
        capture->lifecycle_observer = CFBridgingRetain(observer);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static void ndv_unregister_lifecycle(NdvInputCapture *capture) {
    if (capture->lifecycle_observer == NULL) {
        return;
    }
    NdvInputLifecycleObserver *observer =
        (__bridge NdvInputLifecycleObserver *)capture->lifecycle_observer;
    [observer invalidate];
    @try {
        [NSWorkspace.sharedWorkspace.notificationCenter removeObserver:observer];
    } @catch (__unused NSException *exception) {
        // Removal is best-effort after the callback pointer is cleared.
    }
    CFBridgingRelease(capture->lifecycle_observer);
    capture->lifecycle_observer = NULL;
}

void *ndv_input_capture_create(NdvInputCallback callback, void *context) {
    if (callback == NULL || !AXIsProcessTrusted()) {
        return NULL;
    }
    NdvInputCapture *capture = calloc(1, sizeof(*capture));
    if (capture == NULL) {
        return NULL;
    }
    capture->callback = callback;
    capture->callback_context = context;
    capture->control = calloc(1, sizeof(*capture->control));
    if (capture->control == NULL) {
        free(capture);
        return NULL;
    }
    capture->control->run_loop = CFRunLoopGetCurrent();
    CFRetain(capture->control->run_loop);
    atomic_init(&capture->control->reference_count, 1);
    atomic_init(&capture->control->stop_requested, false);
    atomic_init(&capture->control->exit_reason,
                NDV_CAPTURE_STOP_REQUESTED);

    CGEventMask mask = CGEventMaskBit(kCGEventKeyDown) |
                       CGEventMaskBit(kCGEventKeyUp) |
                       CGEventMaskBit(kCGEventFlagsChanged) |
                       CGEventMaskBit(kCGEventMouseMoved) |
                       CGEventMaskBit(kCGEventLeftMouseDragged) |
                       CGEventMaskBit(kCGEventRightMouseDragged) |
                       CGEventMaskBit(kCGEventOtherMouseDragged) |
                       CGEventMaskBit(kCGEventLeftMouseDown) |
                       CGEventMaskBit(kCGEventLeftMouseUp) |
                       CGEventMaskBit(kCGEventRightMouseDown) |
                       CGEventMaskBit(kCGEventRightMouseUp) |
                       CGEventMaskBit(kCGEventOtherMouseDown) |
                       CGEventMaskBit(kCGEventOtherMouseUp) |
                       CGEventMaskBit(kCGEventScrollWheel) |
                       CGEventMaskBit((CGEventType)NSEventTypeSystemDefined);
    capture->event_tap = CGEventTapCreate(
        kCGSessionEventTap, kCGHeadInsertEventTap, kCGEventTapOptionDefault,
        mask, ndv_event_tap_callback, capture);
    if (capture->event_tap == NULL) {
        CFRelease(capture->control->run_loop);
        free(capture->control);
        free(capture);
        return NULL;
    }
    capture->run_loop_source = CFMachPortCreateRunLoopSource(
        kCFAllocatorDefault, capture->event_tap, 0);
    if (capture->run_loop_source == NULL) {
        CFRelease(capture->event_tap);
        CFRelease(capture->control->run_loop);
        free(capture->control);
        free(capture);
        return NULL;
    }
    CFRunLoopAddSource(capture->control->run_loop, capture->run_loop_source,
                       kCFRunLoopCommonModes);
    if (!ndv_register_lifecycle(capture)) {
        CFRunLoopRemoveSource(capture->control->run_loop,
                              capture->run_loop_source,
                              kCFRunLoopCommonModes);
        CFRelease(capture->run_loop_source);
        CFRelease(capture->event_tap);
        CFRelease(capture->control->run_loop);
        free(capture->control);
        free(capture);
        return NULL;
    }
    CGEventTapEnable(capture->event_tap, true);
    if (!CGEventTapIsEnabled(capture->event_tap)) {
        ndv_unregister_lifecycle(capture);
        CFRunLoopRemoveSource(capture->control->run_loop,
                              capture->run_loop_source,
                              kCFRunLoopCommonModes);
        CFRelease(capture->run_loop_source);
        CFRelease(capture->event_tap);
        CFRelease(capture->control->run_loop);
        free(capture->control);
        free(capture);
        return NULL;
    }
    return capture;
}

void *ndv_input_capture_create_stop_handle(void *opaque_capture) {
    NdvInputCapture *capture = opaque_capture;
    if (capture == NULL || capture->control == NULL) {
        return NULL;
    }
    (void)atomic_fetch_add_explicit(&capture->control->reference_count, 1,
                                    memory_order_relaxed);
    return capture->control;
}

static void ndv_input_capture_stop_internal(NdvInputCaptureControl *control,
                                            int32_t reason) {
    if (control == NULL) {
        return;
    }
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(
            &control->stop_requested, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        atomic_store_explicit(&control->exit_reason, reason,
                              memory_order_release);
    }
    CFRunLoopStop(control->run_loop);
    CFRunLoopWakeUp(control->run_loop);
}

void ndv_input_capture_stop(void *opaque_control) {
    ndv_input_capture_stop_internal(opaque_control,
                                    NDV_CAPTURE_STOP_REQUESTED);
}

int32_t ndv_input_capture_run(void *opaque_capture) {
    NdvInputCapture *capture = opaque_capture;
    if (capture == NULL || capture->event_tap == NULL ||
        !CGEventTapIsEnabled(capture->event_tap)) {
        return NDV_CAPTURE_NATIVE_FAILURE;
    }
    bool was_stopped = atomic_load_explicit(&capture->control->stop_requested,
                                            memory_order_acquire);
    if (!was_stopped) {
        CFRunLoopRun();
    }
    CGEventTapEnable(capture->event_tap, false);
    if (!atomic_load_explicit(&capture->control->stop_requested,
                              memory_order_acquire)) {
        return NDV_CAPTURE_NATIVE_FAILURE;
    }
    return atomic_load_explicit(&capture->control->exit_reason,
                                memory_order_acquire);
}

void ndv_input_capture_release(void *opaque_capture) {
    NdvInputCapture *capture = opaque_capture;
    if (capture == NULL) {
        return;
    }
    ndv_input_capture_stop_internal(capture->control,
                                    NDV_CAPTURE_STOP_REQUESTED);
    ndv_unregister_lifecycle(capture);
    if (capture->run_loop_source != NULL) {
        CFRunLoopRemoveSource(capture->control->run_loop,
                              capture->run_loop_source,
                              kCFRunLoopCommonModes);
        CFRelease(capture->run_loop_source);
    }
    if (capture->event_tap != NULL) {
        CFMachPortInvalidate(capture->event_tap);
        CFRelease(capture->event_tap);
    }
    if (atomic_fetch_sub_explicit(&capture->control->reference_count, 1,
                                  memory_order_acq_rel) == 1) {
        CFRelease(capture->control->run_loop);
        free(capture->control);
    }
    free(capture);
}

void ndv_input_capture_release_stop_handle(void *opaque_control) {
    NdvInputCaptureControl *control = opaque_control;
    if (control != NULL &&
        atomic_fetch_sub_explicit(&control->reference_count, 1,
                                  memory_order_acq_rel) == 1) {
        CFRelease(control->run_loop);
        free(control);
    }
}

static NSInteger ndv_media_key_type(uint16_t usage) {
    switch (usage) {
    case 0x00cd:
        return NX_KEYTYPE_PLAY;
    case 0x00b5:
        return NX_KEYTYPE_NEXT;
    case 0x00b6:
        return NX_KEYTYPE_PREVIOUS;
    case 0x00b3:
        return NX_KEYTYPE_FAST;
    case 0x00b4:
        return NX_KEYTYPE_REWIND;
    case 0x00e2:
        return NX_KEYTYPE_MUTE;
    case 0x00e9:
        return NX_KEYTYPE_SOUND_UP;
    case 0x00ea:
        return NX_KEYTYPE_SOUND_DOWN;
    default:
        return -1;
    }
}

bool ndv_post_media_key(uint16_t usage, bool pressed, int64_t tag) {
    NSInteger key_type = ndv_media_key_type(usage);
    if (key_type < 0 || !AXIsProcessTrusted()) {
        return false;
    }
    NSInteger key_state = pressed ? NX_KEYDOWN : NX_KEYUP;
    NSInteger data1 = (key_type << 16) | (key_state << 8);
    @autoreleasepool {
        @try {
            NSEvent *event = [NSEvent
                otherEventWithType:NSEventTypeSystemDefined
                          location:NSZeroPoint
                     modifierFlags:0
                         timestamp:NSProcessInfo.processInfo.systemUptime
                      windowNumber:0
                           context:nil
                           subtype:NX_SUBTYPE_AUX_CONTROL_BUTTONS
                             data1:data1
                             data2:-1];
            CGEventRef cg_event = event.CGEvent;
            if (cg_event == NULL) {
                return false;
            }
            CGEventSetIntegerValueField(cg_event, kCGEventSourceUserData, tag);
            CGEventPost(kCGSessionEventTap, cg_event);
            return true;
        } @catch (__unused NSException *exception) {
            return false;
        }
    }
}
