#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/hidsystem/ev_keymap.h>
#import <IOKit/hidsystem/IOLLEvent.h>
#import <Security/Security.h>
#import <xpc/xpc.h>

#include <bsm/libbsm.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

enum {
    NDV_IPC_OK = 0,
    NDV_IPC_REJECTED = 1,
};

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
