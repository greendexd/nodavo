#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/hidsystem/ev_keymap.h>
#import <IOKit/hidsystem/IOLLEvent.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
