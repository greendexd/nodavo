use std::time::Duration;

use nodavo_platform_macos::{
    MacInputCapture, MacInputCaptureEvent, MacInputLifecycleEvent, accessibility_trusted,
};

fn main() {
    println!("probe_mode=inert capture=yes suppression=no injection=no");
    println!("accessibility_trusted={}", accessibility_trusted());

    let mut capture = MacInputCapture::new(|event| {
        if let MacInputCaptureEvent::Lifecycle(lifecycle) = event {
            println!("lifecycle={}", lifecycle_name(lifecycle));
        }
    });
    if let Err(error) = capture.start() {
        eprintln!("capture_start_failed={error}");
        std::process::exit(1);
    }
    assert!(!capture.routing_to_peer());
    std::thread::sleep(Duration::from_millis(50));
    if let Err(error) = capture.restart() {
        eprintln!("capture_restart_failed={error}");
        std::process::exit(1);
    }
    assert!(!capture.routing_to_peer());
    println!("capture_restarted=true");
    std::thread::sleep(Duration::from_millis(50));
    if let Err(error) = capture.stop() {
        eprintln!("capture_stop_failed={error}");
        std::process::exit(1);
    }
    println!("capture_stopped=true");
}

const fn lifecycle_name(event: MacInputLifecycleEvent) -> &'static str {
    match event {
        MacInputLifecycleEvent::CaptureStarted => "capture_started",
        MacInputLifecycleEvent::CaptureStopped => "capture_stopped",
        MacInputLifecycleEvent::SystemWillSleep => "system_will_sleep",
        MacInputLifecycleEvent::SystemDidWake => "system_did_wake",
        MacInputLifecycleEvent::ScreensDidSleep => "screens_did_sleep",
        MacInputLifecycleEvent::ScreensDidWake => "screens_did_wake",
        MacInputLifecycleEvent::SessionDidResignActive => "session_inactive",
        MacInputLifecycleEvent::SessionDidBecomeActive => "session_active",
        MacInputLifecycleEvent::TapDisabledByTimeout => "tap_timeout",
        MacInputLifecycleEvent::TapDisabledByUserInput => "tap_disabled",
    }
}
