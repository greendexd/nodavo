#![no_main]

use libfuzzer_sys::fuzz_target;
use nodavo_update::{InstallAndRestartHandoff, MAX_INSTALL_HANDOFF_BYTES};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(decoded) = InstallAndRestartHandoff::decode(bytes) {
        let encoded = decoded.encode().expect("decoded handoff must re-encode");
        assert!(encoded.len() <= MAX_INSTALL_HANDOFF_BYTES);
        assert_eq!(encoded, bytes);
        assert_eq!(
            InstallAndRestartHandoff::decode(&encoded).expect("canonical handoff"),
            decoded
        );
    }
});
