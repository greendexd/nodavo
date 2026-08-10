#![no_main]

use ed25519_dalek::VerifyingKey;
use libfuzzer_sys::fuzz_target;
use nodavo_update::{ReleaseVerifier, RollbackState, VerificationPolicy};
use semver::Version;

const PUBLIC_KEY: [u8; 32] = [
    144, 23, 104, 79, 80, 228, 113, 121, 75, 64, 212, 118, 181, 66, 104, 119, 204, 209, 47,
    37, 158, 74, 3, 241, 167, 101, 16, 168, 71, 18, 62, 104,
];

fuzz_target!(|bytes: &[u8]| {
    let key = VerifyingKey::from_bytes(&PUBLIC_KEY).expect("fixed public key");
    let policy = VerificationPolicy::new(
        "nodavo",
        "stable",
        "macos",
        "aarch64",
        "dev.nodavo.macos",
        Version::new(1, 5, 0),
    )
    .expect("fixed verification policy");
    let verifier = ReleaseVerifier::new(key, policy);
    let floor = RollbackState::new(7, Version::new(1, 5, 0));
    let _ = verifier.verify_json(bytes, &floor);
});
