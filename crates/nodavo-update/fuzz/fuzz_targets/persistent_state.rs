#![no_main]

use libfuzzer_sys::fuzz_target;
use nodavo_update::{InstallJournal, RollbackState, SupervisionJournal};

fuzz_target!(|bytes: &[u8]| {
    let _ = RollbackState::decode(bytes);
    let _ = InstallJournal::decode(bytes);
    let _ = SupervisionJournal::decode(bytes);
});
