use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/macos/ffi.m");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=NODAVO_APPLE_TEAM_ID");
    if env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some(OsStr::new("macos")) {
        return;
    }

    if let Some(team_id) = env::var_os("NODAVO_APPLE_TEAM_ID") {
        let team_id = team_id
            .into_string()
            .expect("NODAVO_APPLE_TEAM_ID must be ASCII");
        assert!(
            team_id.len() == 10
                && team_id
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()),
            "NODAVO_APPLE_TEAM_ID must be exactly 10 uppercase ASCII letters or digits"
        );
        println!("cargo:rustc-env=NODAVO_APPLE_TEAM_ID={team_id}");
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"));
    let object = out_dir.join("nodavo_macos_ffi.o");
    let archive = out_dir.join("libnodavo_macos_ffi.a");
    let target = env::var_os("TARGET").expect("Cargo must provide TARGET");
    let deployment_target = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "13.0".into());

    run_xcrun([
        OsString::from("--sdk"),
        OsString::from("macosx"),
        OsString::from("clang"),
        OsString::from("-target"),
        target,
        OsString::from(format!("-mmacosx-version-min={deployment_target}")),
        OsString::from("-fobjc-arc"),
        OsString::from("-fblocks"),
        OsString::from("-Wall"),
        OsString::from("-Wextra"),
        OsString::from("-Werror"),
        OsString::from("-c"),
        OsString::from("src/macos/ffi.m"),
        OsString::from("-o"),
        object.as_os_str().to_owned(),
    ]);
    run_xcrun([
        OsString::from("--sdk"),
        OsString::from("macosx"),
        OsString::from("ar"),
        OsString::from("rcs"),
        archive.as_os_str().to_owned(),
        object.as_os_str().to_owned(),
    ]);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=nodavo_macos_ffi");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Carbon");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=bsm");
}

fn run_xcrun<const N: usize>(arguments: [OsString; N]) {
    let status = Command::new("xcrun")
        .args(arguments)
        .status()
        .expect("failed to launch xcrun for the macOS FFI shim");
    assert!(status.success(), "macOS FFI shim compilation failed");
}
