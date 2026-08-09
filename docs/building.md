<!-- doc-id: building; lang: en; revision: 3 -->

# Building Nodavo

[English](building.md) · [Русский](building.ru.md)

Nodavo is under active pre-alpha implementation. These commands build development components; they do not produce signed 1.0 installers.

## Rust workspace

Requirements: the stable Rust toolchain with Rust 1.96 or newer, Cargo, Clippy, and rustfmt.

```bash
cargo check --workspace
cargo run -p nodavo-agent -- --self-check
```

The checked-in `Cargo.lock` pins development and application dependencies. Core crates are platform-neutral. The macOS adapter builds only on macOS; the Windows adapter must be fully linked on a Windows MSVC host.

## macOS shell

Requirements: macOS 13 or newer and a current full Xcode installation.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

The menu-bar shell connects to the agent through `~/Library/Application Support/Nodavo/agent.sock`. Set `NODAVO_IPC_PATH` for an isolated development socket. Accessibility permission is required before input capture or injection can run.

The agent listens for pairing bootstrap on `0.0.0.0:44310` by default. Set `NODAVO_PAIRING_ADDR` to another local socket address when running multiple development agents. In the Devices screen, select each permission explicitly, let one peer choose **Wait for another device**, and enter `IP:PORT` or `mdns:INSTANCE` on the other; compare and confirm the same code on both peers. Permissions default to off and are signed into the confirmed pairing transcript.

The current command-line development agent stores test identity and trust material in private per-user files. The implemented macOS Keychain boundary deliberately fails without a provisioned application identifier and Keychain access group, so it is not silently replaced with plaintext storage. Do not use development identities as release credentials.

## Feasibility programs

```bash
swift build --package-path spikes/macos-input
swift build --package-path spikes/macos-clipboard
```

The Windows crate can be type-checked from this Mac because the Rust target is installed:

```bash
cargo check -p nodavo-platform-windows --target x86_64-pc-windows-msvc
```

Type-checking is not Windows runtime evidence. Linking, WinUI, input hooks, clipboard, DPI, installers, x64/ARM64, and real hardware still require Windows CI and Windows machines.
