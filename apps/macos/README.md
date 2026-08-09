<!-- doc-id: macos-app; lang: en; revision: 3 -->

# Nodavo for macOS

[English](README.md) · [Русский](README.ru.md)

The current SwiftUI menu-bar shell connects to the per-user Rust agent through its private Unix socket. It displays bounded status/focus metadata, exposes local emergency stop and manual focus controls, and implements listening/manual pairing with explicit per-capability selection and six-digit code confirmation. Pairing, pinned reconnect, the authenticated input session, and the macOS native capture/injection bridge run in pre-alpha. Edge switching, cross-device display mapping, trusted-device management, post-pair permission changes, transfers, signing, and packaging remain under implementation.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

All pairing permissions default to off. The selected permissions are bound to the confirmed pairing transcript and signed device trust. The current macOS development agent still uses private development files; its Keychain boundary requires a correctly signed and provisioned app before integration.
