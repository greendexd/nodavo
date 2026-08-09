<!-- doc-id: windows-app; lang: en; revision: 3 -->

# Nodavo for Windows

[English](README.md) · [Русский](README.ru.md)

This directory contains the first native WinUI 3 shell for Nodavo. It provides bilingual overview, devices, layout, transfers, and settings screens. The overview implements bounded status and emergency-stop requests. The Devices screen implements listening/manual pairing, explicit per-capability selection, six-digit code comparison, bilateral confirmation, cancellation, and honest pre-alpha states; unfinished screens say that they are unavailable instead of simulating a working feature.

## Supported source targets

- Windows 10 22H2 and Windows 11.
- x64 and ARM64 project configurations.
- Packaged MSIX development builds and unpackaged development builds.
- Current-user execution only. The manifest requests `asInvoker`; login, UAC secure desktop, Session 0, and privileged unattended control are not supported.

## Build on Windows

Install Visual Studio 2022 17.10 or newer with the Windows application development workload, the .NET 8 SDK, Windows 10/11 SDK 10.0.26100, and MSIX tooling. Then run from the repository root:

```powershell
dotnet restore apps/windows/Nodavo.Windows.sln -p:Platform=x64
dotnet build apps/windows/Nodavo.Windows.sln -c Release -p:Platform=x64
```

For an unpackaged development build:

```powershell
dotnet build apps/windows/Nodavo.Windows.sln -c Release -p:Platform=x64 -p:NodavoPackageMode=Unpackaged
```

Use `ARM64` and `win-arm64` on native Windows ARM64 build hardware. The included publish profiles are development inputs, not signed release definitions.

An unpackaged build requires the matching Windows App Runtime to be installed. Producing an installable public MSIX requires a real publisher identity and Authenticode certificate; neither is included in the repository.

## Local IPC contract

The UI connects to `\\.\pipe\nodavo-agent-{current-user-SID}` using .NET's current-user-only named-pipe option. Each message is a four-byte unsigned big-endian length followed by UTF-8 JSON, with a hard 64 KiB limit. The shell sends `get_status`, `emergency_stop`, `begin_pairing`, and `confirm_pairing`; long pairing requests have a bounded deadline and are cancellable from the UI. All permissions default to off and the explicit selection is signed into pairing trust. The shell does not log response bodies, peer traffic, input, clipboard data, filenames, pairing codes, keys, or stable network identifiers.

## Current limitations

This source has not been compiled, linked, or run on Windows from the current macOS development host. XML, resource parity, and source-level invariants can be checked here, but Windows CI and real Windows x64/ARM64 machines are required for build and runtime evidence.

The Rust source now includes a same-user/session validated named-pipe server and DPAPI-protected identity/trust storage, and this shell includes the matching pairing flow. They cross-compile or pass source/XML checks from macOS, but have not yet been linked or run together on Windows; runtime success is therefore not claimed. Trusted-device permissions/revocation UI, layout editing, input routing, clipboard, transfers, tray integration, autostart, diagnostics, updates, installers, and signing remain under implementation. `Package.appxmanifest` uses a development publisher and package version and must not be distributed as a stable release.

The UI and IPC code are original clean-room work derived from Nodavo's own architecture and local IPC contract; no third-party KVM source or assets were used.
