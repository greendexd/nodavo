<!-- doc-id: windows-app; lang: en; revision: 7 -->

# Nodavo for Windows

[English](README.md) · [Русский](README.ru.md)

This directory contains the first native WinUI 3 shell for Nodavo. It provides bilingual overview, devices, layout, transfers, and settings screens. The overview implements bounded status and emergency-stop requests. The Devices screen implements listening/manual pairing, code comparison and confirmation, a bounded trusted-device list, transactional changes for all four local grants, and confirmed destructive revocation. Transfers accepts only explicit Windows file/folder picker results, enforces the local 32-path/4-KiB-per-path bounds before IPC, and displays only a redacted transfer identifier after acknowledgement. These are source and CI claims, not qualified Windows runtime claims.

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

The cross-host static safety check validates bilingual resources, XAML XML, IPC deadline ordering, separate trust-operation ownership, reconciliation markers, and ambiguous-transfer retry lockout:

```bash
python3 apps/windows/tests/check_product_ui.py
```

Use `ARM64` and `win-arm64` for a direct native Windows ARM64 build. The packaging workflow may cross-build that payload on an x64 Windows runner, but only real ARM64 hardware can qualify its runtime. The included publish profiles are development inputs, not signed release definitions.

An unpackaged build requires the matching Windows App Runtime to be installed. Producing an installable public MSIX requires a real publisher identity and Authenticode certificate; neither is included in the repository.

## x64 and ARM64 MSIX packaging

The packaging script builds self-contained WinUI and Rust agent payloads for x64 and ARM64, creates one MSIX per architecture, combines them into a bundle, checks the manifest and PE architectures, and refuses private-key files in the package. It never installs a service or requests elevation: the Win32 manifests stay `asInvoker`, the package runs at `mediumIL`, installation is per-user, and login/UAC secure-desktop/Session 0 control remains excluded.

For a clearly labeled self-signed development artifact on Windows:

```powershell
pwsh -NoProfile -File scripts/package-windows.ps1 `
  -Development -Version 0.1.0 -BuildNumber 1
```

The result is written below `target/windows-packages/0.1.0.1-development/`. Both the bundle filename and package contents say `DEVELOPMENT-NOT-FOR-DISTRIBUTION`. The script creates a short-lived certificate, verifies the signature while that certificate is temporarily trusted, exports only the public `.cer`, and removes its private key from the certificate store. App Installer requires the test certificate in the local machine `TrustedPeople` store, which needs administrator approval even though MSIX itself installs per-user. Do that only on a disposable test machine and remove the certificate after testing.

Release mode is deliberately fail-closed. It requires all of these environment variables and refuses to build if any is absent or inconsistent:

- `WINDOWS_PACKAGE_PUBLISHER`: exact X.509 subject written to the package manifest.
- `WINDOWS_PUBLISHER_DISPLAY_NAME`: public publisher name.
- `WINDOWS_SIGNING_PFX`: identity-validated Authenticode PFX path.
- `WINDOWS_SIGNING_PFX_PASSWORD`: PFX password. The script copies it into a `SecureString` and deletes the process environment variable before invoking Rust, .NET, or other build tooling; it is never passed on the SignTool command line.
- `WINDOWS_TIMESTAMP_URL`: HTTPS RFC 3161 timestamp endpoint.
- `WINDOWS_SIGNING_CHAIN_ALLOWLIST`: comma- or semicolon-separated allowlist of reviewed 40-hex certificate thumbprints. The validated chain's immediate issuing CA or trust root must match one entry; do not list only the signing leaf.

```powershell
pwsh -NoProfile -File scripts/package-windows.ps1 `
  -Version 1.0.0 -BuildNumber 1
```

Release packaging builds and inspects the unsigned bundle before loading the PFX. It then requires exactly one private-key leaf, rejects self-signed and CA certificates, checks the exact subject, validity, and Code Signing EKU, performs online revocation and trusted-chain validation, and requires the immediate issuer or root to match `WINDOWS_SIGNING_CHAIN_ALLOWLIST`. Before importing the PFX, it snapshots `CurrentUser/My`; its `finally` cleanup removes the complete certificate delta even if import, validation, signing, or verification fails. The script signs only the final MSIX bundle, retains SignTool chain/timestamp verification, unpacks it again, and rechecks the identity, display name, x64/ARM64 payloads, exact two-capability multiset, development-marker absence, and secret-file absence. No release certificate or password is stored in the repository or artifact.

The package declares only LAN access (`privateNetworkClientServer`) and the `runFullTrust` capability required by a desktop `mediumIL` package. It does not request broad filesystem, location, camera, microphone, enterprise-authentication, service, UAC, or secure-desktop capability. The included `app.manifest` explicitly requests `asInvoker` with `uiAccess=false`.

The separate Windows packaging workflow proves only that the self-signed development path can assemble and verify an x64/ARM64 bundle on a Windows runner. Its artifact retention is short and its name says that it is not for distribution. The workflow has no release credentials and cannot produce a release.

## Local IPC contract

The UI connects to `\\.\pipe\nodavo-agent-{current-user-SID}` using .NET's current-user-only named-pipe option. Each message is a four-byte unsigned big-endian length followed by UTF-8 JSON, with a hard 64 KiB limit. The shell sends bounded status, emergency-stop, pairing, trusted-peer listing, grant mutation, revocation, and selected-path transfer commands. Long pairing requests have a bounded deadline and are cancellable from the UI. All permissions default to off and the explicit selection is signed into pairing trust. Trusted-list refresh and trust mutation have separate serialized ownership. A grant switch is committed after an exact echo; an explicit agent error restores the previous authoritative value. A lost, timed-out, or invalid mutation response is instead treated as unknown: the affected peer remains disabled while the UI waits beyond the agent's two sequential five-second safety windows and reconciles from a new authoritative trusted-peer list. File requests contain one to 32 unique absolute paths explicitly returned by Windows pickers; each UTF-8 path is at most 4 KiB, and the response is reduced to a redacted transfer ID before it reaches the view. The transfer client waits beyond the agent's five-minute preparation deadline. If that response is ambiguous, the existing selection is locked against retry until the user explicitly makes a fresh picker selection. The shell does not log response bodies, peer traffic, input, clipboard data, filenames, pairing codes, keys, or stable network identifiers.

## Current limitations

This source cannot be compiled, linked, or run on the current macOS development host. The x64 WinUI source is compile-checked by Windows CI, while the packaging workflow is the required build evidence for the complete x64/ARM64 development bundle. CI remains compile/package evidence rather than interactive runtime qualification.

The Rust source now includes a same-user/session validated named-pipe server and DPAPI-protected identity/trust storage, and this shell includes the matching pairing, trust-management, and explicit transfer-queue flows. They compile or pass source/XML checks, but have not yet been run together on qualified real Windows x64 and ARM64 systems; runtime success is therefore not claimed. The transfer screen proves only selection and queue acknowledgement, not end-to-end delivery. Packaged agent lifecycle/autostart UX, layout editing, full input routing, clipboard UX, transfer progress/resume/cancel UX, tray integration, diagnostics, updates, and production signing remain under implementation. `Package.appxmanifest` is development-only and uses a separate identity so it cannot be confused with or upgrade over a public release.

Remaining release gates are exact and external: reserve/freeze the final Microsoft Store package identity and publisher in Partner Center; obtain Store approval for `runFullTrust` or use an identity-validated direct-distribution certificate; configure protected signing credentials and a reliable RFC 3161 endpoint; run clean install, upgrade, downgrade rejection, uninstall, certificate-expiry, tamper, rollback, and real x64/ARM64 runtime matrices; publish stable HTTPS artifacts and hashes before authoring a WinGet manifest. No MSI is emitted because Nodavo has not yet justified a second installer technology, tested its per-user upgrade/uninstall semantics, or qualified a WiX/MSI toolchain. MSI and portable ZIP remain optional decisions, not release claims.

Packaging design provenance is limited to Nodavo's own requirements and Microsoft's official documentation for [single-project MSIX automation](https://learn.microsoft.com/windows/apps/windows-app-sdk/single-project-msix), [package identity](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview), [desktop package capabilities](https://learn.microsoft.com/windows/apps/package-and-deploy/app-capability-declarations), and [MSIX signing and timestamping](https://learn.microsoft.com/windows/msix/package/signing-package-overview). No third-party KVM installer source or assets were used.

The UI and IPC code are original clean-room work derived from Nodavo's own architecture and local IPC contract; no third-party KVM source or assets were used.
