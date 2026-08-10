<!-- doc-id: windows-app; lang: en; revision: 11 -->

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
- `WINDOWS_PACKAGE_FAMILY_NAME`: exact reserved PFN; the official Windows package API must derive it from the configured package name and publisher.
- `WINDOWS_PUBLISHER_DISPLAY_NAME`: public publisher name.
- `WINDOWS_SIGNING_PFX`: identity-validated Authenticode PFX path.
- `WINDOWS_SIGNING_CERTIFICATE`: public DER certificate matching the PFX. Only this public certificate and its hash are exposed to Rust and .NET builds.
- `WINDOWS_SIGNING_PFX_PASSWORD`: PFX password. The script copies it into a `SecureString` and deletes the process environment variable before invoking Rust, .NET, or other build tooling; it is never passed on the SignTool command line.
- `WINDOWS_TIMESTAMP_URL`: HTTPS RFC 3161 timestamp endpoint.
- `WINDOWS_SIGNING_CHAIN_ALLOWLIST`: comma- or semicolon-separated allowlist of reviewed 40-hex certificate thumbprints. The validated chain's immediate issuing CA or trust root must match one entry; do not list only the signing leaf.

```powershell
pwsh -NoProfile -File scripts/package-windows.ps1 `
  -Version 1.0.0 -BuildNumber 1
```

Release packaging validates the public certificate, exact PFN, online revocation, trusted chain, subject, validity, and Code Signing EKU before building. The private-key PFX is not opened or imported until every Rust and .NET build completes, must contain the exact public certificate, and is cleaned up only by the exact known imported thumbprints. Each `Nodavo.Windows.exe`, each `agent\nodavo-agent.exe`, and the final bundle receive the same trusted RFC 3161-timestamped signature. The script unpacks the bundle again and rechecks the exact identity/PFN/AUMID/executables, signer, embedded UI server-auth policy, x64/ARM64 payloads, two-capability multiset, development-marker absence, and secret-file absence. No release certificate or password is stored in the repository or artifact.

The package declares only LAN access (`privateNetworkClientServer`) and the `runFullTrust` capability required by a desktop `mediumIL` package. It does not request broad filesystem, location, camera, microphone, enterprise-authentication, service, UAC, or secure-desktop capability. The included `app.manifest` explicitly requests `asInvoker` with `uiAccess=false`.

The separate Windows packaging workflow proves only that the self-signed development path can assemble and verify an x64/ARM64 bundle on a Windows runner. Its artifact retention is short and its name says that it is not for distribution. The workflow has no release credentials and cannot produce a release.

## Local IPC contract

Before decoding any frame, the agent binds the accepted pipe connection to an opaque guard that retains the exact client process, primary token, and executable handles. Authorization requires the configured development or release package identity, PFN, UI AUMID, executable location, and embedded Authenticode signer certificate. The guard revalidates the same process/token/package/image identity both before each bounded read and again after decoding immediately before dispatch.

The UI independently authenticates the pipe server before writing a command. Its compile-time policy must match the exact `Package.Current` name, publisher, PFN, UI AUMID, and installed package root. It then retains the pipe-reported server process, primary token, creation time, and a read-only no-share-delete handle to the exact non-reparse `agent\nodavo-agent.exe` under that root. The server must have the same user/session/logon identity, remain live, execute that exact image, and carry the pinned trusted Authenticode signer; release builds additionally require validated timestamp evidence. The UI revalidates the connection and retained identity before waiting for a response and again after the bounded response read, before JSON decoding. The separately launched agent process is not claimed to have package identity or an AUMID; trust comes from the authenticated UI package's content-enforced root plus the exact signed executable inside it. Unconfigured and unpackaged UI builds fail closed, and no runtime environment or path override exists.

Together these checks reject ordinary independent same-user/session clients, pipe-name squatters, and PID, path, package, token, executable, or signer substitution. They do not establish a separate Windows principal between the two `mediumIL` processes and do not claim protection from arbitrary same-user malware. A process that obtains invasive access to either authorized process—such as `PROCESS_DUP_HANDLE`, process-memory read/write, debugging, injection, or hollowing—is treated as a compromise of that process and is outside the Windows 1.0 boundary. Supporting that stronger threat model requires a separately isolated broker/principal; shorter one-request connections reduce capability lifetime but are not a substitute for that isolation.

The UI connects to `\\.\pipe\nodavo-agent-{current-user-SID}` using .NET's current-user-only named-pipe option. Each authenticated connection carries exactly one request and one response and is then closed; a later command creates a new authenticated connection. Each message is a four-byte unsigned big-endian length followed by UTF-8 JSON, with a hard 64 KiB limit. The shell sends bounded status, emergency-stop, pairing, trusted-peer listing, grant mutation, revocation, and selected-path transfer commands. Long pairing requests have a bounded deadline and are cancellable from the UI. All permissions default to off and the explicit selection is signed into pairing trust. Trusted-list refresh and trust mutation have separate serialized ownership. A grant switch is committed after an exact echo; an explicit agent error restores the previous authoritative value. A lost, timed-out, or invalid mutation response is instead treated as unknown: the affected peer remains disabled while the UI waits beyond the agent's two sequential five-second safety windows and reconciles from a new authoritative trusted-peer list. File requests contain one to 32 unique absolute paths explicitly returned by Windows pickers; each UTF-8 path is at most 4 KiB, and the response is reduced to a redacted transfer ID before it reaches the view. The transfer client waits beyond the agent's five-minute preparation deadline. If that response is ambiguous, the existing selection is locked against retry until the user explicitly makes a fresh picker selection. The shell does not log response bodies, peer traffic, input, clipboard data, filenames, pairing codes, keys, or stable network identifiers.

## Packaged agent lifecycle

The Overview screen can launch the bundled unprivileged `agent\nodavo-agent.exe` only after an explicit Start agent action. The lifecycle coordinator first probes the private pipe, serializes concurrent requests, and launches at most once before a bounded readiness poll. If sign-in activation races the UI action, the agent's first-instance pipe makes the later process fail closed instead of creating a second server. The UI resolves only `Package.Current.InstalledLocation`, requires canonical containment under that package root, the exact filename, and a regular non-reparse file, then uses direct process creation with `UseShellExecute=false`, `CreateNoWindow=true`, and no arguments or untrusted executable input. The returned process handle is disposed immediately without terminating the child. This design relies on Windows keeping the installed package root immutable and content-enforced; it provides no unpackaged path fallback.

The package also declares one `windows.startupTask` for that exact agent executable with `Enabled=false`. The Settings screen is the only in-app enable/disable action. It reports enabled, disabled, user-disabled, policy-disabled, policy-enabled, and unavailable states; it never overrides a user's Task Manager/Startup Apps choice or administrator policy. There is no service, elevation, scheduled task, Registry `Run` key, shell, or PowerShell fallback. Startup remains current-user and occurs only after sign-in, never at the login screen, on the UAC secure desktop, or in Session 0. The directly created child is not claimed to receive a separate packaged activation identity; the current agent requires only the interactive user's unprivileged session behavior.

The reducer, concurrent-start, cancellation, and bounded-timeout paths have source tests wired into Windows CI. Installed-MSIX launch and sign-in behavior still require real x64 and ARM64 runtime qualification and are not claimed from source or CI compilation alone. Design provenance is Microsoft's documentation for [`StartupTask`](https://learn.microsoft.com/uwp/api/windows.applicationmodel.startuptask), [packaged desktop startup extensions](https://learn.microsoft.com/windows/apps/desktop/modernize/desktop-to-uwp-extensions), [`Package.InstalledLocation`](https://learn.microsoft.com/uwp/api/windows.applicationmodel.package.installedlocation), and direct [`ProcessStartInfo.UseShellExecute=false`](https://learn.microsoft.com/dotnet/api/system.diagnostics.processstartinfo.useshellexecute).

## Current limitations

This source cannot be compiled, linked, or run on the current macOS development host. The x64 WinUI source is compile-checked by Windows CI, while the packaging workflow is the required build evidence for the complete x64/ARM64 development bundle. CI remains compile/package evidence rather than interactive runtime qualification.

The Rust source now includes a connection-bound package, process/token, executable, and Authenticode-signer guard in addition to same-user/session checks and DPAPI-protected identity/trust storage. This shell includes the matching pairing, trust-management, explicit transfer-queue, packaged on-demand launch, and opt-in startup-task flows. They compile or pass source/XML checks, but have not yet been run together on qualified real Windows x64 and ARM64 systems; runtime success is therefore not claimed. The transfer screen proves only selection and queue acknowledgement, not end-to-end delivery. Installed lifecycle/autostart behavior, layout editing, full input routing, clipboard UX, transfer progress/resume/cancel UX, tray integration, diagnostics, updates, and production signing remain unqualified or under implementation. `Package.appxmanifest` is development-only and uses a separate identity so it cannot be confused with or upgrade over a public release.

Remaining release gates are exact and external: reserve/freeze the final Microsoft Store package identity and publisher in Partner Center; obtain Store approval for `runFullTrust` or use an identity-validated direct-distribution certificate; configure protected signing credentials and a reliable RFC 3161 endpoint; run clean install, upgrade, downgrade rejection, uninstall, certificate-expiry, tamper, rollback, and real x64/ARM64 runtime matrices; publish stable HTTPS artifacts and hashes before authoring a WinGet manifest. No MSI is emitted because Nodavo has not yet justified a second installer technology, tested its per-user upgrade/uninstall semantics, or qualified a WiX/MSI toolchain. MSI and portable ZIP remain optional decisions, not release claims.

Packaging design provenance is limited to Nodavo's own requirements and Microsoft's official documentation for [single-project MSIX automation](https://learn.microsoft.com/windows/apps/windows-app-sdk/single-project-msix), [package identity](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview), [desktop package capabilities](https://learn.microsoft.com/windows/apps/package-and-deploy/app-capability-declarations), and [MSIX signing and timestamping](https://learn.microsoft.com/windows/msix/package/signing-package-overview). No third-party KVM installer source or assets were used.

The UI and IPC code are original clean-room work derived from Nodavo's own architecture and local IPC contract; no third-party KVM source or assets were used.
