<!-- doc-id: privacy; lang: en; revision: 1 -->

# Privacy

[English](privacy.md) · [Русский](privacy.ru.md)

Nodavo is designed to operate directly between paired devices on a local network. No account, cloud storage, hosted relay, advertising identifier, or mandatory telemetry is planned for 1.0.

## Data processed locally

Depending on enabled capabilities, Nodavo may process pointer and keyboard events, clipboard representations, file metadata and contents, device identities, display layouts, connection addresses, performance counters, and local diagnostic logs.

Input, clipboard, and file data is sent only to the actively paired peer and only under the relevant capability. Content is not sent to the Nodavo maintainers.

## Logs

Logs must not record keystrokes, clipboard content, file contents, private filenames, pairing codes, private keys, or stable IP identifiers. Diagnostic exports are user initiated, previewable, and sanitized by default.

## Telemetry

Telemetry and crash uploading are disabled by default. If optional telemetry is introduced, the exact schema, purpose, retention, endpoint, and deletion process must be published before release. Consent must be explicit and revocable without losing updates or core features.

## Updates

Update checks may contact a documented release endpoint in future versions. The application must also support manual update workflows. Update access must not transmit input or content data and must not require an account.

## Paired peers

Pairing grants another computer technical access to selected capabilities. Users should pair only devices they control and revoke trust when a device is lost, transferred, reinstalled, or suspected of compromise.

