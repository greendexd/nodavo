<!-- doc-id: macos-input-spike; lang: en; revision: 1 -->

# macOS input feasibility spike

[English](README.md) · [Русский](README.ru.md)

This disposable M0 program verifies the official CoreGraphics and Accessibility path before it is wrapped by the production platform adapter. It does not transmit input and deliberately logs event categories only.

```bash
swift build --package-path spikes/macos-input
.build/debug/nodavo-macos-input-spike --request-permission
.build/debug/nodavo-macos-input-spike --monitor
```

`--inject-probe` posts a tagged no-motion event. A running monitor must observe physical event categories while ignoring that tagged event. Real permission, sleep, lock, update-signature, and Intel/ARM evidence remains required before M0 can close.
