<!-- doc-id: macos-clipboard-spike; lang: en; revision: 1 -->

# macOS clipboard feasibility spike

[English](README.md) · [Русский](README.ru.md)

This disposable M0 program validates `NSPasteboard` revision tracking and supported format discovery without printing clipboard contents. Its write/read probe uses a private named pasteboard and does not replace the user's general clipboard.

```bash
swift build --package-path spikes/macos-clipboard
spikes/macos-clipboard/.build/debug/nodavo-macos-clipboard-spike --inspect
spikes/macos-clipboard/.build/debug/nodavo-macos-clipboard-spike --round-trip-private
```

General-pasteboard text, HTML, image, size-limit, malformed-data, and loop-prevention evidence is still required before M0 closes.
