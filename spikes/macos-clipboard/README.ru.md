<!-- doc-id: macos-clipboard-spike; lang: ru; translation-of: README.md; revision: 1 -->

# Проверка буфера macOS

[English](README.md) · [Русский](README.ru.md)

Эта одноразовая программа M0 проверяет версии `NSPasteboard` и обнаружение поддерживаемых форматов, не выводя содержимое буфера. Проверка чтения и записи использует отдельный именованный pasteboard и не заменяет общий буфер пользователя.

```bash
swift build --package-path spikes/macos-clipboard
spikes/macos-clipboard/.build/debug/nodavo-macos-clipboard-spike --inspect
spikes/macos-clipboard/.build/debug/nodavo-macos-clipboard-spike --round-trip-private
```

До закрытия M0 всё ещё нужны реальные доказательства для текста, HTML, изображений, лимитов размера, повреждённых данных и защиты от циклов в общем буфере.
