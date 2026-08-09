<!-- doc-id: macos-app; lang: ru; translation-of: README.md; revision: 3 -->

# Nodavo для macOS

[English](README.md) · [Русский](README.ru.md)

Текущая SwiftUI-оболочка в строке меню подключается к пользовательскому Rust-агенту через приватный Unix socket. Она показывает ограниченные метаданные статуса/focus, предоставляет emergency stop и ручное управление focus, а также реализует ожидающее/ручное сопряжение с отдельными разрешениями и шестизначным кодом. В pre-alpha работают pairing, pinned reconnect, authenticated input session и native capture/injection bridge macOS. Edge switching, cross-device mapping дисплеев, trusted-device management, изменение разрешений, transfers, подпись и упаковка ещё разрабатываются.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

Все разрешения при сопряжении по умолчанию выключены. Выбор привязывается к подтверждённому transcript сопряжения и подписанному доверию устройств. Текущий macOS-агент разработки пока использует приватные development-файлы; до интеграции границы Keychain требуется корректно подписанное и provisioned приложение.
