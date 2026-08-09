<!-- doc-id: building; lang: ru; translation-of: building.md; revision: 3 -->

# Сборка Nodavo

[English](building.md) · [Русский](building.ru.md)

Nodavo находится в активной pre-alpha разработке. Эти команды собирают компоненты для разработки, а не подписанные установщики 1.0.

## Rust workspace

Требования: стабильный Rust версии 1.96 или новее, Cargo, Clippy и rustfmt.

```bash
cargo check --workspace
cargo run -p nodavo-agent -- --self-check
```

Файл `Cargo.lock` фиксирует зависимости приложений и разработки. Crates ядра не зависят от платформы. Адаптер macOS собирается только на macOS, а полноценная линковка Windows adapter требует Windows с MSVC.

## Оболочка macOS

Требования: macOS 13 или новее и актуальная полная установка Xcode.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

Оболочка в строке меню подключается к агенту через `~/Library/Application Support/Nodavo/agent.sock`. Для отдельного сокета разработки задайте `NODAVO_IPC_PATH`. До захвата или эмуляции ввода необходимо разрешение Accessibility.

По умолчанию агент ожидает bootstrap сопряжения на `0.0.0.0:44310`. При запуске нескольких агентов для разработки задайте другой локальный адрес через `NODAVO_PAIRING_ADDR`. На экране устройств явно выберите каждое разрешение, на одном peer нажмите **Ждать другое устройство**, а на втором введите `IP:PORT` или `mdns:INSTANCE`; затем сравните и подтвердите одинаковый код. Разрешения по умолчанию выключены и подписываются в подтверждённом transcript сопряжения.

Текущий консольный агент разработки хранит тестовые идентификаторы и доверие в приватных пользовательских файлах. Реализованная граница macOS Keychain намеренно отказывает без provisioned application identifier и Keychain access group и не заменяется незаметно открытым файловым хранением. Не используйте development-идентификаторы как релизные учётные данные.

## Программы проверки реализуемости

```bash
swift build --package-path spikes/macos-input
swift build --package-path spikes/macos-clipboard
```

Windows crate можно проверить на этом Mac, потому что Rust target уже установлен:

```bash
cargo check -p nodavo-platform-windows --target x86_64-pc-windows-msvc
```

Проверка типов не является доказательством работы в Windows. Линковка, WinUI, input hooks, буфер, DPI, установщики, x64/ARM64 и реальное оборудование всё ещё требуют Windows CI и Windows-компьютеров.
