<!-- doc-id: macos-app; lang: ru; translation-of: README.md; revision: 5 -->

# Nodavo для macOS

[English](README.md) · [Русский](README.ru.md)

Текущая SwiftUI-оболочка в строке меню подключается к пользовательскому Rust-агенту через приватный Unix socket. Она показывает ограниченные метаданные статуса/focus, предоставляет emergency stop и ручное управление focus, а также реализует ожидающее/ручное сопряжение с отдельными разрешениями и шестизначным кодом. В pre-alpha работают pairing, pinned reconnect, authenticated input session и native capture/injection bridge macOS. Edge switching, cross-device mapping дисплеев, trusted-device management, изменение разрешений и transfers ещё разрабатываются.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

Все разрешения при сопряжении по умолчанию выключены. Выбор привязывается к подтверждённому transcript сопряжения и подписанному доверию устройств.

## Упаковка

Репозиторий может собрать universal-приложение `arm64` + `x86_64`, содержащее SwiftUI executable и пользовательский helper агента:

```bash
scripts/package-macos.sh --development --version 0.1.0 --build-number 1
```

Этот development-артефакт подписан ad-hoc, не нотариализован, не имеет provisioned-доступа к Keychain, не регистрирует встроенный LaunchAgent и помечен как непригодный для распространения. Это проверка структуры bundle, а не релиз.

Release-упаковка завершается с ошибкой, если вызывающая сторона явно не передала Developer ID identity, Team ID, отдельные provisioning profiles для `dev.nodavo.macos` и `dev.nodavo.agent`, а также профиль Keychain для `notarytool`:

```bash
APPLE_TEAM_ID=TEAMID1234 \
MACOS_SIGNING_IDENTITY="Developer ID Application: Example" \
MACOS_APP_PROVISIONING_PROFILE=/path/to/app.provisionprofile \
MACOS_AGENT_PROVISIONING_PROFILE=/path/to/agent.provisionprofile \
MACOS_NOTARY_PROFILE=nodavo-notary \
scripts/package-macos.sh --version 1.0.0 --build-number 1
```

Оба provisioning profile должны разрешать точную Keychain access group `${APPLE_TEAM_ID}.dev.nodavo.agent`. Release-путь использует hardened runtime, регистрирует встроенный helper как пользовательский LaunchAgent и требует успешной нотариализации, stapling и проверки Gatekeeper до сообщения об успехе. Без учётных данных Nodavo для подписи и нотариализации эти release-шаги не проверялись.

Интерфейс упакованного приложения показывает, включён ли helper, ожидает ли он разрешения в «Объектах входа», отсутствует или не смог зарегистрироваться. При ошибке регистрации Nodavo не запускает незарегистрированную копию и не создаёт привилегированную службу.
