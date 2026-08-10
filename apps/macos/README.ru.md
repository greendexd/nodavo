<!-- doc-id: macos-app; lang: ru; translation-of: README.md; revision: 7 -->

# Nodavo для macOS

[English](README.md) · [Русский](README.ru.md)

Текущая SwiftUI-оболочка в строке меню подключается к пользовательскому Rust-агенту через приватный Unix socket. Она показывает ограниченные сводки статуса/focus и доверенных устройств, предоставляет emergency stop и ручное управление focus, реализует ожидающее/ручное сопряжение с отдельными разрешениями и шестизначным кодом, а также транзакционное изменение разрешений после сопряжения и подтверждённый отзыв доверия. Раздел «Передачи» ставит в очередь до 32 файлов или папок, явно выбранных через системное окно macOS, и показывает только сокращённую ссылку очереди. В pre-alpha работают pairing, pinned reconnect, authenticated input session, native capture/injection bridge macOS и ограниченная очередь передачи файлов. Edge switching, cross-device mapping дисплеев, подробный прогресс передачи в локальном IPC и широкая кросс-платформенная проверка ещё разрабатываются.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

Все разрешения при сопряжении по умолчанию выключены. Выбор привязывается к подтверждённому transcript сопряжения и подписанному доверию устройств. Переключатель после сопряжения меняется только после подтверждения агентом точной операции; разрешения отозванного устройства редактировать нельзя, его нужно сопрячь заново. Интерфейс не отправляет вычисленные пути файловой системы: принимаются только абсолютные пути, возвращённые явным выбором в локальном системном окне.

## Обновления

Settings предоставляет текущий не активирующий обновления slice. Пользователь может вручную запустить проверку или обновить статус, увидеть результат up-to-date, явно выбрать **Загрузить и подготовить** или **Отклонить** для точного предложения, следить за ограниченным прогрессом и возобновить приостановленную загрузку. Один polling loop с владельцем-generation использует отдельный client агента после согласия или во время загрузки, поэтому не блокирует pairing, transfers или emergency stop и прекращается в terminal или paused state. Интерфейс никогда не показывает URL манифеста, staging path или digest. Проверенный результат честно обозначается как staged; автоматическая установка недоступна в development build.

Агент по умолчанию не настроен. Только сборка, в которую явно встроены закреплённые HTTPS endpoint манифеста и публичный ключ Ed25519, может обращаться к update service; репозиторий не содержит ни production endpoint, ни приватного signing key, а live production check или signing ceremony не заявляются. Текущий путь macOS/Unix использует нативный платформенный TLS без redirects и decompression, проверяет ограниченный подписанный манифест и same-origin артефакт, привязывает согласие к его canonical offer UUID и возобновляемо пишет проверенное по digest содержимое в приватный capability-rooted staging root с межпроцессной арендой, квотами, retention и fsync.

Отсутствуют installer handoff, activation, перезапуск приложения или агента, health/rollback supervisor, защищённый production Keychain-журнал состояния обновлений и durable rollback floor. Staged content не выполняется. Изменяющий updater IPC ограничен тем же локальным пользователем, но пока не аутентифицирует signed/provisioned UI Nodavo относительно других процессов этого пользователя; более сильная client authentication остаётся stable-release gate. Windows updater staging и UI integration также отсутствуют.

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
