<!-- doc-id: macos-app; lang: ru; translation-of: README.md; revision: 9 -->

# Nodavo для macOS

[English](README.md) · [Русский](README.ru.md)

Текущая SwiftUI-оболочка в строке меню подключается к пользовательскому Rust-агенту через signed XPC в release build. Упакованный LaunchAgent объявляет `dev.nodavo.agent.ipc`; агент проверяет точный signing requirement UI для каждого полученного сообщения, а UI применяет взаимный точный requirement helper. Оболочка показывает bounded summaries статуса/focus и доверенных устройств, предоставляет emergency stop и ручное управление focus, реализует pairing с явным выбором capabilities и шестизначным кодом, а также post-pair changes и подтверждённый revocation. Раздел «Передачи» ставит в очередь до 32 явно выбранных файлов/папок и показывает только сокращённую ссылку. Широкая cross-platform и signed-runtime validation ещё не выполнена.

```bash
cargo run -p nodavo-agent --features development-unverified-local-ipc
swift run --package-path apps/macos \
  -Xswiftc -DNODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC Nodavo
```

Указанные feature и Swift compile flag выбирают явный unsafe same-user UDS bypass только для source-tree разработки. Он несовместим с distribution. Default-сборка агента без встроенного Team ID или зарегистрированного Mach service завершается fail-closed и не имеет UDS fallback.

Все разрешения при сопряжении по умолчанию выключены. Выбор привязывается к подтверждённому transcript сопряжения и подписанному доверию устройств. Переключатель после сопряжения меняется только после подтверждения агентом точной операции; разрешения отозванного устройства редактировать нельзя, его нужно сопрячь заново. Интерфейс не отправляет вычисленные пути файловой системы: принимаются только абсолютные пути, возвращённые явным выбором в локальном системном окне.

## Обновления

Settings предоставляет текущий не активирующий обновления slice. Пользователь может вручную запустить проверку или обновить статус, увидеть результат up-to-date, явно выбрать **Загрузить и подготовить** или **Отклонить** для точного предложения, следить за ограниченным прогрессом и возобновить приостановленную загрузку. Один polling loop с владельцем-generation использует отдельный client агента после согласия или во время загрузки, поэтому не блокирует pairing, transfers или emergency stop и прекращается в terminal или paused state. Интерфейс никогда не показывает URL манифеста, staging path или digest. Проверенный результат честно обозначается как staged; автоматическая установка недоступна в development build.

Агент по умолчанию не настроен. Только сборка, в которую явно встроены закреплённые HTTPS endpoint манифеста и публичный ключ Ed25519, может обращаться к update service; репозиторий не содержит ни production endpoint, ни приватного signing key, а live production check или signing ceremony не заявляются. Текущий путь macOS/Unix использует нативный платформенный TLS без redirects и decompression, проверяет ограниченный подписанный манифест и same-origin артефакт, привязывает согласие к его canonical offer UUID и возобновляемо пишет проверенное по digest содержимое в приватный capability-rooted staging root с межпроцессной арендой, квотами, retention и fsync.

Отсутствуют installer handoff, activation, перезапуск приложения или агента, health/rollback supervisor, защищённый production Keychain-журнал состояния обновлений и durable rollback floor. Staged content не выполняется. Для правильно подписанного release XPC проверяет точные Developer ID/Team ID identifiers и entitlements каждого сообщения UI-to-agent, а UI взаимно проверяет точный helper. Предыдущий claim socket audit-token отозван: он мог аутентифицировать post-exec task при чтении bytes, поставленных в очередь до exec. Development feature намеренно сохраняет только unsafe same-UID UDS. Live proof с production credentials Nodavo для signing, provisioning и notarization остаётся открытым release gate. Windows updater staging и UI integration также отсутствуют.

## Упаковка

Репозиторий может собрать universal-приложение `arm64` + `x86_64`, содержащее SwiftUI executable и пользовательский helper агента:

```bash
scripts/package-macos.sh --development --version 0.1.0 --build-number 1
```

Этот development-артефакт подписан ad-hoc, не нотариализован, не имеет provisioned-доступа к Keychain, не регистрирует встроенный LaunchAgent, компилирует unsafe same-user UDS bypass, рендерит Mach service выключенным и помечен как непригодный для распространения. Packaging подтверждает эти свойства. Это проверка структуры bundle, а не release.

Release-упаковка завершается с ошибкой, если вызывающая сторона явно не передала Developer ID identity, Team ID, отдельные provisioning profiles для `dev.nodavo.macos` и `dev.nodavo.agent`, а также профиль Keychain для `notarytool`:

```bash
APPLE_TEAM_ID=TEAMID1234 \
MACOS_SIGNING_IDENTITY="Developer ID Application: Example" \
MACOS_APP_PROVISIONING_PROFILE=/path/to/app.provisionprofile \
MACOS_AGENT_PROVISIONING_PROFILE=/path/to/agent.provisionprofile \
MACOS_NOTARY_PROFILE=nodavo-notary \
scripts/package-macos.sh --version 1.0.0 --build-number 1
```

Точную Keychain access group `${APPLE_TEAM_ID}.dev.nodavo.agent` должен разрешать только profile helper агента; UI entitlement и profile не получают эту group. Release-путь встраивает проверенный Team ID в Rust и signed app metadata, подтверждает signed-mutual XPC policy через bounded pre-sign self-check output, проверяет объявление точного Mach service в LaunchAgent и фактические universal UI/helper по точным взаимным Developer ID requirements, identifiers, entitlements, всем архитектурам, hardened runtime и отсутствию `get-task-allow`. Затем он регистрирует helper и требует notarization, stapling и Gatekeeper. Без Nodavo signing/notarization credentials эти release-шаги не выполнялись; один self-check не является signed runtime proof.

Интерфейс упакованного приложения показывает, включён ли helper, ожидает ли он разрешения в «Объектах входа», отсутствует или не смог зарегистрироваться. При ошибке регистрации Nodavo не запускает незарегистрированную копию и не создаёт привилегированную службу.
