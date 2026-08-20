<!-- doc-id: macos-app; lang: ru; translation-of: README.md; revision: 19 -->

# Nodavo для macOS

[English](README.md) · [Русский](README.ru.md)

Текущая SwiftUI-оболочка в строке меню подключается к пользовательскому Rust-агенту через signed XPC в release build. Упакованный LaunchAgent объявляет `dev.nodavo.agent.ipc`; агент проверяет точный signing requirement UI для каждого полученного сообщения, а UI применяет взаимный точный requirement helper. Оболочка показывает bounded summaries статуса/focus и доверенных устройств, предоставляет emergency stop и ручное управление focus, реализует pairing с явным выбором capabilities и шестизначным кодом, а также транзакционные post-pair changes разрешений и размещения каждого устройства с подтверждённым revocation. Экраны Overview и Settings раздельно показывают доступность агента, Accessibility trust, готовность локального ввода, локальные дисплеи и синхронизацию peer-топологии. Раздел «Расположение» показывает точную сохранённую настройку отключено/слева/справа/сверху/снизу для одного выбранного доверенного peer. Раздел «Передачи» ставит в очередь до 32 явно выбранных файлов/папок, показывает ограниченный прогресс по байтам и отмену со скрытыми идентификаторами передач, а также сообщает о фиксированной папке `Downloads/Nodavo` для полученных файлов. Широкая cross-platform и signed-runtime validation ещё не выполнена.

```bash
cargo run -p nodavo-agent --features development-unverified-local-ipc
swift run --package-path apps/macos \
  -Xswiftc -DNODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC Nodavo
```

Указанные feature и Swift compile flag выбирают явный unsafe same-user UDS bypass только для source-tree разработки. Он несовместим с distribution. Default-сборка агента без встроенного Team ID или зарегистрированного Mach service завершается fail-closed и не имеет UDS fallback.

Все разрешения при сопряжении по умолчанию выключены. Выбор привязывается к подтверждённому transcript сопряжения и подписанному доверию устройств. Переключатель после сопряжения меняется только после подтверждения агентом точной операции; разрешения отозванного устройства редактировать нельзя, его нужно сопрячь заново. Интерфейс не отправляет вычисленные пути файловой системы: принимаются только абсолютные пути, возвращённые явным выбором в локальном системном окне.

## Ручное управление фокусом

Ручное получение фокуса доступно только из точного авторитетного состояния локального фокуса при подключённом peer и готовых вводе, локальной топологии и peer-топологии. UI отправляет один `request_remote_focus` с фиксированной пятиисекундной арендой и отдельным 15-секундным deadline mutation. Локальный ответ или любой неоднозначный результат ожидает полное окно аренды и выполняет ровно одну свежую status-only сверку с deadline восемь секунд; mutation никогда не повторяется. Возврат аналогично отправляет один 15-секундный `release_focus`: точный локальный ответ завершает операцию сразу, а любой другой успешный или неоднозначный результат выполняет одну status-only сверку. Максимальный последовательный путь занимает 28 секунд в рамках 30-секундного контракта операции.

Детерминированной считается только точная строгая ошибка `focus_rejected`. Ошибки транспорта, timeout, неизвестный или повреждённый error, дублирующиеся ключи, неверная форма status и ошибки декодирования неоднозначны. Неудачная сверка блокирует оба действия с фокусом при неизвестном владельце до успешного явного авторитетного обновления статуса. Emergency stop остаётся доступным всегда, заменяет generation операции focus и не позволяет позднему ответу focus изменить отображение.

## Расположение

Раздел «Расположение» загружает один строгий ограниченный авторитетный список доверенных peers. Каждая запись обязана содержать ровно одно известное значение `placement`: `disabled`, `left`, `right`, `above` или `below`; дублирующиеся, отсутствующие, неизвестные, лишние или приватные поля отклоняются до отображения. UI выбирает одну сохранённую identity peer и отправляет только её точный peer ID и одно смысловое направление. Display IDs, session IDs, координаты или вычисленная топология не отправляются.

Выбор расположения не применяется оптимистично. Показанное значение меняется только после точного acknowledgement `peer_placement_changed` для того же peer и направления. Потерянный, повреждённый или несовпадающий ответ имеет неоднозначный результат, поэтому mutation никогда не повторяется: UI выполняет одну свежую сверку `list_trusted_peers` и целиком применяет этот авторитетный результат. Если сверка тоже не удалась, peer остаётся заблокирован до успешного явного обновления. Отозванные peers, а также peers с активной или неразрешённой mutation изменять нельзя. Для этого пути есть строгие decoder- и generation/race-тесты, но физический переход через край между подписанными пакетами macOS и Windows остаётся release gate.

## Передачи

Открытый раздел «Передачи» примерно раз в секунду получает строгий ограниченный authoritative snapshot агента, пока есть незавершённая работа или ожидается результат отмены. Polling и отмена используют отдельные clients агента с короткими deadline на каждую команду, а локальное добавление имеет собственный ограниченный запас для двух последовательных окон подготовки, поэтому прогресс файлов не занимает пути pairing, readiness, update или emergency stop. При скрытии раздела или полностью terminal snapshot polling прекращается. Дублирующиеся ключи JSON-объектов отклоняются в ограниченных сырых байтах до декодирования; ответы с отсутствующими, лишними, приватными, повреждёнными, слишком большими, дублирующимися или неканоническими полями также отклоняются. Отклонённый или более старый poll сохраняет последние строки как устаревшие, повторяется с ограниченной задержкой, пока остаётся работа, и не придумывает ошибку передачи. Усечённый snapshot сохраняет только ограниченные строки, необходимые для ожидаемого добавления или отмены; отсутствие разрешает операцию только в полном authoritative snapshot.

Интерфейс показывает текущие передачи и terminal-передачи, впервые замеченные в этом сеансе приложения. Это не долговременная история передач. Показываются направление, локализованная фаза, ограниченные счётчики и общий формат идентификатора `••••••••-12345678`, но не имена, абсолютные пути, данные второго устройства или приватные метаданные. Подписанная release-сборка использует фиксированную относительную метку назначения `Downloads/Nodavo`; development-unverified сборка остаётся в изолированной папке состояния приложения, и ни один режим не открывает полученные файлы автоматически. Завершённая пустая передача отображается как определённые 100%, включая значение универсального доступа. Отмена применяет только точный authoritative response для того же идентификатора передачи. Если ответ об отмене неоднозначен, право отмены остаётся закреплено за этим одним идентификатором до authoritative convergence; другая передача не может его заменить. Неоднозначный ответ о добавлении блокирует этот выбор и требует нового явного выбора перед следующей отправкой, предотвращая слепой дубль.

## Готовность и Accessibility

Readiness — строгий public snapshot из enum states, а не diagnostic dump. Оболочка отклоняет отсутствующие, неизвестные или повреждённые значения. За конечным deadline и коротким cache агент проверяет Accessibility trust, обнаружение локальных дисплеев и prerequisite injector без отправки events; вторая capture runtime не создаётся, ввод не suppress и не inject. Поэтому **Готов** означает текущую доступность локальных prerequisites, а не live capture proof. Подключённая session показывает peer topology как ready только после установки точной аутентифицированной remote topology и либо acknowledgement локальной revision, опубликованной для inbound control, либо намеренно unpublished local graph при отсутствии inbound input grant.

Platform source macOS теперь наблюдает CoreGraphics display reconfiguration через callback, который только помечает coalesced dirty generation. Capture и injection используют один стабильный ограниченный полный snapshot с непереиспользуемыми opaque identities. Агент закрывает routing admission, дренирует уже принятый input и освобождает старую focus lease. Когда local topology публикуется для inbound control, acknowledgement точной replacement revision обязателен до повторного состояния ready; outbound-only локальный graph намеренно остаётся unpublished и напрямую использует stable committed snapshot. Focused/inert tests покрывают callback interleavings, teardown, stale identities, deadlines и safety latching; реальный signed Mac с Windows peer ещё не прошёл физическую квалификацию hot-plug.

Кнопка **Разрешить универсальный доступ** запрашивает macOS от процесса агента, которому требуется permission, а затем выполняет свежую проверку. Возвращаемое prompt API значение не считается авторизацией, поэтому отмена prompt или отсутствие изменений в Системных настройках оставляет состояние **Требуется действие**. Это поведение source и focused prerequisite tests реализовано; полный TCC flow ещё не доказан на чистом Mac с signed, provisioned и notarized сборкой Nodavo.

## Обновления

Settings предоставляет текущий не активирующий обновления slice. Пользователь может вручную запустить проверку или обновить статус, увидеть результат up-to-date, явно выбрать **Загрузить и подготовить** или **Отклонить** для точного предложения, следить за ограниченным прогрессом и возобновить приостановленную загрузку. Один polling loop с владельцем-generation использует отдельный client агента после согласия или во время загрузки, поэтому не блокирует pairing, transfers или emergency stop и прекращается в terminal или paused state. Интерфейс никогда не показывает URL манифеста, staging path или digest. Проверенный результат честно обозначается как staged; автоматическая установка недоступна в development build.

Агент по умолчанию не настроен. Только сборка, в которую явно встроены закреплённые HTTPS endpoint манифеста и публичный ключ Ed25519, может обращаться к update service; репозиторий не содержит ни production endpoint, ни приватного signing key, а live production check или signing ceremony не заявляются. Текущий путь macOS/Unix использует нативный платформенный TLS без redirects и decompression, проверяет ограниченный подписанный манифест и same-origin артефакт, привязывает согласие к его canonical offer UUID и возобновляемо пишет проверенное по digest содержимое в приватный capability-rooted staging root с межпроцессной арендой, квотами, retention и fsync.

Platform source умеет проверять и удерживать точное ограниченное sealed universal app tree, включая подписи app и nested agent, entitlements, notarization/System Policy, owner/mode/ACL rules, hardlink rejection, immutable contents и mutation detection. Он намеренно не предоставляет swap, activation или rollback API: локальная проверка показала, что unprivileged cross-parent exchange завершается ошибкой после sealing обоих trees против same-user mutation. В репозитории всё ещё нет installer handoff, перезапуска приложения или агента, health/rollback supervisor, защищённого production Keychain-журнала обновлений и durable rollback floor. Staged content не выполняется. Live proof с production credentials Nodavo для signing, provisioning и notarization остаётся открытым release gate.

## Упаковка

Репозиторий может собрать universal-приложение `arm64` + `x86_64`, содержащее SwiftUI executable и пользовательский helper агента. Тот же development run создаёт явно не notarized universal update ZIP и точные metadata size/SHA-256 для validation tests; текущий продукт не умеет устанавливать ни один из этих artifacts:

```bash
scripts/package-macos.sh --development --version 0.1.0 --build-number 1
```

Этот development-артефакт подписан ad-hoc, не нотариализован, не имеет provisioned-доступа к Keychain, не регистрирует встроенный LaunchAgent, компилирует unsafe same-user UDS bypass, рендерит Mach service выключенным и помечен как непригодный для распространения. Packaging подтверждает эти свойства. Это не release.

Локальная и GitHub development-упаковка также запускают точный встроенный helper с изолированным state, loopback networking, выключенным mDNS и изолированным UDS, после чего вызывают точный packaged SwiftUI executable с development-only entry point `--passive-smoke`. Этот entry point ровно по одному разу вызывает каждый строгий read-only production client method: `status()`, `focusStatus()` (второй ограниченный `get_status`), `listTrustedPeers()` и `listTransfers()`. Он выводит один ограниченный результат без пользовательского контента. Release builds не содержат и не принимают этот entry point. Это доказывает, что packaged development UI executable может общаться со своим встроенным helper по unsafe development UDS contract; проверка не охватывает XPC, Developer ID signing, notarization, TCC, capture или injection ввода, pairing, реальный peer, строки placement, публикацию файлов и физическое оборудование.

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
