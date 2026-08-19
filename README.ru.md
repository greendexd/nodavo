<!-- doc-id: readme; lang: ru; translation-of: README.md; revision: 20 -->

<div align="center">
  <img src="assets/logo.svg" width="132" alt="Логотип Nodavo">
  <h1>Nodavo</h1>
  <p><strong>Одно движение. Все компьютеры.</strong></p>
  <p>Проект безопасного локального программного KVM с открытым исходным кодом для macOS и Windows.</p>

  <p>
    <a href="README.md">English</a> ·
    <a href="README.ru.md">Русский</a>
  </p>

  <p>
    <img alt="Статус: активная pre-alpha" src="https://img.shields.io/badge/status-active%20pre--alpha-6d5efc">
    <a href="LICENSE"><img alt="Лицензия Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-22c55e"></a>
    <a href="SECURITY.ru.md"><img alt="Политика безопасности" src="https://img.shields.io/badge/security-policy-0ea5e9"></a>
  </p>
</div>

> [!IMPORTANT]
> Nodavo находится в активной разработке на стадии pre-alpha. Поддерживаемой межкомпьютерной сборки и публичного релиза пока нет. Интегрированный Rust-агент, оболочка macOS и WinUI 3 x64 компилируются в CI, а для macOS и Windows есть явно помеченный development packaging, но реальная квалификация Mac ↔ PC, release signing, чистая установка и полная матрица release tests ещё не готовы.

## Видение

Nodavo создаётся, чтобы Mac и Windows-компьютер ощущались как одно локальное рабочее пространство. Курсор переходит через край экрана, клавиатура продолжает работать на другом компьютере, а содержимое буфера и файлы передаются только с явного разрешения — без облачной учётной записи и сервера-посредника.

Реализация будет написана с нуля. Существующие программные KVM используются только как ориентиры поведения и совместимости в рамках [политики чистой реализации](docs/clean-room-policy.ru.md).

## Принципы продукта

- **Локальная работа:** прямое соединение между устройствами в доверенной локальной сети.
- **Безопасность по умолчанию:** взаимная аутентификация и шифрование; незашифрованного режима нет.
- **Равноправные устройства:** любой компьютер может стать источником ввода.
- **Явная передача данных:** отдельные разрешения для ввода, буфера и файлов.
- **Нативный интерфейс:** полноценные сценарии разрешений, строки меню, системного трея и обновлений для macOS и Windows.
- **Честный открытый код:** документированный протокол, публичная модель угроз и воспроизводимые доказательства качества релизов.

## Текущее состояние реализации

| Возможность | Цель для 1.0 | Текущий статус pre-alpha |
| --- | --- | --- |
| Общая мышь и клавиатура | macOS ↔ Windows в обе стороны | Оба native bridge подключены к аутентифицированным equal-peer sessions. Reliable pointer entry подтверждается до suppression; relative motion, HID/media keys, buttons, scroll, focus leases, forced release и lifecycle recovery проходят virtual/native-inert проверки. Реального hardware-доказательства Mac ↔ PC пока нет |
| Переход через край экрана | Разный масштаб DPI и несколько мониторов | Подключены authenticated session-scoped topology, mixed-DPI transforms, явные edge routes, debounce/hysteresis, reliable entry и relative deltas. macOS и Windows теперь обнаруживают изменения дисплеев, публикуют только стабильные ограниченные полные snapshots со свежими opaque identities, освобождают активную lease и требуют точный topology acknowledgement до возобновления focus. Всё ещё нет layout editor и физической cross-platform проверки hot-plug/multi-monitor |
| Буфер обмена | UTF-8 текст, HTML, PNG/BMP | Надёжный peer channel применяет независимые grants, bounded streaming, BLAKE3, loop prevention и cleanup. macOS поддерживает text/HTML/PNG/clear; Windows — text/HTML/PNG/clear и строгий subset BMP. Для Windows есть только compile/parser evidence |
| Файлы и папки | Копирование, очередь, возобновление, проверка целостности | Authenticated manifest/data channels, ограниченные background workers, явные native pickers, exact-offset resume в рамках процесса, peer-scoped cleanup, BLAKE3, private no-follow staging и no-overwrite publication проходят focused/virtual checks. Content-free process-local registry публикует ограниченные progress и targeted cancellation через строгий двуязычный native UI без file names, paths, hashes, peer identities и wire IDs. Нет реальной межкомпьютерной проверки, user-selected receive destinations, durable history/ownership между перезапусками процесса и Windows directory durability при отключении питания |
| Обнаружение | mDNS и запасной вариант с ручным IP | Агент разрешает ограниченные записи mDNS и принимает ручные адреса; автоматического списка устройств в интерфейсе пока нет |
| Сопряжение | Подтверждаемый пользователем короткий код и закреплённые идентификаторы устройств | Pairing-time grants, signed trust, pinned mutual TLS reconnect, directional grant epochs, транзакционные post-pair changes, bounded trusted-device list и revocation работают в focused tests. Этот UX есть в обеих native shells. Остаются signed/provisioned Keychain success и реальная Windows runtime validation |
| Транспорт | QUIC с TLS 1.3 | Через одно mutually authenticated соединение в focused/virtual tests работают pairing, pinned reconnect, negotiation, topology, focus, reliable input, acknowledged entry, datagrams/fallback, clipboard и bounded file channels. Нет реальной квалификации двух устройств с loss/reorder/performance |
| Обновления | Подписанные проверки, явное согласие, безопасная установка и откат | В агенте есть выключенный по умолчанию, не активирующий обновления slice с проверкой подписанного манифеста, согласием на точный offer, проверяемым staging macOS и двуязычным status macOS. Staged session с отдельным согласием на установку и перезапуск теперь можно однократно преобразовать в ограниченный encode-only handoff supervisor, сохраняющий точный подписанный envelope; admission reducer, decoding и actions исключены из обычной сборки agent. В исходниках также есть проверка sealed macOS bundle и приватный Windows staging/read-only Appx inspection. Production endpoint и signing key не использовались; отсутствуют supervisor executable и IPC, защищённое состояние обновлений, установка, активация, process wiring для restart/health/rollback, Windows UI и физическая квалификация обновления |
| Платформы | macOS 13+ и Windows 10 22H2/11, x64 и ARM64 | SwiftUI и WinUI 3 x64 компилируются в CI; Rust проверяется для macOS arm64/x64 и Windows x64. Обе оболочки строго декодируют не содержащую контента готовность агента, локальных input prerequisites, локальных дисплеев и синхронизации аутентифицированной peer-топологии; macOS может попросить агент показать Accessibility prompt и затем повторно проверяет фактический trust. Readiness probe никогда не создаёт вторую native capture registration, поэтому `ready` честно означает готовность prerequisites, а не доказанный live capture. Правильно подписанные macOS release builds используют взаимные per-message XPC code requirements через фиксированный LaunchAgent Mach service без UDS fallback; только development packaging компилирует явный unsafe same-UID UDS bypass. Windows source взаимно связывает каждое one-request named-pipe connection с точным packaged UI и точным signed agent image внутри installed root этого UI package, а также предоставляет fixed launch action и opt-in StartupTask. Это отклоняет независимую подмену endpoint, но не создаёт отдельный Windows principal против invasive access к авторизованному process. Reproducibly собирается universal development app/DMG macOS, а также существует fail-closed Windows x64+ARM64 development MSIXBundle workflow. Signed TCC/XPC proof, installed Windows readiness/lifecycle/auth execution, production signing, ARM64 runtime и clean installer matrices не доказаны |

Трансляция экрана, сервер-посредник в интернете, мобильные клиенты, Linux и управление Windows Secure Desktop не входят в первоначальный объём 1.0.

### Что уже существует

- Rust workspace с ограниченными компонентами протокола, идентификаторов, транспорта, сессии, обнаружения, буфера, передачи файлов, проверки обновлений и локального IPC.
- Пользовательский Rust-агент с приватным локальным IPC, ручным/mDNS-сопряжением, явными grants, signed trust, pinned reconnect, revocation, negotiated peer sessions, authenticated topology, relative input, clipboard sync, deterministic safety recovery и emergency stop. macOS по умолчанию использует Keychain; файловое хранилище включается только явным insecure-development flag.
- Двуязычная SwiftUI-оболочка macOS в строке меню, подключённая к агенту через release signed XPC (или явный unsafe development UDS), с pairing, управлением trusted devices/grants, подтверждённым revocation, явным выбором файлов/папок, ограниченными progress/cancellation без имён файлов и карточкой готовности. Действие разрешения запрашивает Accessibility от identity агента и применяет только свежий probe; показ системного prompt никогда не считается выдачей доступа.
- Двуязычная WinUI 3-оболочка с ограниченными статусом, раздельными сигналами готовности, emergency stop, pairing, управлением trusted devices/grants, подтверждённым revocation, явным выбором файлов/папок, ограниченными progress/cancellation без имён файлов, fixed package-root agent launch action и opt-in запуском при входе. До любой команды shell проверяет собственный package root и точный signed agent process/image внутри него; agent взаимно проверяет настроенный packaged UI и закрывает connection после одного response. Неоднозначный результат grant/transfer запускает reconciliation или блокирует retry, а не изображает rollback. GitHub Actions компилирует Release x64; installed lifecycle, readiness, transfer и mutual-authentication paths интерактивно в Windows пока не запускались.
- Оригинальные macOS/Windows input и clipboard runtimes, подключённые к agent, с default-off suppression, injected-event rejection, bounded relative motion, транзакционным display hot-plug refresh, lifecycle recovery, deterministic release и content-redacted failures. Hot-plug callbacks только сигнализируют об изменении; до возобновления focus выполняются stable full snapshot, callback/admission barriers, drain очереди, освобождение lease и точный peer acknowledgement.
- Authenticated bounded file channels, process worker с четырьмя reservations, cooperative scan cancellation, peer-scoped cleanup, private capability-rooted receiver staging и outbound filesystem source с exact hashes, mutation detection, no-follow handles, Windows birth-time DACL и консервативной no-overwrite publication. Отдельный short-held registry выдаёт process-local public IDs, ограничивает live/recent rows, продвигает outbound bytes только после reliable send, inbound bytes — только после durable staging write, и линеаризует targeted cancellation с finalization.
- Universal development app/DMG pipeline для macOS и fail-closed release path Developer ID/provisioning/notarization. Release credentials недоступны, поэтому собран только явно непригодный для распространения development artifact.
- Не активирующий обновления slice в агенте и Settings macOS, а также source-only foundations для отдельно подписанного supervisor. Только `ReadyToInstall` session с отдельным согласием на установку и перезапуск можно однократно преобразовать в ограниченный handoff; default agent умеет кодировать этот request, но не может его декодировать или линковать reducer admission/actions. Handoff сохраняет точный исходный проверенный signed envelope для authoritative re-verification в supervisor, а schema 3 supervision journal связывает его ненулевой request ID. Package gates отклоняют non-default feature `supervisor-host` в обычных agent artifacts; эта build boundary не заменяет mutual process authentication, protected storage и exclusive locking. macOS умеет проверять и удерживать точное sealed universal app tree, но намеренно не предоставляет swap API; Windows добавляет private fixed-volume staging и bounded read-only Appx inspection. Package pipeline создаёт sealed universal update ZIP и точные metadata hash/size; фактически собран только явно development-labeled вариант. Ничто здесь не устанавливает и не выполняет staged content.

### Чего не хватает до рабочей сборки

- Реальная интерактивная Mac ↔ Windows проверка input, relative edge crossing, DPI, lifecycle, clipboard, DPAPI, named-pipe/WinUI flow и recovery; также отсутствует Windows ARM64 evidence.
- Реальная проверка peer file transfer, выбираемые пользователем receive destinations, durable progress/history и peer/outbound ownership между перезапусками агента, display layout editor и физическая квалификация hot-plug, onboarding, экспортируемые diagnostics, а также отдельно упакованный updater supervisor с mutually authenticated IPC, protected journals, platform activation, process adapters для restart/health/rollback, Windows UI и физической power-loss квалификацией.
- Signed/provisioned запуск macOS, подтверждающий стабильность Keychain/TCC, а также Developer ID/notarization и Authenticode/MSIX/MSI credentials с clean install/upgrade/uninstall matrices.
- Полные security, fuzz, stress, compatibility, accessibility, long-running beta, external-review, SBOM/provenance и real-hardware gates версии 1.0.

## Направление архитектуры

```mermaid
flowchart LR
    UI1["SwiftUI-приложение<br/>macOS"] -->|"защищённый локальный IPC"| A1["Rust session agent"]
    UI2["WinUI 3-приложение<br/>Windows"] -->|"защищённый локальный IPC"| A2["Rust session agent"]
    A1 <-->|"QUIC / TLS 1.3<br/>только LAN"| A2
    A1 --> M["CGEventTap · NSPasteboard"]
    A2 --> W["Raw Input · SendInput · Win32 Clipboard"]
```

Частые движения указателя пойдут через датаграммы QUIC. Клавиши, кнопки, управляющее состояние, буфер и файлы будут передаваться через ограниченные надёжные потоки. Доверие создаётся подтверждаемым пользователем сопряжением и постоянными взаимно проверяемыми идентификаторами устройств.

Подробности находятся в документах [«Архитектура»](docs/architecture.ru.md) и [«Модель безопасности»](docs/security-model.ru.md).

## План разработки

Разработка разделена на этапы с проверяемыми условиями выхода. Основа M0/M1 уже реализуется, но ни один этап не считается завершённым до прохождения его выходных критериев:

1. **M0 — Реализуемость:** доказать захват и эмуляцию ввода, подавление синтетических событий, QUIC, API буфера и возможность переноса файлов Finder ↔ Explorer.
2. **M1 — Основа:** рабочее пространство, нативные оболочки, локальный IPC, идентификаторы, обнаружение, сопряжение и переподключение.
3. **M2 — Ввод:** надёжное одностороннее управление Mac → Windows и Windows → Mac.
4. **M3 — Двусторонний KVM:** равноправные устройства, аренда фокуса, несколько мониторов, разный DPI, безопасные сон и переподключение.
5. **M4 — Буфер:** текст, HTML, изображения, лимиты и защита от циклов.
6. **M5 — Файлы:** файлы и папки, очередь, возобновление, промежуточное хранение, целостность и защита путей.
7. **M6 — Интерфейс продукта:** первоначальная настройка, разрешения, диагностика, доверенные устройства, обновления и чистое удаление.
8. **M7 — Публичная бета:** подписанные установщики, 100 реальных пар устройств, 30 дней внутреннего использования и внешний аудит безопасности.
9. **M8 — Стабильная 1.0:** стабильный протокол, подтверждённая матрица оборудования, SBOM, происхождение сборок, откат и процесс реакции на уязвимости.

Смотрите подробный [план продукта](docs/product-plan.ru.md) и публичную [дорожную карту](docs/roadmap.ru.md).

## Документация

| English | Русский |
| --- | --- |
| [Documentation index](docs/README.md) | [Раздел документации](docs/README.ru.md) |
| [Product plan](docs/product-plan.md) | [План продукта](docs/product-plan.ru.md) |
| [Architecture](docs/architecture.md) | [Архитектура](docs/architecture.ru.md) |
| [Peer protocol](docs/protocol.md) | [Протокол между устройствами](docs/protocol.ru.md) |
| [Roadmap](docs/roadmap.md) | [Дорожная карта](docs/roadmap.ru.md) |
| [Security model](docs/security-model.md) | [Модель безопасности](docs/security-model.ru.md) |
| [Privacy](docs/privacy.md) | [Конфиденциальность](docs/privacy.ru.md) |
| [Clean-room policy](docs/clean-room-policy.md) | [Политика чистой реализации](docs/clean-room-policy.ru.md) |
| [Technical glossary](docs/glossary.md) | [Технический глоссарий](docs/glossary.ru.md) |

## Участие в разработке

Сейчас особенно полезны целевые реализации или рецензии существующего этапа, предположений безопасности, платформенных ограничений и критериев реализуемости. Сначала согласуйте значительную работу в issue, сохраняйте задокументированные границы доверия и не называйте компилируемый компонент выпущенной функцией.

Прочитайте [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md), соблюдайте [Кодекс поведения](CODE_OF_CONDUCT.ru.md) и используйте двуязычные формы issues.

## Лицензия

Nodavo распространяется по [Apache License 2.0](LICENSE). Вместо CLA с передачей авторских прав проект использует подтверждение Developer Certificate of Origin.
