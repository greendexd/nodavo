<!-- doc-id: adr-0004-macos-signed-local-ipc; lang: ru; translation-of: 0004-macos-signed-local-ipc.md; revision: 2 -->

# ADR-0004: Подписанный XPC с проверкой каждого сообщения для локального IPC macOS

[English](0004-macos-signed-local-ipc.md) · [Русский](0004-macos-signed-local-ipc.ru.md)

- Статус: принято для pre-alpha реализации macOS; security claim ревизии 1 отозван
- Дата: 2026-08-10

## Контекст

Ревизия 1 аутентифицировала peer Unix domain socket: читала `LOCAL_PEERTOKEN`, разрешала текущий `audit_token_t` в dynamic `SecCode` и повторно проверяла token вокруг чтения frame. Этот дизайн не является надёжной границей происхождения сообщений. Same-user process может подключиться и поставить в очередь полную команду без подписи, выполнить exec правильно подписанного UI Nodavo в том же процессе и позволить агенту аутентифицировать post-exec task до чтения pre-exec bytes. `LOCAL_PEERTOKEN` описывает текущую task, связанную с последним PID socket, но не маркирует уже поставленные в очередь bytes. Дополнительные token gates, `FD_CLOEXEC` или конечный challenge не исправляют это несоответствие.

Поэтому release IPC требуется OS primitive, который проверяет code identity каждого доставленного сообщения, а не snapshot, выведенный из byte stream. Реализация должна оставаться bounded, завершаться fail-closed, не использовать paths/PID/tokens как authority и не логировать payload либо identity процесса.

## Решение

Упакованный per-user LaunchAgent агента объявляет фиксированный Mach service `dev.nodavo.agent.ipc`. Release-сборки используют только XPC: release fallback на UDS отсутствует, `NODAVO_IPC_PATH` не читается.

До activation агент устанавливает `xpc_connection_set_peer_code_signing_requirement` на listener Mach service и повторно на каждое принятое peer connection. Контракт локального SDK утверждает, что проверяются все сообщения, полученные настроенным connection. Фиксированный requirement UI требует:

- Apple generic anchor, leaf Developer ID Application и intermediate Developer ID;
- точный identifier `dev.nodavo.macos` и десятисимвольный Team ID времени компиляции;
- точные entitlements `com.apple.application-identifier` и `com.apple.developer.team-identifier`;
- отсутствие `com.apple.security.get-task-allow`.

Release UI на Swift до activation своего XPC connection устанавливает взаимный requirement для точного helper `dev.nodavo.agent`, Team ID, цепочки Developer ID, application/team entitlements и отсутствующего `get-task-allow`. Таким образом, реализованный release path проверяет UI перед агентом и агент перед UI для каждого сообщения. Live mutual qualification остаётся недоказанной до запуска реальной сборки с Nodavo Developer ID, provisioning и notarization.

Каждый XPC request и reply — dictionary ровно с одним data-значением `frame`, содержащим существующий JSON contract команд/событий. Data ограничены 64 КиБ; неизвестные поля команд отклоняются. Native admission допускает максимум 16 peers, четыре outstanding requests на peer и 32 глобально. Rust ставит в очередь максимум 32 requests и прерывает dispatch через 350 секунд; native и Swift reply capabilities истекают через 360 секунд, то есть позже пятиминутной bounded-операции dispatcher. Reply capabilities одноразовые, отменяются при abandonment и не раскрывают authentication token в Rust или Swift. Shutdown отменяет listener и outstanding tasks.

Native XPC, ARC и dispatch операции остаются внутри существующего Objective-C/Rust FFI module. Safe listener намеренно не реализует `Send` и `Sync`, callbacks не могут выполнить unwind через FFI, а ownership request/reply передаётся ровно один раз. Safe adapter агента направляет декодированные XPC-команды в тот же exhaustive authority dispatcher, который используют остальные platform transports.

Non-default compile-time Cargo feature `development-unverified-local-ipc` сохраняет приватный UDS только для source-tree разработки и development packaging. Он требует тот же effective UID, устанавливает `FD_CLOEXEC` в Swift, помечен как unsafe и non-distributable, не объявляет release Mach service и никогда не выбирается release packaging.

Release packaging встраивает проверенный Team ID в Rust и подписанные app metadata, подтверждает XPC signed-mutual policy ограниченным pre-sign `--self-check`, регистрирует Mach service и проверяет фактические requirements и entitlements подписанных universal UI/helper, hardened runtime, architectures, разделение Keychain, notarization и Gatekeeper. Self-check служит evidence политики, а не proof подписанного runtime.

## Влияние на безопасность и приватность

Для правильно подписанного release per-message enforcement XPC предотвращает laundering queued-byte/exec, который сделал ревизию 1 недействительной, и отклоняет независимые same-user, ad-hoc, wrong-team, wrong-identifier и `get-task-allow` clients. Он не защищает process после arbitrary code injection/compromise, скомпрометированную signing identity, компрометацию kernel/XPC/Security.framework или development bypass build.

Payloads, audit tokens, PID, process paths, private filenames, signing subjects и Team IDs не записываются в runtime logs. Ошибки остаются общими. Старый audit-token reducer сохранён только как протестированное evidence для анализа unsafe development/socket; он не является release message provenance.

## Отклонённые варианты

- UDS с повторными audit-token checks: аутентифицирует текущее состояние task, а не sender уже поставленных в очередь bytes.
- UDS с конечным challenge: process может поставить protocol bytes в очередь или передать их через exec boundary; stream всё равно не получает per-byte code provenance.
- Только same-UID credentials: каждый process пользователя мог бы отправлять authority-bearing команды.
- Lookup PID или executable path: содержит гонки exec/PID reuse и доверяет изменяемому path state.
- Shared secret UI: расширяет распространение секрета, а его извлечение другим same-user process становится новой границей.
- Runtime bypass variables: изменение environment могло бы незаметно ослабить distributable build.

## Происхождение решения

Решение использует независимо написанные требования репозитория и локальные официальные контракты Apple SDK/XPC, Security.framework, launchd и публичных XNU interfaces. Ключевая корректировка следует из документированного различия между текущим состоянием peer socket и XPC code requirement для всех получаемых сообщений. Исходный код или assets других KVM-реализаций не изучались и не использовались.
