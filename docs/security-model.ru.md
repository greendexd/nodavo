<!-- doc-id: security-model; lang: ru; translation-of: security-model.md; revision: 4 -->

# Модель безопасности

[English](security-model.md) · [Русский](security-model.ru.md)

Это целевой дизайн, а не утверждение о готовой реализации. Порядок сообщения об уязвимостях описан в [политике безопасности](../SECURITY.ru.md).

## Защищаемые активы

- События клавиатуры и указателя.
- Clipboard text, images и file lists.
- File contents, metadata, destination paths и transfer history.
- Device private keys, trust decisions и capability grants.
- Подлинность updates и rollback state.
- Локальный контроль пользователя, особенно немедленный disconnect.

## Источники угроз

- Злоумышленник в той же локальной сети.
- Поддельный discovery service или pairing MITM.
- Ранее доверенный, но скомпрометированный peer.
- Вредоносный локальный process, имитирующий UI или agent.
- Вредоносный clipboard/file sender, атакующий parsers, paths, quotas или auto-open.
- Скомпрометированная dependency, build runner, download host или update manifest.

Physical compromise paired-машины, kernel compromise, malicious firmware и compromised OS trust store выходят за защитную границу 1.0, но должны явно указываться в release documentation.

## Установление доверия

- mDNS discovery сообщает только расположение, но не identity.
- Явная pairing attempt сначала обменивается только ограниченными краткоживущими метаданными TLS-сертификата через неаутентифицированный TCP preflight по обнаруженному или введённому вручную адресу. Эти metadata публичны и никогда не создают trust.
- Каждая сторона закрепляет точный полученный ephemeral certificate до открытия первоначального QUIC-канала с TLS 1.3. Защищённые application data никогда не принимаются через preflight connection.
- Short authentication string связывает QUIC TLS exporter, роли, nonce обеих сторон, оба persistent identities, оба persistent certificates, grants и версию протокола и показывается на обоих устройствах.
- Пользователь подтверждает совпадение с обеих сторон.
- Устройства обмениваются persistent Ed25519 identities.
- Будущие подключения требуют mutual proof pinned identities.
- Silent trust-on-first-use запрещён.
- Reset identity, key replacement и revoked trust требуют нового pairing.

Private keys по возможности non-exportable и хранятся через macOS Keychain и Windows DPAPI/CNG. Trust records разделяют input, clipboard и file capabilities.

Текущий pre-alpha agent также содержит явно предназначенный только для разработки versioned file fallback для локальной работы с двумя процессами. На Unix каталоги ограничены режимом `0700`, файлы — `0600`, decoding ограничен, а replacement выполняется атомарно, но этот fallback не выполняет production-требование Keychain/DPAPI и не должен попадать в stable storage.

## Безопасность сессии

- QUIC с TLS 1.3; plaintext compatibility mode для application/session data отсутствует. TCP preflight первого контакта переносит только untrusted metadata временного сертификата и не может разрешить input, clipboard, files или persistent trust.
- Version/capability negotiation аутентифицирован.
- Replay-resistant session IDs и монотонная проверка sequences.
- Bounded messages, timeouts, rate limits и connection quotas.
- Единственный ownership lease управляет remote input routing.
- Emergency disconnect выполняется локально и не зависит от peer.
- Lock, sleep, timeout и disconnect освобождают keys/buttons и отзывают active lease.

## Захват и эмуляция ввода

- Native capture запускается без подавления. Suppression разрешается только при активной аутентифицированной и разрешённой focus lease, которая действительно маршрутизирует локальный ввод на peer.
- macOS требует выданное пользователем Accessibility trust. Windows остаётся внутри default input desktop интерактивного текущего пользователя; login, Session 0, UAC secure desktop и privileged unattended control отклоняются.
- Инъекция Nodavo использует приватную process tag, если платформа это поддерживает. Capture отклоняет эту tag и все события, отмеченные OS как injected, предотвращая synthetic feedback loop.
- Keyboard usages, modifiers, media keys, pointer buttons, normalized motion и line/precise scrolling проверяются до injection. Native codes не передаются напрямую через peer protocol.
- Injector отслеживает каждое принятое нажатие key/button. Emergency stop, потеря focus, lock, sleep, отключение tap/hook, timeout и transport failure синхронно запрашивают детерминированное освобождение и возврат local ownership до успешного acknowledgement.
- Отключённый или просроченный capture hook работает fail-closed: suppression прекращается, local ownership возвращается, а remote session не может незаметно продолжиться.
- Input payloads и pairing codes не попадают в logs, crash metadata или telemetry.

## Безопасность буфера

- Clipboard sync выключен до явного разрешения для peer.
- Revisions и content hashes предотвращают loops и stale overwrite.
- MIME allowlist сначала ограничен text, HTML, PNG/BMP и file lists.
- Size, decompression, allocation, parsing-time и concurrency limits применяются до decode.
- HTML передаётся как данные и не отображается в privileged Nodavo surface.
- Clipboard contents никогда не попадают в logs или telemetry.

## Безопасность файлов

- Получение файлов требует отдельного grant.
- Manifests ограничиваются до allocation.
- Имена нормализуются и отклоняются при traversal, reserved-device paths, dangerous ambiguity и invalid encoding.
- Symlinks, junctions, reparse points, sparse/special files отклоняются в 1.0 без отдельной спецификации и тестов.
- Данные пишутся в private staging, проверяются BLAKE3 и атомарно finalizes.
- Существующие файлы не перезаписываются молча.
- Полученные файлы не запускаются и не открываются автоматически.
- Per-peer quotas, cancellation, backpressure и rate limits ограничивают DoS.

## Локальный IPC

- macOS использует user-owned Unix domain socket с restrictive permissions и peer credential checks.
- Windows использует named pipe с ACL текущего пользователя и проверкой peer process context.
- UI requests проходят capability checks; UI не читает private network keys напрямую.

Текущий pre-alpha Unix socket аутентифицирует только credential владельца, а Windows pipe — тот же SID/session. Это блокирует cross-user и remote clients, но пока не отличает подписанный UI Nodavo от другого процесса, уже работающего от того же пользователя. Поэтому signed-client или launch-bound authentication остаётся stable-release gate; чувствительные локальные запросы должны быть узко ограничены, а release storage не должно открывать UI приватные сетевые ключи.

## Обновления и supply chain

Ниже перечислены обязательные требования к релизу, а не описание текущего pre-alpha репозитория:

- Артефакты релиза будут подписаны; сборки macOS пройдут notarization, а Windows будет использовать Authenticode.
- Манифесты обновлений будут подписаны отдельным офлайн-ключом релиза.
- Механизм обновления будет запрещать откат ниже зафиксированной безопасной версии без документированного восстановления пользователем.
- Релизы будут содержать контрольные суммы, SBOM, данные о происхождении сборки, lock-файлы и исходный коммит.
- Политика зависимостей, аудиты, CodeQL, фаззинг и поиск секретов будут работать постоянно до появления поддерживаемого релиза.

## Логи и телеметрия

Логи исключают keystrokes, clipboard/file contents, private filenames, device private keys, pairing codes и stable IP identifiers. Optional diagnostics должны быть просмотрены и явно экспортированы пользователем.

Telemetry и crash upload выключены по умолчанию. Будущая opt-in schema должна быть документирована, минимальна, отзывна и независима от updates.

## Обязательные security gates

- Тесты pairing MITM, key replacement, replay, revocation, malicious peer, parser fuzzing, path traversal, quota, update substitution и local IPC impersonation.
- Independent review до перевода public beta в stable.
- На stable gate нет открытых critical/high findings.
- Private vulnerability reporting и назначенный ответственный.
