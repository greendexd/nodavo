<!-- doc-id: security-model; lang: ru; translation-of: security-model.md; revision: 2 -->

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
- Initial pairing использует ephemeral encrypted channel и short authentication string на обоих устройствах.
- Пользователь подтверждает совпадение с обеих сторон.
- Устройства обмениваются persistent Ed25519 identities.
- Будущие подключения требуют mutual proof pinned identities.
- Silent trust-on-first-use запрещён.
- Reset identity, key replacement и revoked trust требуют нового pairing.

Private keys по возможности non-exportable и хранятся через macOS Keychain и Windows DPAPI/CNG. Trust records разделяют input, clipboard и file capabilities.

## Безопасность сессии

- QUIC с TLS 1.3; plaintext compatibility mode отсутствует.
- Version/capability negotiation аутентифицирован.
- Replay-resistant session IDs и монотонная проверка sequences.
- Bounded messages, timeouts, rate limits и connection quotas.
- Единственный ownership lease управляет remote input routing.
- Emergency disconnect выполняется локально и не зависит от peer.
- Lock, sleep, timeout и disconnect освобождают keys/buttons и отзывают active lease.

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
