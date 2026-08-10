<!-- doc-id: changelog; lang: ru; translation-of: CHANGELOG.md; revision: 11 -->

# История изменений

Все значимые изменения Nodavo будут фиксироваться здесь. Формат следует принципам Keep a Changelog; после первой публичной сборки проект планирует использовать Semantic Versioning.

## [Не выпущено]

### Добавлено

- Первоначальное двуязычное оформление репозитория и документация продукта.
- План продукта, архитектура, дорожная карта, модель безопасности, конфиденциальность и политика чистой реализации.
- Документация pre-alpha протокола между устройствами с разделением каналов, ограниченным каноническим CBOR, текущими тегами, правилами актуальности и ограничениями совместимости.
- Шаблоны участия в разработке и создания issues.
- Основа Rust workspace для ограниченных сообщений протокола, семантического ввода, безопасности сессии, идентификаторов и сопряжения, обнаружения, транспорта QUIC/TLS, синхронизации буфера, проверки передачи файлов, локального IPC, проверки подписанных обновлений и детерминированных виртуальных адаптеров.
- Пользовательский Rust-агент с ограниченным IPC через приватный сокет, явными capability-разрешениями при сопряжении, первичным ephemeral-сопряжением, взаимным подтверждением короткого кода, сохранением подписанного доверия, закреплённым взаимным TLS-переподключением после перезапуска, отзывом устройства, статусом, самопроверкой, завершением и аварийным отключением.
- Аутентифицированный symmetric peer-session runtime с negotiation протокола/capabilities, отдельными sequence lanes ввода, двусторонними focus leases в том же соединении, datagram/pointer fallback, bounded command ingress и safety recovery до acknowledgement.
- Двуязычная SwiftUI-оболочка macOS в строке меню для статуса агента, аварийного отключения, ручного/ожидающего сопряжения, явного выбора отдельных разрешений и подтверждения короткого кода.
- Ручные focus controls macOS и подключённый native capture/injection bridge с default-off suppression, bounded coalescing, невыбрасываемыми key/button events, priority lifecycle recovery и synchronous forced-release acknowledgement.
- Owned input runtimes macOS/Windows с synthetic-event suppression, переводом HID/media/buttons/motion/scroll, lifecycle recovery и deterministic forced release, а также input/clipboard feasibility programs. Windows runtime ещё не подключён к агенту и не проверен runtime на Windows.
- Windows-границы ввода, дисплеев, безопасности сессии, буфера и current-user DPAPI, а также API защищённого same-user named pipe; Rust-агент ещё не запускает этот pipe.
- Исходники двуязычной WinUI 3-оболочки с ограниченными клиентами статуса, аварийного отключения, ручного/ожидающего сопряжения, явного выбора отдельных разрешений и подтверждения кода. Они прошли только проверку XML/исходников, но не компиляцию или запуск на Windows.
- Исходники запуска Windows-агента с сервером named pipe, проверяющим того же пользователя/сеанс, и защищённым DPAPI-хранением идентификаторов/доверия; они cross-check для Windows x64, но требуют runtime-проверки на Windows.
- Ограниченное FIFO-планирование transfers с детерминированными эффектами pause/resume/cancel, а также приватный файловый staging с durable-журналом, возобновлением после перезапуска с точного offset, обрезанием torn tail, BLAKE3, удалением сохранённого состояния и завершением без перезаписи.
- Компиляционные проверки репозитория для двуязычной документации, форматирования и сборки Rust на macOS/Windows, x64-проекта WinUI 3 и Swift-пакетов macOS.
- Authenticated session-scoped display topology, mixed-DPI edge policy, relative pointer deltas и reliable pointer-entry acknowledgement gate до suppression.
- Сквозные bounded clipboard channels: text/HTML/PNG/clear в macOS и Windows, а также строгий canonical BMP/DIB subset в Windows.
- Production-default macOS Keychain storage с явным insecure-development file fallback, universal development app/DMG и fail-closed packaging path Developer ID/notarization.
- Capability-rooted outbound file scanning/streaming с no-follow traversal, deterministic manifests, BLAKE3, mutation detection, resume evidence и безопасным receiver staging.
- Directional persistent grant epochs, bounded trusted-device listing, транзакционные post-pair capability updates, peer-scoped cleanup при revocation и native trusted-device/file-selection UX для macOS и Windows.
- Authenticated bounded file channels с background workers, cooperative scan cancellation, same-process resume после потери связи, completion ordering, process-wide staging leases, Windows owner-only DACL при создании и консервативной no-overwrite publication.
- Fail-closed Windows x64+ARM64 development MSIXBundle pipeline и core state machine подписанных updates с bounded staging, consent, rollback floor и restart/health contracts.
- Выключенный по умолчанию, не активирующий обновления slice с закреплёнными при компиляции HTTPS endpoint манифеста и публичным ключом Ed25519, нативным платформенным TLS без redirects и decompression, проверкой подписи манифеста и same-origin артефакта, согласием на точный UUID предложения и возобновляемым private capability-root staging с проверкой digest, межпроцессной арендой, квотами, retention и fsync. Раздел Settings macOS умеет проверять, обновлять/опрашивать прогресс, показывать up-to-date, принимать или отклонять точное предложение, возобновлять приостановленную загрузку и сообщать о проверенном staging на английском и русском, не раскрывая URL, путь или hash.

### Пока недоступно

- Рабочее или выпущенное приложение macOS ↔ Windows. Input/focus/clipboard/files объединены в pre-alpha agent и есть исходники native UX, но реальная квалификация на двух машинах ещё отсутствует.
- Подтверждённая runtime-работа Windows agent/WinUI; также отсутствуют release signing, endpoint обновлений/private signing key, защищённое сохранение update state и rollback floor, updater installation/activation/restart/rollback supervision, Windows updater staging/UI, hot-plug layout UX, подробный transfer progress/destinations, durable restart ownership journals и Windows ARM64 execution.
- Полные матрицы безопасности, фаззинга, нагрузки, совместимости, обновлений, доступности и реальных устройств; они остаются условиями релиза функционально завершённой версии 1.0.
