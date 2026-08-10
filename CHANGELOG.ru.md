<!-- doc-id: changelog; lang: ru; translation-of: CHANGELOG.md; revision: 9 -->

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

### Пока недоступно

- Рабочее или выпущенное приложение macOS ↔ Windows. Input/focus/clipboard объединены в pre-alpha agent, но реальная квалификация на двух машинах и file peer-channel/UI integration ещё отсутствуют.
- Подтверждённая runtime-работа Windows agent/WinUI; также отсутствуют release signing, updater installation, trusted-device/grant UX, hot-plug layout UX, file orchestration и Windows ARM64 validation.
- Полные матрицы безопасности, фаззинга, нагрузки, совместимости, обновлений, доступности и реальных устройств; они остаются условиями релиза функционально завершённой версии 1.0.
