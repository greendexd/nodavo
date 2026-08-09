<!-- doc-id: product-plan; lang: ru; translation-of: product-plan.md; revision: 2 -->

# План продукта

[English](product-plan.md) · [Русский](product-plan.ru.md)

## Определение продукта

Nodavo — clean-room, local-first software KVM для людей, которые используют Mac и Windows PC за одним столом. Цель — двустороннее управление клавиатурой и указателем, общий буфер и явная передача файлов через взаимно аутентифицированное локальное соединение.

Продукт не является remote desktop: у каждого компьютера остаётся собственный дисплей и собственные приложения.

## Основные пользователи

1. Разработчики, проверяющие ПО на macOS и Windows.
2. Создатели контента и стримеры с отдельными производственными и capture-машинами.
3. Пользователи домашнего офиса с рабочим Mac и Windows workstation.
4. Лаборатории и небольшие команды, которым нужна локальная работа без облачных аккаунтов.

## Обещание пользователю

Новый пользователь должен установить Nodavo на две поддерживаемые машины, выдать понятные разрешения, подтвердить совпадающий pairing-код, расположить дисплеи и начать переходить между компьютерами менее чем за три минуты — без аккаунта и передачи input-данных в интернет.

## Цели 1.0

- macOS 13+ и Windows 10 22H2/11 на x64 и ARM64.
- Равноправные peers: физическая мышь и клавиатура каждой стороны могут управлять другой машиной.
- Указатель, кнопки, колесо, распространённые раскладки, modifiers, media keys и mixed-DPI дисплеи.
- Буфер с текстом, HTML и распространёнными изображениями, лимитами и защитой от циклов.
- Явная передача файлов/папок, очередь, отмена, resume, проверка целостности и безопасная политика назначения.
- mDNS discovery и ручной IP fallback.
- QUIC/TLS 1.3, подтверждаемый pairing, постоянные взаимно проверяемые identities и отзыв доверия.
- Нативные permission, tray/menu-bar, layout, diagnostics, trusted-device и update сценарии.
- Подписанные установщики, SBOM, checksums, provenance и процесс реакции на уязвимости.

## Non-goals 1.0

- Трансляция видео, экрана, аудио или приложений.
- Работа через публичный интернет или hosted relay.
- Linux, mobile, tablet и browser-клиенты.
- Windows login, UAC secure desktop и unattended privileged control.
- Автоматическое открытие полученных файлов.
- Более двух активных peers в одной control-сессии.
- Обязательная телеметрия или облачная регистрация.

## Ограничения продукта

- Plaintext transport не предоставляется.
- Discovery не является доверием; pairing всегда требует подтверждения пользователя.
- Ввод, буфер и файлы являются отдельными capabilities.
- Синтетические события не должны повторно захватываться и усиливаться.
- Disconnect, lock, sleep, crash и emergency stop должны освободить клавиши и вернуть локальное управление.
- Логи не содержат введённый текст, clipboard content, содержимое и частные имена файлов, ключи и стабильные сетевые identifiers.

## Этапы и acceptance gates

Оценки предполагают сфокусированную разработку одним человеком и не являются обещанием сроков. Доступ к hardware, signing и внешний security review могут увеличить время. Stable-продукт реалистично требует **9–12+ месяцев** full-time и больше при part-time работе.

| Этап | Оценочный диапазон | Результат | Условие выхода |
| --- | ---: | --- | --- |
| M0 — Реализуемость | 2–4 недели | Изолированные macOS/Windows input, clipboard, QUIC и Finder ↔ Explorer file-drop spikes | Синтетические события различаются; permissions понятны; cross-OS file-drop доказан или явно исключён |
| M1 — Основа | 3–5 недель | Rust workspace, native shells, local IPC, identity, discovery, pairing, reconnect | Две чистые машины находят и pair друг друга без CLI; reconnect сохраняет подтверждённую identity |
| M2 — Односторонний ввод | 4–6 недель | Mac → Windows и Windows → Mac pointer и keyboard | EN/RU раскладки, modifiers, media keys; p95 LAN latency ≤15 ms; stress не оставляет stuck keys |
| M3 — Двусторонний KVM | 4–6 недель | Equal peers, ownership lease, screen graph, DPI transforms | Переключение, multi-monitor, sleep/reconnect, конфликт takeover и emergency stop детерминированы |
| M4 — Буфер | 3–5 недель | Текст, HTML, изображения, versioning и limits | Нет sync-loop; изображения 100 MB ограничены; malformed input завершается безопасно |
| M5 — Файлы | 5–8 недель | Файлы/папки, очередь, resume, staging и hashes | 0 B–10 GB, Unicode, cancel/resume, нет traversal/symlink escape и silent overwrite |
| M6 — Product UX | 5–8 недель | Onboarding, permissions, layout, transfers, diagnostics, autostart, uninstall | Чистый пользователь соединяет устройства менее чем за 3 минуты; install/upgrade/uninstall matrix проходит |
| M7 — Public beta | 8+ недель | Подписанная beta, updater, protocol release candidate | 30 дней dogfood, 100 реальных пар, ≥99.5% crash-free sessions, после внешнего review нет critical/high |
| M8 — Stable 1.0 | По gates | Стабильный protocol, supported matrix, release и recovery процесс | Reproducible artifacts, rollback, SBOM/provenance, response process и документация завершены |

## Стратегия качества

- Unit/property tests для codecs, state machines, transforms, mappings, trust и limits.
- Fuzzing каждого network decoder, clipboard parser, transfer manifest, discovery record и IPC boundary.
- Симуляция loss, duplication, reordering, MTU/address changes, suspend и reconnect.
- Virtual platform adapters для детерминированных integration tests.
- Реальные Mac ARM64/Intel и Windows x64/ARM64 для hooks, permissions, DPI, drag/drop, sleep и installers.
- 24-часовые soak tests с 1000 Hz mouse, clipboard churn, reconnect и большими файлами.
- Проверка EN/RU, dead keys, AltGr, Caps Lock, IME fallback, media keys, trackpads и мышей 125–1000 Hz.
- Контроль supply chain: dependency policy, audits, lockfiles, SBOM и signed provenance.

## Релизы и распространение

### macOS

- Подписанный и notarized universal либо ARM64/x64 DMG.
- Hardened runtime и явный onboarding Accessibility/Input Monitoring/Local Network.
- Homebrew Cask после подтверждения надёжности beta.

### Windows

- Authenticode-signed x64/ARM64 MSIX/MSI и portable ZIP только при подтверждении его безопасности.
- Firewall rule только для Private networks.
- WinGet после создания stable-канала.

### Общие доказательства релиза

- Immutable tags и release notes на английском и русском.
- SHA-256 checksums и подписанный checksum manifest.
- SPDX/CycloneDX SBOM и build provenance.
- Stable и beta channels с проверенным rollback.
- Телеметрия остаётся optional и не требуется для updates.

## Метрики успеха

До stable 1.0:

- Не менее 100 реальных paired Mac/Windows setups в public beta.
- p95 local input latency не выше 15 ms на опубликованной reference LAN.
- Не менее 99.5% crash-free beta sessions.
- Нет нерешённых critical/high findings независимого security review.
- Опубликованы воспроизводимые benchmarks и compatibility matrix.
- Не менее пяти значимых внешних issues, fixes, documentation contributions или test reports от людей вне команды мейнтейнера.

Эти метрики показывают здоровье продукта; одних stars и downloads недостаточно.

## Реестр рисков

| Риск | Влияние | Снижение риска |
| --- | --- | --- |
| Finder ↔ Explorer drag/drop нельзя сделать безопасным и бесшовным | Высокое | Доказать в M0; использовать явную transfer queue вместо фальшивого DnD |
| Различие keyboard semantics | Высокое | Canonical HID events, layout matrix, Unicode fallback, real hardware tests |
| Синтетический input вызывает loops или stuck keys | Критическое | Origin/session tags, ownership lease, forced key release, emergency hotkey |
| Pairing подменяется в hostile LAN | Критическое | SAS confirmation, mutual pinned identities, отсутствие silent TOFU |
| Clipboard/files становятся каналом атаки | Критическое | Capabilities, size limits, staging, path validation, no auto-open, fuzzing |
| macOS permissions сбрасываются после update | Среднее | Stable signing identity, diagnostics, upgrade tests |
| Windows secure desktop расширяет privileges | Высокое | Явно исключить из 1.0 |
| Signing и hardware matrix задерживают релиз | Среднее | Заложить бюджет до beta; не называть unsigned artifacts stable |

## Доверие к open-source проекту

Nodavo должен заслужить доверие публичным протоколом, threat model, clean-room policy, ADR, воспроизводимыми benchmarks, continuous fuzzing, подписанными binaries, SBOM/provenance, good-first issues, прозрачным описанием неудач и реальной maintainer-работой. Репозиторий нельзя представлять зрелым только ради участия в акции или программе.
