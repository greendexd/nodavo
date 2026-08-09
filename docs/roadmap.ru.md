<!-- doc-id: roadmap; lang: ru; translation-of: roadmap.md; revision: 2 -->

# Дорожная карта

[English](roadmap.md) · [Русский](roadmap.ru.md)

Roadmap описывает порядок, а не обещанные даты. Работа переходит дальше только после воспроизводимого прохождения предыдущего acceptance gate.

## Завершённая основа

- Опубликовать двуязычные документы продукта, архитектуры, privacy, security и clean-room.
- Создать ADR process и проверки качества репозитория.

## Сейчас — проверка реализуемости M0

- Проверить macOS capture/injection и suppression synthetic events.
- Проверить Windows capture/injection и suppression synthetic events.
- Доказать QUIC datagrams и reliable streams в реальной LAN.
- Независимо проверить text/image clipboard API обеих систем.
- Определить безопасность и реализуемость настоящего Finder ↔ Explorer drag/drop.
- Проверить тонкие оболочки SwiftUI и WinUI 3 и выбрать точные способы их упаковки после платформенных экспериментов.

## Next — M1–M3

- Создать Rust workspace и virtual platform adapters.
- Добавить native menu-bar/tray shells и authenticated local IPC.
- Реализовать identity storage, mDNS, pairing, pinning, revocation и reconnect.
- Реализовать one-way input в обе стороны.
- Добавить equal-peer focus ownership, emergency stop, screen graph, multi-monitor и mixed DPI.
- Опубликовать benchmarks latency, CPU, memory, reconnect и stuck keys.

## Then — M4–M6

- Выпустить bounded text/HTML/image clipboard synchronization.
- Создать safe transfer queue, staging, hashing, resume, cancellation и destination rules.
- Добавить cross-OS file clipboard и drag/drop только при подтверждении M0.
- Завершить onboarding, permissions diagnostics, trusted devices, autostart, logs, updates и clean uninstall.
- Добавить continuous fuzzing и real-hardware platform matrix.

## До stable — M7 и M8

- Подписать и notarize beta installers.
- Провести минимум 30 дней dogfood и public beta на 100 парах.
- Выполнить independent security review и закрыть critical/high findings.
- Зафиксировать protocol 1.0, migration rules, compatibility policy, SBOM/provenance, rollback и security response.
- Публиковать Homebrew/WinGet packages только после проверки stable artifacts.

## Later, без обещания

- Поддержка Linux.
- Более двух активных peers.
- Mobile remote input.
- Optional LAN-only audio forwarding.
- Режим совместимости с Deskflow protocol.
- Organization policy deployment.

Public-internet relay, mandatory accounts, скрытая telemetry и автоматический запуск полученных файлов не планируются.
