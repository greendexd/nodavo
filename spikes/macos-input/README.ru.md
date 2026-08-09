<!-- doc-id: macos-input-spike; lang: ru; translation-of: README.md; revision: 1 -->

# Проверка ввода macOS

[English](README.md) · [Русский](README.ru.md)

Эта одноразовая программа M0 проверяет официальный путь CoreGraphics и Accessibility до создания рабочего платформенного адаптера. Она не передаёт ввод по сети и намеренно выводит только категории событий.

```bash
swift build --package-path spikes/macos-input
.build/debug/nodavo-macos-input-spike --request-permission
.build/debug/nodavo-macos-input-spike --monitor
```

Команда `--inject-probe` отправляет помеченное событие без движения курсора. Запущенный монитор должен видеть категории физических событий и игнорировать это помеченное событие. Для закрытия M0 всё ещё нужны реальные проверки разрешений, сна, блокировки, изменения подписи и обеих архитектур Intel/ARM.
