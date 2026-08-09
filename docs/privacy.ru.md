<!-- doc-id: privacy; lang: ru; translation-of: privacy.md; revision: 1 -->

# Конфиденциальность

[English](privacy.md) · [Русский](privacy.ru.md)

Nodavo проектируется для прямой работы между paired-устройствами в локальной сети. В 1.0 не планируются account, cloud storage, hosted relay, advertising identifier и mandatory telemetry.

## Локально обрабатываемые данные

В зависимости от enabled capabilities Nodavo может обрабатывать pointer/keyboard events, clipboard representations, file metadata/content, device identities, display layouts, connection addresses, performance counters и local diagnostic logs.

Input, clipboard и file data отправляются только активному paired peer и только при соответствующей capability. Содержимое не отправляется мейнтейнерам Nodavo.

## Логи

Логи не должны содержать keystrokes, clipboard/file contents, private filenames, pairing codes, private keys и stable IP identifiers. Diagnostic export запускается пользователем, доступен для предварительного просмотра и sanitizes по умолчанию.

## Телеметрия

Telemetry и crash upload выключены по умолчанию. Если появится optional telemetry, её точная schema, purpose, retention, endpoint и deletion process публикуются до релиза. Согласие должно быть explicit и revocable без потери updates и core features.

## Обновления

Будущая update check может обращаться к документированному release endpoint. Приложение также должно поддерживать manual update. Update access не передаёт input/content data и не требует аккаунт.

## Paired peers

Pairing предоставляет другому компьютеру технический доступ к выбранным capabilities. Пользователь должен pair только контролируемые устройства и отзывать trust при потере, передаче, переустановке или подозрении на compromise.

