<!-- doc-id: adr-0005-stable-update-supervision; lang: ru; translation-of: 0005-stable-update-supervision.md; revision: 1 -->

# ADR-0005: Стабильный внешний supervisor для активации обновлений

[English](0005-stable-update-supervision.md) · [Русский](0005-stable-update-supervision.ru.md)

- Статус: принят для pre-alpha supervision core; production activation остаётся выключенной
- Дата: 2026-08-19

## Контекст

Nodavo умеет проверять подписанный release и staging content-addressed artifact, но обновление заменяет само приложение, UI и session agent. Ни один из этих процессов не может быть единственным владельцем recovery, если candidate не запускается, завершается до health check или питание пропадает после activation. Platform package transaction также не доказывает здоровье приложения после успешной замены файлов или пакета.

Activation меняет исполняемый код и не может наследовать существующее решение **Скачать и подготовить**. Recovery должен переживать перезапуск процесса и машины, отклонять устаревшие сигналы процессов, сохранять точный predecessor artifact и никогда не удалять его до продвижения durable anti-rollback floor.

## Решение

Production activation будет принадлежать небольшому отдельно подписанному per-user supervisor, установленному вне заменяемого application target. Supervisor не является компонентом peer session и не получает authority для input, clipboard, file transfer, discovery или сетевого peer. Текущий agent отвечает только за release check, verified staging, отдельное одноразовое решение **Установить и перезапустить**, постоянный bounded quiescence и content-free status projection.

Platform-neutral crate `nodavo-update` задаёт bounded write-ahead reducer. Его authenticated journal связывает:

- случайный идентификатор transaction;
- точный candidate artifact, install target, version, rollback epoch и identity каждой process attempt;
- точный сохранённый predecessor artifact и installer evidence;
- ограниченное число candidate-start, health, predecessor-start и old-process-exit attempts;
- текущую фазу и rollback floor, который должен получиться после healthy install.

Каждый внешний эффект разрешён одной уже durable фазой. Supervisor сохраняет следующую фазу до prepare, activation, запуска process, rollback или удаления backup. Один timeout никогда не разрешает второй process или replacement, пока предыдущий точный process может быть жив; сначала требуется process-bound stop и наблюдение exit.

Порядок commit:

1. аутентифицировать точный candidate и записать health;
2. продвинуть durable rollback floor, пока predecessor ещё доступен;
3. записать `FloorAdvanced`;
4. удалить точный predecessor;
5. очистить active journal.

До `FloorAdvanced` ошибка восстанавливает точный сохранённый predecessor и аутентифицирует его перезапуск. После `FloorAdvanced` recovery может повторять cleanup, но не может выполнять downgrade. Отсутствующее, повреждённое, unauthenticated, удалённое, устаревшее или oversized supervision state завершает операцию fail closed.

Platform adapters остаются effect boundaries. Для macOS нужны точный подписанный/notarized universal bundle, private immutable candidate slot, same-volume atomic exchange и отдельно зарегистрированный подписанный supervisor. Для direct-signed Windows нужны точные candidate и predecessor MSIXBundle, four-part package identities, отдельно установленный supervisor package и platform package staging/registration. Microsoft Store builds используют Store-owned updates и не заявляют Nodavo-controlled downgrade без отдельной подтверждённой схемы.

Текущий pre-alpha source реализует только pure supervision policy и неактивирующие platform validation/staging primitives. Он не предоставляет installation IPC, не запускает supervisor, не активирует package и не заявляет power-loss qualification.

## Влияние на безопасность и приватность

Стабильный supervisor исключает candidate code из recovery trust root и делает явными consent, process identity, artifact identity, retry и порядок rollback. Supervisor IPC должен использовать фиксированные взаимные signed-code requirements, эквивалентные существующей границе UI/agent. Public status и logs содержат только bounded phases, versions и общие failure categories; в них нет paths, artifact names, hashes, process identifiers, package family names, transaction identifiers, signing subjects или keys.

User-owned storage не может предотвратить произвольный denial of service со стороны владельца account. Поэтому production state macOS требует supervisor-only Data Protection Keychain entitlement. Windows DPAPI и user-owned files защищают confidentiality и случайное повреждение, но не дают честной rollback-resistance гарантии против invasive same-user process; security model 1.0 исключает compromise уже авторизованных процессов, а более сильное persistence claim требует отдельно квалифицированного principal или broker.

## Отклонённые варианты

- Работающий agent заменяет сам себя: он не переживает candidate startup failure или power loss.
- UI выполняет replacement: он входит в target и не может независимо восстановить себя.
- Helper находится только внутри заменяемого приложения: он заменяется в той же transaction.
- Прямой unprivileged cross-parent bundle exchange в macOS: sealing обоих trees против same-user mutation убирает directory write authority, нужную для `RENAME_SWAP`; ослабление seal снова открывает substitution races. Поэтому текущий platform API остаётся validation-only.
- Download consent повторно используется для activation: он не сообщает о restart или замене executable.
- Сразу после timeout выполняется retry или rollback: timed-out process может оставаться живым.
- Floor продвигается после удаления backup: persistence failure может оставить систему без безопасного rollback и без нужного durable floor.
- Shell, elevation или произвольное исполнение installer: они расширяют authority и разрешают поведение, управляемое artifact.

## Происхождение решения

Решение основано на независимо написанных требованиях репозитория и официальных локальных контрактах Apple Security, launchd, ServiceManagement, filesystem, Microsoft Appx packaging, package deployment и process APIs. Source, сообщения, test fixtures или assets других KVM-продуктов не использовались.
