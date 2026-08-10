<!-- doc-id: security-model; lang: ru; translation-of: security-model.md; revision: 14 -->

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
- Независимый вредоносный локальный process, имитирующий UI или agent через документированный IPC endpoint без предварительного invasive access к авторизованному процессу Nodavo.
- Вредоносный clipboard/file sender, атакующий parsers, paths, quotas или auto-open.
- Скомпрометированная dependency, build runner, download host или update manifest.

Physical compromise paired-машины, kernel compromise, malicious firmware и compromised OS trust store выходят за защитную границу 1.0, но должны явно указываться в release documentation. Code injection, process hollowing, debugging, `PROCESS_DUP_HANDLE`, process-memory read/write и arbitrary-code compromise, затрагивающие уже авторизованный Nodavo UI или agent process, также находятся вне этой границы: local IPC gates отклоняют независимый impersonating endpoint, но не создают отдельный OS principal или integrity boundary вокруг самого доверенного процесса. Для Windows full-trust UI/agent processes это различие особенно важно. Threat model с invasive same-user process access требует отдельно квалифицированный broker или OS principal и не заявляется для 1.0.

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

Private keys по возможности non-exportable и хранятся через macOS Keychain и Windows DPAPI/CNG. Trust records разделяют input, clipboard и file capabilities. Локальная trust record также хранит ограниченное display name из pairing и ненулевую монотонно возрастающую local grant epoch. Legacy pre-alpha trust records мигрируют с нейтральным ограниченным display name и epoch `1`; миграция не выводит и не добавляет новые grants.

Текущий pre-alpha agent также содержит явно предназначенный только для разработки versioned file fallback для локальной работы с двумя процессами. На Unix каталоги ограничены режимом `0700`, файлы — `0600`, decoding ограничен, а replacement выполняется атомарно, но этот fallback не выполняет production-требование Keychain/DPAPI и не должен попадать в stable storage.

## Безопасность сессии

- QUIC с TLS 1.3; plaintext compatibility mode для application/session data отсутствует. TCP preflight первого контакта переносит только untrusted metadata временного сертификата и не может разрешить input, clipboard, files или persistent trust.
- Version/capability negotiation аутентифицирован.
- Replay-resistant session IDs и монотонная проверка sequences.
- Bounded messages, timeouts, rate limits и connection quotas.
- Единственный ownership lease управляет remote input routing.
- Emergency disconnect выполняется локально и не зависит от peer.
- Lock, sleep, timeout и disconnect освобождают keys/buttons и отзывают active lease.
- Display snapshots являются critical, versioned, ограничены 32 записями, привязаны к сессии и защищены replay-проверкой. Native display IDs остаются локальными; peer может указать только непрозрачный token, установленный для этой аутентифицированной сессии.
- Local и peer capability epochs разделены по направлениям. Входящие input, topology, clipboard и file metadata должны указывать текущую persistent local epoch получателя; исходящие metadata используют epoch, аутентифицированную от peer. Reconnect обменивается полными grants и epochs обеих сторон.
- Изменения capabilities после pairing используют существующий mutually authenticated TLS control stream. Они не описываются как отдельно подписанные: trust boundary состоит из pinned mTLS-аутентификации peer, строгой проверки target/epoch и локальной OS-protected trust database. Каждое принятое изменение освобождает затронутое input/content state и закрывает старое соединение; reconnect обязан использовать persistent policy и заново согласованные epochs.

## Захват и эмуляция ввода

- Native capture запускается без подавления. Suppression разрешается только при активной аутентифицированной и разрешённой focus lease, которая действительно маршрутизирует локальный ввод на peer.
- macOS требует выданное пользователем Accessibility trust. Windows остаётся внутри default input desktop интерактивного текущего пользователя; login, Session 0, UAC secure desktop и privileged unattended control отклоняются.
- Readiness probes не содержат пользовательского контента, ограничены, кратко кэшируются и выполняются вне async command dispatcher. Они никогда не создают или регистрируют capture runtime: проверяются только permission/default-desktop state, обнаружение дисплеев, capability API и prerequisite injector без отправки events. Поэтому `ready` означает готовность prerequisites, а не live capture proof. Timeout или platform error возвращает unavailable, а не выводит готовность косвенно.
- Команда разрешения macOS выполняется только от аутентифицированной identity агента. Показ системного prompt не является авторизацией: его возвращаемое значение игнорируется, а UI получает только результат новой проверки trust и prerequisites. В Windows нет соответствующей permission command, elevation path или обхода secure desktop.
- Готовность session topology независима от обнаружения локальных дисплеев. Она становится ready только после аутентифицированного обмена topology и точного acknowledgement revision и сбрасывается при disconnect, recovery, revoke или failure.
- Инъекция Nodavo использует приватную process tag, если платформа это поддерживает. Capture отклоняет эту tag и все события, отмеченные OS как injected, предотвращая synthetic feedback loop.
- Keyboard usages, modifiers, media keys, pointer buttons, normalized motion и line/precise scrolling проверяются до injection. Native codes не передаются напрямую через peer protocol.
- Edge transition использует critical reliable pointer-entry message. Native suppression и relative deltas остаются закрыты gate, пока receiver не проверит lease/session/grant, не разрешит session display token, не inject начальную позицию и не вернёт аутентифицированный acknowledgement. Это не позволяет потерянному или переупорядоченному entry datagram применить deltas к stale cursor.
- Routed motion использует ограниченные ненулевые relative deltas без display identity. Coalescing callback queue сохраняет точную сумму только пока она остаётся в пределах; иначе события остаются раздельными или запускают явное recovery вместо тихого обрезания physical motion.
- Injector отслеживает каждое принятое нажатие key/button. Emergency stop, потеря focus, lock, sleep, отключение tap/hook, timeout и transport failure синхронно запрашивают детерминированное освобождение и возврат local ownership до успешного acknowledgement.
- Одна safety operation имеет общий 20-секундный ceiling для приёма команды, acknowledgement освобождения, quiescence ранее начатых session/workers, а также authoritative enrollment и cleanup входящих transfers. Пока операция активна, stale handshake generations не могут публиковать `connected`/`ready`, а admission новых transfer workers закрыт. При успехе admission открывается и `ready` публикуется только после cleanup под тем же status lock. Timeout или любая частичная ошибка фиксирует agent в `stopping`, закрывает сессии, отклоняет последующие reconnect/pairing в этом процессе, сохраняет worker admission закрытым и никогда не сообщает `ready`; после remediation требуется restart. Native UI используют более длинный ограниченный deadline ответа и не сообщают timeout, пока server budget ещё допустим.
- Отключённый или просроченный capture hook работает fail-closed: suppression прекращается, local ownership возвращается, а remote session не может незаметно продолжиться.
- Input payloads и pairing codes не попадают в logs, crash metadata или telemetry.
- Readiness response содержит только enum states; в нём нет native display или desktop identifiers, process data, paths, peer identities, prompt details и input content.
- Ревизия топологии должна быть установлена и подтверждена до переноса фокуса в соответствующем направлении. Координаты layout от peer только описательные и никогда не создают adjacency. Edge routes задаются явной локальной политикой, отключены при пустой конфигурации и всё равно проходят обычные проверки focus lease, debounce, hysteresis и cooldown.
- Relative capture через macOS CGEvent и Windows Raw Input вместе с native relative injection реализованы и compile-tested. Поведение на реальных устройствах, различия acceleration, extreme hardware deltas, mixed-DPI hardware и drift долгих сессий остаются release-validation gates.

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
- Receive executor допускает к одному staging owner только одну выбранную очередью передачу. Он принимает лишь непустые ограниченные chunks строго со следующего ожидаемого offset, продвигает публичный прогресс без имён файлов только после подтверждённой staging write и запрещает completion, пока не получен каждый объявленный байт файлов.
- Явная cancellation удаляет только совпадающую active transfer. Неверный identifier, параллельный manifest, gap/overlap offset, преждевременный completion или staging failure отклоняются без продвижения receive state.
- Существующие файлы не перезаписываются молча.
- Полученные файлы не запускаются и не открываются автоматически.
- Per-peer quotas, cancellation, backpressure и rate limits ограничивают DoS.

Pre-alpha receiver пишет через capability-rooted no-follow handles каталогов и файлов. Staging root становится приватным до создания любого имени содержимого: на Unix проверяются permissions, а на Windows owner-only protected DACL создаётся атомарно через root-relative handle; permissive, inherited, foreign-owned, reparse и структурно неоднозначное состояние отклоняется. Один process-wide operation lease сериализует begin/resume/finalize/discard. Progress подтверждается только после flush файлов и журнала; поддерживаемые платформы также синхронизируют каждый изменённый destination-каталог от самого глубокого к корню, причём destination root — последним. Windows явно сообщает, что crash-flush directory entries не поддерживается, поэтому untracked resume после перезапуска агента отклоняется и не выдаётся за устойчивый к отключению питания.

Исходный выбор закрепляется no-follow handles до canonicalization. Enumeration, manifest accounting, hashing, chunks, roots, stable file identities и cooperative cancellation ограничены. Links, reparse points, sparse/special files, overlapping roots, hard-link aliases, mutations, cycles и cross-platform path collisions отклоняются fail-closed. Publication никогда не перезаписывает существующий destination. Если поздняя ошибка многофайловой publication или cleanup делает безопасный rollback неоднозначным, staging owner переходит в poisoned state, а уже опубликованные Nodavo identities сохраняются для явного исправления вместо удаления потенциально подменённого pathname.

Работающий агент связывает входящий transfer ID с peer только после аутентифицированного и разрешённого manifest и сохраняет эту peer-scoped связь при потере соединения. Revocation ждёт завершения workers и освобождения staging lease, затем удаляет только IDs, известные для этого peer. Durable peer-ownership journal между перезапусками агента пока не реализован; неизвестный persisted ID никогда не удаляется лишь потому, что peer предъявил его UUID. Outbound persistence между перезапусками процесса и durable persistence poisoned state также остаются stable-release gates.

## Локальный IPC

- Release-сборки macOS используют пользовательский launchd Mach service `dev.nodavo.agent.ipc` с взаимными per-message XPC code-signing requirements; приватный same-UID UDS остаётся только в явном non-distributable development feature.
- Windows использует named-pipe connections на один request с ACL текущего пользователя и взаимными connection-bound guards точных packaged UI и agent processes до отправки или декодирования request.
- UI requests проходят capability checks; UI не читает private network keys напрямую.
- Listing доверенных устройств ограничен 32 публичными summaries, содержащими только локальный peer identifier, ограниченное display name, состояние active/revoked и локально выданные grants. Сертификаты, endpoints, private material и независимо выданные peer grants исключены.

Агент macOS устанавливает точный `xpc_connection_set_peer_code_signing_requirement` до activation listener Mach service и каждого принятого peer; Swift UI устанавливает взаимный requirement helper до activation client connection. Оба requirement связывают Apple/Developer ID chain, десятисимвольный Team ID времени компиляции, точный identifier `dev.nodavo.macos` или `dev.nodavo.agent`, точные application/team entitlements и отсутствие `get-task-allow`. Контракт XPC проверяет каждое полученное сообщение, поэтому независимый same-user process не может выдать bytes, поставленные в очередь до exec, за сообщение подписанного UI. Requests/replies — точные XPC dictionaries с одним значением и существующим deny-unknown JSON contract; пределы составляют 64 КиБ, 16 peers, четыре outstanding requests на peer, 32 глобально и hard ceiling запроса 360 секунд.

Предыдущий UDS audit-token design явно отозван: `LOCAL_PEERTOKEN` описывает текущее состояние task peer, но не происхождение уже поставленных в очередь bytes, поэтому token rechecks и конечные challenges не устанавливают message provenance. Отсутствующие compile-time Team ID или Mach service приводят к fail-closed, release не имеет UDS fallback и игнорирует `NODAVO_IPC_PATH`. Только development packaging компилирует non-default same-UID UDS bypass `development-unverified-local-ipc`, помечает его unsafe/non-distributable и не объявляет release Mach service. Взаимная XPC authentication реализована для правильно подписанных release builds, но live proof Nodavo Developer ID/provisioning/notarization credentials и installed mutual runtime exercise остаются release gates.

Windows UI-to-agent source path удерживает handles принятого pipe, process, primary token и точного process image на всё время one-request connection. Initial authorization требует совпадения SID, interactive session и logon authentication identifier с агентом; неизменных process creation time и token identifiers; полной package identity с совпадающими compile-time package name, publisher-derived family name, AUMID, architecture, пустым resource identifier и точным `Nodavo.Windows.exe`; а также действительной Authenticode signature, SHA-256 DER leaf certificate которой совпадает со встроенной в эту сборку agent policy. Удерживаемая identity повторно проверяется перед блокирующим чтением frame и после bounded decode непосредственно перед dispatch.

До отправки Windows UI аутентифицирует собственные точные `Package.Current` name, publisher, PFN, AUMID и installed content root, затем получает PID pipe server и удерживает handles server process, token и executable без share-delete. Server должен выполнять точный non-reparse `agent\nodavo-agent.exe` внутри этого аутентифицированного package root, иметь общую с UI session/logon lineage, стабильные process creation/token identifiers и compile-time pinned Authenticode signer. Identity повторно проверяется после framed reply и до JSON decode. Для отдельно запущенного Rust agent не заявляются package identity или AUMID; его authority основан на аутентифицированном package root и точном signed executable внутри него. Development и release policies — взаимоисключающие compile-time metadata с разными UI package identities; unconfigured, unpackaged, mismatched, unsigned или substituted binaries отклоняются fail-closed. Release policy дополнительно требует normal Windows trust и проверенный timestamp evidence; development policy требует отдельно установленный development certificate и точный pin. Packaging подписывает и проверяет оба native executables до packing и повторно после unpacking.

На этом этапе для Windows checks существуют только source, policy-test, cross-target и package-script evidence. Они ещё не выполнялись через установленный packaged UI на квалифицированном Windows x64 или ARM64 hardware, а production publisher, Authenticode и timestamp credentials отсутствуют. Mutual source enforcement уже существует, но installed mutual local-IPC qualification остаётся release gate. Process с invasive access к уже авторизованному UI или agent всё ещё может украсть либо изменить его handles или memory; это явно исключённая граница authorized-process compromise, а не заявленный same-user security principal.

## Обновления и supply chain

Агент теперь интегрирует намеренно не активирующий обновления Unix/macOS slice вокруг pre-alpha crate обновлений. Сборка остаётся ненастроенной, если HTTPS endpoint манифеста и публичный ключ Ed25519 не были явно встроены при компиляции. В настроенной сборке клиент использует нативную платформенную проверку TLS и root store, отключает redirects, ambient proxy discovery, cookies, credentials и decompression, а также применяет ограниченные правила status, length, range, timeout и body. Подписанный манифест должен совпадать с channel, target и install identity сборки, а origin его артефакта — с origin манифеста. Согласие привязано к точному canonical UUID предложения.

Принятые артефакты возобновляемо загружаются в приватный capability-rooted content-addressed staging под межпроцессной exclusive lease и ограничениями quota/retention. Запись проходит потоковые проверки точного offset, размера и digest; файлы и поддерживаемые изменения каталогов синхронизируются до сообщения о verified staging. Staged content не открывается, не запускается, не устанавливается и не активируется. Двуязычный раздел Settings macOS умеет вручную проверять или обновлять статус, опрашивать ограниченный progress через отдельный client, показывать результат up-to-date, принимать или отклонять точное предложение и возобновлять приостановленную загрузку, не отображая endpoint, filesystem path или digest. Для Windows соответствующей интеграции updater staging и UI нет.

Репозиторий не содержит production endpoint, приватного release signing key или доказательства live production update check. В нём также нет защищённого production Keychain-журнала состояния обновлений и durable rollback floor. Контракты state machine для restart, health checking и rollback не подключены, потому что отсутствуют installer, activation step, restart handoff, health supervisor и rollback supervisor. Это release gates, а не свойства текущего потока staged artifacts.

Ниже перечислены обязательные требования к релизу:

- Артефакты релиза будут подписаны; сборки macOS пройдут notarization, а Windows будет использовать Authenticode.
- Манифесты обновлений будут подписаны отдельным офлайн-ключом релиза.
- Механизм обновления будет запрещать откат ниже зафиксированной безопасной версии без документированного восстановления пользователем.
- Правильно подписанные releases должны сохранять взаимные per-message XPC code requirements macOS и Windows reciprocal process/package/Authenticode guards с one-request pipe connections; signed mutual runtime qualification macOS, installed mutual-IPC evidence Windows и live proof production credentials остаются требованиями релиза.
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
