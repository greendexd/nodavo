<!-- doc-id: adr-0006-semantic-peer-placement; lang: ru; translation-of: 0006-semantic-peer-placement.md; revision: 1 -->

# ADR-0006: Сохранение семантического положения peer и вывод временных edge routes

[English](0006-semantic-peer-placement.md) · [Русский](0006-semantic-peer-placement.ru.md)

- Статус: принято для pre-alpha реализации двустороннего KVM
- Дата: 2026-08-20

## Контекст

Seamless edge switching требует заданной пользователем связи между двумя компьютерами. Native display identifiers, session display identifiers, порядок мониторов, координаты, scale и active topology нестабильны при reconnect, sleep, hot-plug и restart процесса. Сохранение конкретного display-to-display route сделало бы stale hardware state authoritative и могло направить input на удалённую или переиспользованную identity.

Начальному продукту также нужен рабочий layout control до квалификации полного per-display drag editor. Этот control не должен обходить input grants, topology acknowledgement, focus ownership, pointer-entry acknowledgement или safety recovery.

## Решение

Каждая active trust record хранит ровно один `PeerPlacement`: disabled, left, right, above или below. Legacy trust records мигрируют в disabled. Schema не может кодировать native или session display identifier. Revoked peers не могут менять placement.

После commit обеих актуальных topologies, активного peer input grant и точного acknowledgement любой локальной revision, directionally опубликованной для inbound control, session выводит не более 32 детерминированных exterior `Stretch` routes. Outbound-only локальный graph намеренно не публикуется и требует только того же стабильного committed snapshot. Topology transition, снятие grant, смена placement или stale/invalid acknowledgement очищает все derived routes. Focus recovery и восстановление local ownership очищают active route и pending pointer entry. Обычные focus lease, reliable pointer-entry acknowledgement, debounce, hysteresis и cooldown остаются обязательными.

Placement сохраняется до in-session notification. Mutation и session publication используют единый peer-bound lock order, поэтому новая session не может стартовать со stale value между этими шагами. Если active focus не локален или live application неоднозначна, agent восстанавливает local ownership и закрывает session. Сохранённое placement остаётся authoritative для reconnect.

Оба local UI отправляют placement mutation один раз. Они принимают только точный acknowledgement peer и placement; любой неоднозначный outcome сверяется через новый bounded listing trusted peers и никогда — повторной отправкой mutation.

## Влияние на безопасность и приватность

Persistent value раскрывает только coarse relationship, выбранное локальным пользователем. Оно не содержит monitor identity, geometry, route, endpoint, peer-issued grant или input content. Public summaries trusted peers остаются ограничены 32 records и добавляют только этот enum.

Placement не создаёт authority. Без точного peer input grant, актуальных committed topologies и acknowledgement каждой directionally опубликованной локальной revision набор routes пуст. Смена placement не может сохранить non-local lease или pending pointer entry.

## Отклонённые альтернативы

- Сохранять native или session display identifiers: они ephemeral и могут быть удалены или переиспользованы.
- Сохранять concrete edge routes: они связывают stale topology и смешивают user policy с session state.
- Оставить numeric routes из environment: это не native user workflow и небезопасная release policy.
- Сначала построить полный per-display drag editor: он расширяет geometry, accessibility, persistence и hardware qualification до появления базовой рабочей связи между компьютерами.
- Оптимистично обновлять UI или повторять запрос после timeout: потеря acknowledgement даёт outcome-unknown, потому что persistence уже могла завершиться.

## Provenance

Решение следует независимо написанным требованиям Nodavo к product, topology, focus lease и capabilities. Входными данными реализации были оригинальная protocol/state model репозитория и официальная документация Rust, Apple и Microsoft, уже указанная в platform boundaries. Source, UI text, assets или test fixtures других KVM-продуктов не изучались и не переиспользовались.
