<!-- doc-id: clean-room-policy; lang: ru; translation-of: clean-room-policy.md; revision: 2 -->

# Политика чистой реализации

[English](clean-room-policy.md) · [Русский](clean-room-policy.ru.md)

Nodavo планируется как оригинальная реализация под Apache-2.0. Политика снижает риски авторского права и несовместимых лицензий и позволяет проверять происхождение вкладов. Это правило проекта, а не юридическая консультация.

## Допустимые источники

- Официальная документация Apple, Microsoft, IETF, W3C, Unicode, USB-IF, Rust и библиотек.
- Публичные спецификации протоколов и стандарты.
- Независимо составленные product requirements, interoperability observations и black-box test results.
- Permissively licensed dependencies, разрешённые dependency policy.
- Небольшие code examples только при явно совместимой лицензии и зафиксированной attribution.

## Запрещённое заимствование

- Копирование, перевод, реструктурирование или механическое воспроизведение source из GPL/proprietary KVM.
- Перенос кода, assets, fixtures, messages, UI text, branding и generated artifacts из Deskflow, Lan Mouse, Input Leap, Barrier, Synergy, ShareMouse, Logitech Flow, Across и похожих продуктов без явно совместимого разрешения.
- Просьба к AI coding tool портировать, переписать, имитировать или скрыть несовместимый source.
- Удаление attribution, license notices или commit history для представления заимствованной работы как оригинальной.

## Использование как референса

Другие продукты можно использовать для определения ожидаемого поведения, platform edge cases, interoperability requirements и незакрытых потребностей. Документация Deskflow protocol может информировать будущий optional compatibility adapter, но до реализации ему необходима независимая спецификация и provenance review.

## Provenance вкладов

Pull requests должны указывать нетривиальные источники, использованные при проектировании. Reviewer может потребовать более простую независимую реализацию, дополнительную attribution, удаление dependency или отклонить вклад при неясном происхождении.

По мере появления реализации репозиторий будет хранить:

- ADR для значимых архитектурных решений, начиная с существующего шаблона ADR.
- Уведомления о стороннем коде и отчёты о лицензиях для добавленных зависимостей.
- DCO sign-off в коммитах участников.
- Эталонные векторы протокола после появления собственной спецификации Nodavo.

## Строгий clean-room режим

Если legal/interoperability риск требует разделения, один contributor документирует behavior и test requirements без source excerpts, а другой реализует только по этой спецификации. Разделение и входные данные фиксируются в issue или ADR.

## Реакция на инцидент

Если несовместимый материал попал в репозиторий, необходимо остановить распространение затронутых artifacts, изолировать commit range, приватно описать инцидент, заменить реализацию по независимой спецификации и после review опубликовать необходимые notices или corrections.
