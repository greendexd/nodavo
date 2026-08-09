#!/usr/bin/env python3
"""Validate bilingual metadata and local Markdown links without network access."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]

PAIRS = (
    ("README.md", "README.ru.md"),
    ("CHANGELOG.md", "CHANGELOG.ru.md"),
    ("CONTRIBUTING.md", "CONTRIBUTING.ru.md"),
    ("SECURITY.md", "SECURITY.ru.md"),
    ("CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.ru.md"),
    ("GOVERNANCE.md", "GOVERNANCE.ru.md"),
    ("docs/README.md", "docs/README.ru.md"),
    ("docs/product-plan.md", "docs/product-plan.ru.md"),
    ("docs/architecture.md", "docs/architecture.ru.md"),
    ("docs/roadmap.md", "docs/roadmap.ru.md"),
    ("docs/security-model.md", "docs/security-model.ru.md"),
    ("docs/clean-room-policy.md", "docs/clean-room-policy.ru.md"),
    ("docs/privacy.md", "docs/privacy.ru.md"),
    ("docs/glossary.md", "docs/glossary.ru.md"),
    ("spikes/macos-input/README.md", "spikes/macos-input/README.ru.md"),
    ("spikes/macos-clipboard/README.md", "spikes/macos-clipboard/README.ru.md"),
    ("apps/macos/README.md", "apps/macos/README.ru.md"),
    ("apps/windows/README.md", "apps/windows/README.ru.md"),
    ("docs/building.md", "docs/building.ru.md"),
    ("docs/protocol.md", "docs/protocol.ru.md"),
    (
        "docs/adr/0003-first-contact-pairing-bootstrap.md",
        "docs/adr/0003-first-contact-pairing-bootstrap.ru.md",
    ),
    ("spikes/windows-input/README.md", "spikes/windows-input/README.ru.md"),
    (
        "spikes/windows-clipboard/README.md",
        "spikes/windows-clipboard/README.ru.md",
    ),
)

META_RE = re.compile(
    r"<!--\s*doc-id:\s*([^;]+);\s*lang:\s*([^;]+);.*?revision:\s*(\d+)\s*-->"
)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
TRANSLATION_RE = re.compile(r"translation-of:\s*([^;]+)")
HEADING_RE = re.compile(r"^(#{1,6})\s+", re.MULTILINE)


def metadata(path: Path) -> tuple[str, str, int] | None:
    first_lines = "\n".join(path.read_text(encoding="utf-8").splitlines()[:4])
    match = META_RE.search(first_lines)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip(), int(match.group(3))


def translation_of(path: Path) -> str | None:
    first_lines = "\n".join(path.read_text(encoding="utf-8").splitlines()[:4])
    match = TRANSLATION_RE.search(first_lines)
    return match.group(1).strip() if match else None


def heading_signature(path: Path) -> tuple[int, ...]:
    text = path.read_text(encoding="utf-8")
    return tuple(len(match) for match in HEADING_RE.findall(text))


def validate_pairs(errors: list[str]) -> None:
    for en_rel, ru_rel in PAIRS:
        en = ROOT / en_rel
        ru = ROOT / ru_rel
        if not en.is_file() or not ru.is_file():
            errors.append(f"missing bilingual pair: {en_rel} / {ru_rel}")
            continue
        en_meta = metadata(en)
        ru_meta = metadata(ru)
        if en_meta is None or ru_meta is None:
            errors.append(f"missing metadata: {en_rel} / {ru_rel}")
            continue
        if en_meta[0] != ru_meta[0]:
            errors.append(f"doc-id mismatch: {en_rel} / {ru_rel}")
        if en_meta[1] != "en" or ru_meta[1] != "ru":
            errors.append(f"language metadata mismatch: {en_rel} / {ru_rel}")
        if en_meta[2] != ru_meta[2]:
            errors.append(f"revision mismatch: {en_rel} / {ru_rel}")
        expected_translation = Path(en_rel).name
        if translation_of(ru) != expected_translation:
            errors.append(
                f"translation-of mismatch: {ru_rel} should reference {expected_translation}"
            )
        if heading_signature(en) != heading_signature(ru):
            errors.append(f"heading structure mismatch: {en_rel} / {ru_rel}")


def validate_links(errors: list[str]) -> None:
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for raw in LINK_RE.findall(text) + IMAGE_RE.findall(text):
            target = raw.strip().split()[0].strip("<>")
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = unquote(target.split("#", 1)[0])
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"link escapes repository: {path.relative_to(ROOT)} -> {raw}")
                continue
            if not resolved.exists():
                errors.append(f"broken local link: {path.relative_to(ROOT)} -> {raw}")


def main() -> int:
    errors: list[str] = []
    validate_pairs(errors)
    validate_links(errors)
    if errors:
        print("Repository documentation checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        f"Validated {len(PAIRS)} bilingual document pairs, translation metadata, "
        "heading structure, and local Markdown links."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
