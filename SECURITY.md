<!-- doc-id: security-policy; lang: en; revision: 1 -->

# Security Policy

Nodavo processes keyboard, mouse, clipboard, and file data, so security is a primary product boundary rather than an optional feature.

## Current status

Nodavo is pre-alpha and has no supported binary release. Claims in the documentation describe design requirements, not currently shipped protections.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting:

<https://github.com/greendexd/nodavo/security/advisories/new>

Include the affected commit or version, platform pair, reproduction steps, realistic impact, and any suggested mitigation. Do not include unrelated personal data or live clipboard contents.

The maintainer aims to acknowledge complete reports within seven days and provide a status update at least every fourteen days while investigation continues. These are response targets, not guaranteed fix deadlines.

## Coordinated disclosure

Please allow time to investigate, prepare tests, and ship signed fixes before public disclosure. Credit will be offered unless the reporter prefers anonymity or the report is abusive, fraudulent, or not reproducible.

## Security boundaries

The planned security architecture and explicit non-goals are documented in the [security model](docs/security-model.md). A paired device is still a potentially malicious peer; encryption alone does not make clipboard or file content safe.

