# ADR-0001: Bounded canonical CBOR peer protocol

- Status: Accepted
- Date: 2026-08-09

## Context

Nodavo needs a public binary peer protocol with stable numeric tags, strict limits before allocation, deterministic golden vectors, and evolution rules that do not couple the core to Quinn or any native UI language.

## Decision

Peer messages use canonical CBOR with explicit numeric message and field tags. Length limits are selected by channel before decode: control 64 KiB, reliable input 1 KiB, datagrams 1200 bytes, transfer manifests 1 MiB and 10,000 entries, relative paths 1024 UTF-8 bytes, and aggregate transfers 10 GiB. Unknown critical message tags are rejected; documented optional tags may remain opaque. Major/minor version negotiation is explicit. Sensitive messages carry session, origin, sequence, grant epoch, and required capability context.

The semantic protocol crate contains no Quinn, rustls, Tokio, filesystem, or platform types. CBOR encoding is implemented with `minicbor` under its MIT/Apache-2.0 license.

## Consequences

- Every decoder must apply its channel limit before parsing or allocating.
- Wire changes require numeric-tag review, golden-vector updates, and later compatibility/fuzz coverage.
- JSON remains acceptable for bounded local UI IPC but is not the peer protocol.
- The encoding is not frozen as stable 1.0 until the M7 release-candidate gate.
