<!-- doc-id: windows-clipboard-spike; lang: en; revision: 1 -->

# Windows clipboard feasibility spike

[English](README.md) · [Русский](README.ru.md)

This directory is a disposable M0 evidence boundary for the intended Windows clipboard adapter. The production boundary belongs in `nodavo-platform-windows`: Win32 Clipboard and OLE calls, ownership, native allocation, and buffer access must remain inside its `ffi` modules. The safe side must receive owned, bounded representations rather than native handles or pointers.

The intended runtime probe must establish clipboard revision observation and bounded text, HTML, and image format discovery without logging clipboard contents. Read and write paths must handle clipboard contention, reject malformed or oversized representations before copying, release native ownership correctly, require an explicit clipboard capability, and prevent synchronization loops. File clipboard and drag/drop remain separate work and must not be implied by this spike.

## Current command and evidence

From the repository root:

```bash
rustup target add x86_64-pc-windows-msvc
cargo check -p nodavo-platform-windows --target x86_64-pc-windows-msvc
```

A successful command is **type-check evidence only** for the Windows x64 MSVC target. It does not link or run a Windows executable and therefore does not prove Win32 Clipboard or OLE behavior, format conversion, ownership and locking, malformed-data rejection, size limits, loop prevention, session behavior, or secure-desktop rejection.

This directory currently contains no runtime probe. Real Windows x64 and ARM64 hardware evidence, including clipboard churn and lifecycle stress, remains required before M0 can close.
