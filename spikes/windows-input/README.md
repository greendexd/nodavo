<!-- doc-id: windows-input-spike; lang: en; revision: 1 -->

# Windows input feasibility spike

[English](README.md) · [Русский](README.ru.md)

This directory is a disposable M0 evidence boundary for the intended Windows input adapter. The production boundary belongs in `nodavo-platform-windows`: native Raw Input, hook, and `SendInput` details must remain inside its `ffi` modules, while the rest of the workspace receives bounded semantic input events rather than native handles or buffers.

The intended runtime probe must establish that physical keyboard and pointer events can be classified, injected events can be tagged and excluded from recapture, and every tracked key and button is released on disconnect, lock, sleep, timeout, crash recovery, or emergency stop. It must fail closed when the input capability is absent, the user session is unavailable, or the secure desktop is active. Diagnostics may record bounded event categories and error codes, but never keystrokes or stable device identifiers.

## Current command and evidence

From the repository root:

```bash
rustup target add x86_64-pc-windows-msvc
cargo check -p nodavo-platform-windows --target x86_64-pc-windows-msvc
```

A successful command is **type-check evidence only** for the Windows x64 MSVC target. It does not link or run a Windows executable and therefore does not prove Raw Input, hooks, `SendInput`, injected-event suppression, keyboard layouts, pointer coordinates, DPI behavior, session transitions, emergency key release, or secure-desktop rejection.

This directory currently contains no runtime probe. Real Windows x64 and ARM64 hardware evidence, including lifecycle and high-rate input stress, remains required before M0 or M2 can close.
