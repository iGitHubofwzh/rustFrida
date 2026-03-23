# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
rustFrida is an ARM64 Android dynamic binary instrumentation framework. It uses ptrace-based process injection to deploy a native agent library (`libagent.so`) into target processes, enabling inline function hooking, JavaScript scripting (QuickJS), Frida Stalker tracing, and eBPF-based library load monitoring.

## Build Commands

All builds target `aarch64-linux-android` by default (set in `.cargo/config.toml`). Requires Android NDK 25+ at `~/Android/Sdk/ndk/`.

```bash
# Build default members (frida-gum-sys, frida-gum, rust_frida, agent)
cargo build --release

# Build individual crate
cargo build -p agent --release
cargo build -p rust_frida --release

# Build with optional features
cargo build -p agent --release --features frida-gum
cargo build -p agent --release --features qbdi

# Build eBPF monitor (separate from default members)
cargo build -p ldmonitor --release

# Build loader shellcode (requires Python 3 + Android NDK)
cd loader && python3 loader.py

# Setup QuickJS (required before first build of quickjs-hook)
cd quickjs-hook && ./setup_quickjs.sh

# Check syntax without full linking (fast iteration)
cargo check
```

There are no project-level tests or linting configured. The `#![cfg(all(target_os = "android", target_arch = "aarch64"))]` gate on `main.rs` means `cargo test` on the host does nothing for `rust_frida`.

## Deploy & Run

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/
# On device:
./rustfrida --pid <pid>           # Inject by PID
./rustfrida --name com.example    # Inject by process name
./rustfrida --watch-so lib.so     # Wait for SO load, then inject
./rustfrida --pid 1234 -l script.js  # Inject and run JS script
```

## Architecture

### Workspace Crates

```
rust_frida  (binary: rustfrida)  ── Main CLI, ptrace injection, REPL
agent       (cdylib: libagent.so) ── Injected into target process
quickjs-hook (lib)               ── QuickJS engine + ARM64 inline hook engine (C)
frida-gum    (lib)               ── Safe Rust wrapper over Frida Gum
frida-gum-sys (sys lib)          ── Raw FFI bindings to vendored Frida C headers
ldmonitor    (binary + lib)      ── eBPF-based dynamic library load monitor
ldmonitor-common (lib)           ── Shared eBPF message types
ldmonitor-ebpf (eBPF)            ── Kernel-space uprobe program (no_std)
qbdi         (lib)               ── QBDI binary instrumentation bindings
loader/      (C, not a crate)    ── ARM64 bare-metal shellcode for SO loading
```

**Default members** (built by `cargo build`): frida-gum-sys, frida-gum, rust_frida, agent.
**Excluded**: ldmonitor-ebpf, qbdi (build explicitly when needed).

### Injection Pipeline

1. **rust_frida** creates memfds for `agent.so` and `loader.bin` (shellcode)
2. Attaches to target process via ptrace
3. Resolves libc/libdl function addresses by parsing `/proc/<pid>/maps` and calculating offsets from host process
4. Writes `StringTable`, `LibcOffsets`, `DlOffsets` structs into target memory
5. Executes loader shellcode in target → connects Unix socket → receives SO fd → calls `android_dlopen_ext`
6. Agent's `JNI_OnLoad` initializes, connects back via abstract Unix socket
7. CLI enters REPL; commands dispatched to agent over the socket

### rust_frida Modules (src/)

| Module | Responsibility |
|--------|---------------|
| `main.rs` | CLI entry, REPL command loop, shutdown |
| `args.rs` | clap CLI `Args` struct |
| `types.rs` | Code-gen macros (`define_libc_functions!`, `define_dl_functions!`, `define_string_table!`) → `LibcOffsets`, `DlOffsets`, `StringTable`, `UserRegs` |
| `process.rs` | ptrace attach/detach, register manipulation, memory read/write, `/proc/maps` parsing |
| `injection.rs` | `inject_to_process()`, `watch_and_inject()`, `create_memfd_with_data()`; embeds `SHELLCODE` and `AGENT_SO` via `include_bytes!` |
| `communication.rs` | Unix socket listener, agent handshake, command dispatch, `SyncChannel<T>`, global statics (`AGENT_MEMFD`, `GLOBAL_SENDER`, `AGENT_STAT`) |
| `repl.rs` | `CommandCompleter`, `JsReplCompleter`, `run_js_repl()`, `print_help()` |
| `logger.rs` | `log_info!`, `log_error!`, `log_success!`, `log_warn!`, `log_verbose!`, ANSI color constants |

### Agent Features (agent/Cargo.toml)

```toml
default = ["quickjs"]      # JS scripting via QuickJS
frida-gum = [...]          # Frida Stalker tracing (optional)
qbdi = [...]               # QBDI instrumentation (optional)
```

Features gate entire modules with `#[cfg(feature = "...")]`.

### quickjs-hook: Hook Engine + JS Runtime

- **Rust side**: `JSEngine`, `JSContext`, `JSRuntime`, `JSValue` wrappers; JS API registration in `src/jsapi/` (hook, memory, ptr, console)
- **C side**: `hook_engine.c` (ARM64 inline hook dispatcher), `arm64_writer.c` (instruction encoding), `arm64_relocator.c` (branch relocation), `quickjs_wrapper.c` (cross-thread safety helper)
- **Build**: `build.rs` compiles C sources into static libs via `cc`, runs `bindgen` for FFI bindings
- **QuickJS source** must be fetched first: `./setup_quickjs.sh` downloads into `quickjs-src/`

### Hook Memory Allocation & Stealth Patching

Hook engine 管理多个 RWX exec pool（初始 pool + 按需创建的 nearby pool，各 64KB）。

**三层分配器：**
- `hook_alloc(size)` — 全局 bump，无位置约束，fallback 创建无约束 pool
- `hook_alloc_near(size, target)` — 优先 ±4GB pool，Phase 2 fallback `hook_alloc()`（允许非近址，MOVZ 兜底）
- `hook_alloc_near_range(size, target, range)` — 严格范围，不 fallback，扫 `/proc/self/maps` 空隙创建 nearby pool

**三种 stealth patch 模式：**

| | stealth=0 | stealth=1 (wxshadow) | stealth=2 (recomp) |
|---|---|---|---|
| 目标写入 | mprotect + ADRP/MOVZ | prctl shadow 页 | B→slot (recomp 副本页) |
| Patch 大小 | 12~20B | 12~20B | 4B |
| Thunk 分配 | `hook_alloc_near` | **优先** `hook_alloc_near_range(±4GB)` 再 fallback `hook_alloc_near` | recomp 跳板区 slot |
| Trampoline | `hook_alloc` (无约束) | 同左 | `hook_alloc` + `fixup_slot_trampoline` 重建 |

**stealth=1 ADRP 优化**：thunk 优先分配在 target ±4GB 内（`hook_alloc_near_range`），确保 patch 为 12B ADRP+ADD+BR。对小跳板函数（3~4 条指令）更安全。分配失败 fallback 到 `hook_alloc_near`（MOVZ 16~20B），wxshadow 支持最大 20B patch。

**stealth=2 slot 模式**：recomp 代码页 + 跳板区同一次 `mmap` 分配，B 指令距离 ≤68KB（永远不超 ±128MB）。alloc/commit 分离避免竞态：先分配 slot → hook engine 写 thunk → `fixup_slot_trampoline` 修正 → `commit_slot_patch` 原子激活 B 指令。

## Critical Design Constraints

### C/Rust ABI Synchronization
`StringTable`, `LibcOffsets`, `DlOffsets` are defined in both `loader/loader.c` (C) and `rust_frida/src/types.rs` (Rust, via macros). These must match exactly — field order, types, sizes. Any ABI mismatch silently corrupts injection. All Rust structs use `#[repr(C)]`.

### Cross-Thread JS Callback Safety
Hook callbacks execute in the **hooked thread**, not the JS thread. Before any QuickJS operation in a hook callback:
1. Copy `(ctx, callback_bytes)` from `HOOK_REGISTRY` under lock
2. **Release the lock** before calling into QuickJS (prevents deadlock if JS callback calls hook/unhook)
3. Call `ffi::qjs_update_stack_top(ctx)` to update QuickJS runtime stack pointer (prevents false stack overflow → SIGSEGV)

### Macro Imports Across Modules
`#[macro_export]` macros land at the crate root. Each submodule that uses them needs an explicit `use crate::{log_info, log_step, ...};` import.

### Module Name Conflict: `process`
`mod process;` and `use std::process;` in the same file conflict. Use full path `std::process::exit(1)` instead of importing `std::process`.

### Platform Gate
`#![cfg(all(target_os = "android", target_arch = "aarch64"))]` on `main.rs` gates the entire binary. Submodules do NOT need their own copy.

## Code Style

- Comments, CLI help text, and log messages are in Chinese (项目使用中文注释和日志)
- Error handling uses `Result<T, String>` throughout (not `anyhow` or custom error types)
- Logging uses custom macros (`log_info!`, `log_error!`, etc.) with ANSI color constants, not the `log` crate

## gstack

Use the `/browse` skill from gstack for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Available skills: `/office-hours`, `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`, `/design-consultation`, `/review`, `/ship`, `/land-and-deploy`, `/canary`, `/benchmark`, `/browse`, `/qa`, `/qa-only`, `/design-review`, `/setup-browser-cookies`, `/setup-deploy`, `/retro`, `/investigate`, `/document-release`, `/codex`, `/careful`, `/freeze`, `/guard`, `/unfreeze`, `/gstack-upgrade`.

If gstack skills aren't working, run `cd .claude/skills/gstack && ./setup` to build the binary and register skills.
