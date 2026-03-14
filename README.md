# memslicer (memslicer-rs)

Frida-based cross-platform process memory acquisition tool that outputs MSL (Memory Slice) format files.

## Overview

memslicer acquires memory from running processes across platforms using Frida instrumentation, with smart pre-filtering and volatility-ordered reads. It produces streaming MSL files with per-page state tracking, optional compression, and BLAKE3 integrity chains.

## Features

- **Cross-platform** -- Linux, Android, Windows, macOS, iOS
- **Smart pre-filtering** -- Platform-specific detection of unreadable regions (smaps on Linux, VirtualQuery on Windows, mach\_vm\_region on macOS/iOS); skips guard pages, reserved memory, and device mappings
- **Volatility-ordered acquisition** -- Reads `rw-` (heap/stack) first, then `rwx` (JIT), `r-x` (code), `r--` (data)
- **Binary transfer** -- Memory sent as raw `ArrayBuffer` via Frida's `send(payload, data)` mechanism (no base64 encoding, no string overhead)
- **Streaming MSL output** with BLAKE3 integrity chain
- **Batched page reads** -- Single message for page-level fallback instead of per-page round-trips
- **Configurable** -- Chunk size, compression (none/zstd/lz4), page fallback control
- **Graceful abort** -- First Ctrl+C finishes the current region and writes a partial MSL file; second force-exits

## Installation

Requires a working Rust toolchain. First, set up the Frida devkit:

```bash
cargo xtask setup
```

Override host detection if cross-compiling:

```bash
cargo xtask setup --os android --arch arm64
```

Then build:

```bash
cargo xtask build
# or: cargo build --release
```

The binary will be at `target/release/memslicer`.

## Usage

```bash
# Local process by name
./memslicer Chrome

# Local process by PID
./memslicer 1234

# USB device (e.g. Android phone)
./memslicer -U Chrome

# Remote Frida server
./memslicer -R 192.168.1.100:27042 Chrome

# With zstd compression
./memslicer -c zstd Chrome

# With protection filter (only rw- regions)
./memslicer --filter-prot rw- Chrome

# With address range filter
./memslicer --filter-addr 0x7f0000000000-0x7fffffffffff Chrome

# Debug mode (per-region details on stderr)
./memslicer -d -U Chrome

# Custom output path
./memslicer -U Chrome -o chrome_dump.msl
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `target` (positional) | PID or process name | -- |
| `-o, --output <PATH>` | Output `.msl` file path | `{pid}_{timestamp}.msl` |
| `-c, --compress <ALGO>` | Compression: `none`, `zstd`, `lz4` | `none` |
| `-b, --backend <NAME>` | Backend | `frida` |
| `-U, --usb` | Connect to USB device | -- |
| `-R, --remote <HOST:PORT>` | Remote Frida server | -- |
| `--os <OS>` | Override OS detection (`linux`, `android`, `macos`, `ios`, `windows`) | auto-detect |
| `--filter-prot <PROT>` | Protection filter (e.g. `rw-`, `r-x`) | all readable |
| `--filter-addr <RANGE>` | Address range filter (`0xSTART-0xEND`) | all |
| `-d, --debug` | Enable debug output | -- |
| `--max-chunk <BYTES>` | Max chunk size for memory reads | `2097152` (2 MB) |
| `--no-page-fallback` | Skip page-by-page fallback on chunk failure | -- |
| `--max-consecutive-fail <N>` | Consecutive page failures before skipping rest | `16` |

## Architecture

```
┌────────────-─┐      post(json)       ┌──────────────────────┐
│  Rust CLI    │ ───────────────────▶  │  Frida JS Agent      │
│              │                       │  (injected in target)│
│  FridaBackend│  ◀──────────────────  │                      │
│              │   send(json, binary)  │  recv() handler      │
└──────┬───────┘                       └──────────────────────┘
       │                                        │
       │ RPC (small JSON)                       │ readVolatile()
       │  - getPlatformInfo                     │ NativeFunction calls
       │  - enumerateRanges                     │ /proc/self/smaps
       │  - enumerateModules                    │ mach_vm_region
       │                                        │ VirtualQuery
       ▼                                        ▼
  MslWriter ──▶ .msl file              Target process memory
```

**Non-binary operations** (platform info, module/range enumeration) use Frida RPC exports -- small JSON payloads.

**Memory reads** use Frida's binary `send(payload, data)` channel. The Rust side posts a read request via `script.post()`, the agent reads memory with `readVolatile()`, and sends the raw `ArrayBuffer` back with no encoding overhead.

### Acquisition Pipeline

1. **Detect platform** -- Query process arch/OS, classify via module heuristics (e.g. `libart.so` = Android)
2. **Enumerate + enrich ranges** -- Get all readable regions with platform-specific metadata (RSS, VmFlags, page residency)
3. **Pre-filter** -- Skip regions marked unreadable (zero-RSS anonymous regions, `VmFlags dd`, `PAGE_GUARD`, etc.)
4. **Sort by volatility** -- `rw-` first (heap/stack), then `rwx` (JIT), `r-x` (code), `r--` (data) last
5. **Chunked read** -- Read each region in 2MB chunks; failed chunks fall back to batched page-by-page reads
6. **Stream to MSL** -- Write each region immediately with per-page state (`Captured`/`Failed`)
7. **Finalize** -- Write module list, close file, print summary

### Pre-filtering Heuristics

| Platform | Condition | Reason |
|----------|-----------|--------|
| Linux/Android | Anonymous, Rss=0, size >= 1MB | JVM/ART pre-allocated regions |
| Linux/Android | VmFlags contains `dd` | Kernel "don't dump" flag |
| Linux/Android | VmFlags contains `io` | Device I/O mapping |
| Linux/Android | VmFlags contains `um`/`uw` | userfaultfd-managed |
| macOS/iOS | pages\_resident=0, anonymous, not swapped | Not backed by anything |
| Windows | State = MEM\_RESERVE | Not committed |
| Windows | PAGE\_GUARD or PAGE\_NOACCESS | Guard/inaccessible pages |
| All | Path starts with `/dev/` (except ashmem) | Device files |

## Output Format

MSL (Memory Slice) -- a binary format implemented in the companion [libmsl](../libmsl) crate.

**File structure:**
- **Header** -- Endianness, version, UUID, timestamp, OS, architecture, PID
- **Memory region blocks** -- Per-region metadata + per-page state array + concatenated page data
- **Module list** -- Loaded libraries/binaries with base address, size, and path
- **Integrity** -- BLAKE3 hash chain across all blocks

Optional zstd or lz4 compression is applied per-block.

## Supported Platforms

| Platform | Pre-filtering | Arch |
|----------|---------------|------|
| Linux | `/proc/self/smaps` (Rss, VmFlags) | x86, x86\_64, arm, arm64 |
| Android | `/proc/self/smaps` | arm, arm64 |
| Windows | `VirtualQuery` (MEM\_RESERVE, PAGE\_GUARD) | x86, x86\_64 |
| macOS | `mach_vm_region` (pages\_resident) | x86\_64, arm64 |
| iOS | `mach_vm_region` (pages\_resident) | arm64 |

## Testing

```bash
cargo test
```

67 unit tests covering region classification, volatility ordering, protection parsing, address/path filtering, and platform detection.

## License

Apache License 2.0
