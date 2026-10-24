# Changelog

## [Unreleased]

### Added

- Slices are written as MSL 1.1 (`0x0101`); the EoC carries the exact block count.
- A VAS Map (0x1001, `NameSource` live) of every enumerated range is written before the EoC.
- Thread Context blocks (0x0011) from Frida thread contexts; `--no-registers` disables them.
- `Cargo.toml` `[patch]` points at the local `../libmsl` during development.

### Fixed

- Compressed output (`-c zstd|lz4`) now follows spec Table 9 via libmsl and is readable by
  memslicer and MemDiver.
