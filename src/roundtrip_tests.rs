//! In-memory roundtrip of the capture layout memslicer writes:
//! header → Thread Context* → Memory Region* → Module List → VAS Map → End-of-Capture,
//! read back with libmsl's slice reader and integrity validation.

use libmsl::constants::{
    BLOCK_FLAG_COMPRESSED, CAP_MEMORY_REGIONS, CAP_MODULE_LIST, CAP_THREAD_CONTEXTS,
    REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP,
};
use libmsl::{
    ArchType, Block, BlockType, CompAlgo, Endianness, FileHeader, MemoryRegionPayload,
    ModuleEntryPayload, MslSliceReader, MslWriter, OsType, PageState, RegionType, VasNameSource,
};

use crate::backend::{RangeInfo, ThreadInfo};
use crate::thread_context::build_thread_contexts;
use crate::vas_map::build_vas_entries;

const PID: u32 = 4242;

fn ranges() -> Vec<RangeInfo> {
    let captured = RangeInfo {
        base_addr: 0x1000,
        size: 0x2000,
        protection: "rw-".to_string(),
        file_path: "[heap]".to_string(),
        readable: true,
        skip_reason: None,
        pages_resident: -1,
    };
    let skipped = RangeInfo {
        base_addr: 0x3000,
        size: 0x1000,
        protection: "r--".to_string(),
        file_path: "/dev/binder".to_string(),
        readable: false,
        skip_reason: Some("device file".to_string()),
        pages_resident: -1,
    };
    vec![captured, skipped]
}

fn threads() -> Vec<ThreadInfo> {
    vec![ThreadInfo {
        id: u64::from(PID),
        name: "main".to_string(),
        state: "running".to_string(),
        registers: vec![
            ("rip".to_string(), "0x401000".to_string()),
            ("rsp".to_string(), "0x7ffd1000".to_string()),
            ("rbp".to_string(), "0x7ffd1040".to_string()),
        ],
    }]
}

fn heap_region() -> MemoryRegionPayload {
    MemoryRegionPayload {
        base_addr: 0x1000,
        region_size: 0x2000,
        protection: 0b011,
        region_type: RegionType::Heap,
        page_size_log2: 12,
        timestamp_ns: 1,
        page_states: vec![PageState::Captured, PageState::Failed],
        page_data: vec![0xAB; 4096],
    }
}

/// Write the layout exactly as `acquire::run` does and return the file bytes.
fn write_capture(comp_algo: CompAlgo) -> Vec<u8> {
    let contexts = build_thread_contexts(&threads(), ArchType::X86_64, PID);
    let header = FileHeader {
        endianness: Endianness::Little,
        cap_bitmap: CAP_MEMORY_REGIONS | CAP_MODULE_LIST | CAP_THREAD_CONTEXTS,
        os_type: OsType::Linux,
        arch_type: ArchType::X86_64,
        pid: PID,
        block_count: 0,
        ..FileHeader::default()
    };
    let mut writer = MslWriter::new(Vec::new(), &header, comp_algo).unwrap();
    for context in &contexts {
        writer.write_thread_context(context, None).unwrap();
    }
    writer.write_memory_region(&heap_region(), None).unwrap();
    writer
        .write_module_list(&[ModuleEntryPayload {
            base_addr: 0x4000,
            module_size: 0x1000,
            path: "/lib/libc.so".to_string(),
            ..ModuleEntryPayload::default()
        }])
        .unwrap();
    writer.write_vas_map(&build_vas_entries(&ranges())).unwrap();
    writer.finalize().unwrap()
}

fn read_blocks(bytes: &[u8]) -> (FileHeader, Vec<Block>) {
    let mut reader = MslSliceReader::new(bytes);
    let header = reader.read_header().unwrap();
    let mut blocks = Vec::new();
    while let Some(block) = reader.next_block().unwrap() {
        blocks.push(block);
    }
    (header, blocks)
}

#[test]
fn capture_layout_roundtrips_through_libmsl() {
    let bytes = write_capture(CompAlgo::None);
    let (header, blocks) = read_blocks(&bytes);

    assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), 0x0101);
    assert_eq!((header.version_major, header.version_minor), (1, 1));
    assert_eq!(
        header.block_count, 0,
        "streaming producer leaves the header count unknown"
    );
    assert_eq!(header.hash_algo, 0);
    assert_eq!(header.cap_bitmap & CAP_THREAD_CONTEXTS, CAP_THREAD_CONTEXTS);

    let types: Vec<BlockType> = blocks.iter().map(|b| b.header().block_type).collect();
    assert_eq!(
        types,
        vec![
            BlockType::ThreadContext,
            BlockType::MemoryRegion,
            BlockType::ModuleListIndex,
            BlockType::ModuleEntry,
            BlockType::VasMap,
            BlockType::EndOfCapture,
        ]
    );
    match blocks.last() {
        Some(Block::EndOfCapture { payload, .. }) => assert_eq!(payload.block_count, 6),
        other => panic!("expected End-of-Capture, got {other:?}"),
    }
    MslSliceReader::new(&bytes).validate_integrity().unwrap();
}

#[test]
fn thread_context_block_carries_current_main_thread() {
    let bytes = write_capture(CompAlgo::None);
    let (_, blocks) = read_blocks(&bytes);
    match &blocks[0] {
        Block::ThreadContext { payload, .. } => {
            assert_eq!(payload.thread_id, u64::from(PID));
            assert_eq!(payload.name, "main");
            assert_eq!(
                payload.flags & libmsl::constants::TC_FLAG_CURRENT,
                libmsl::constants::TC_FLAG_CURRENT
            );
            assert_eq!(payload.registers.len(), 3);
            assert_eq!(payload.registers[0].name, "rip");
            assert_eq!(payload.registers[0].value, 0x401000u64.to_le_bytes());
        }
        other => panic!("expected Thread Context, got {other:?}"),
    }
}

/// A Frida-style arm64 thread (`fp`/`lr` aliases, `nzcv`) and a Frida-style
/// x86_64 thread (`pc`/`sp` next to `rip`/`rsp`) read back with only the
/// Table 19g canonical names.
#[test]
fn thread_contexts_roundtrip_with_canonical_register_names() {
    assert_roundtrip_register_names(
        ArchType::ARM64,
        &[
            ("pc", "0x100003f00"),
            ("sp", "0x16fdff000"),
            ("nzcv", "0x60000000"),
            ("fp", "0x16fdff010"),
            ("lr", "0x100003e00"),
        ],
        &[
            ("pc", REG_ROLE_PC),
            ("sp", REG_ROLE_SP),
            ("nzcv", REG_ROLE_FLAGS),
            ("x29", REG_ROLE_FP),
            ("x30", REG_ROLE_LR),
        ],
    );
    assert_roundtrip_register_names(
        ArchType::X86_64,
        &[
            ("pc", "0x401000"),
            ("sp", "0x7ffd1000"),
            ("rbp", "0x7ffd1040"),
            ("rsp", "0x7ffd1000"),
            ("rip", "0x401000"),
        ],
        &[
            ("rbp", REG_ROLE_FP),
            ("rsp", REG_ROLE_SP),
            ("rip", REG_ROLE_PC),
        ],
    );
}

fn assert_roundtrip_register_names(
    arch: ArchType,
    registers: &[(&str, &str)],
    expected: &[(&str, u16)],
) {
    let thread = ThreadInfo {
        id: u64::from(PID),
        name: "main".to_string(),
        state: "running".to_string(),
        registers: registers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    };
    let header = FileHeader {
        endianness: Endianness::Little,
        cap_bitmap: CAP_THREAD_CONTEXTS,
        os_type: OsType::MacOS,
        arch_type: arch,
        pid: PID,
        block_count: 0,
        ..FileHeader::default()
    };
    let mut writer = MslWriter::new(Vec::new(), &header, CompAlgo::None).unwrap();
    for context in &build_thread_contexts(&[thread], arch, PID) {
        writer.write_thread_context(context, None).unwrap();
    }
    let bytes = writer.finalize().unwrap();
    let (_, blocks) = read_blocks(&bytes);
    match &blocks[0] {
        Block::ThreadContext { payload, .. } => {
            let names_and_roles: Vec<(&str, u16)> = payload
                .registers
                .iter()
                .map(|register| (register.name.as_str(), register.flags))
                .collect();
            assert_eq!(names_and_roles, expected);
        }
        other => panic!("expected Thread Context, got {other:?}"),
    }
}

#[test]
fn vas_map_lists_captured_and_skipped_ranges_as_live() {
    let bytes = write_capture(CompAlgo::None);
    let (_, blocks) = read_blocks(&bytes);
    match &blocks[4] {
        Block::VasMap { payload, .. } => {
            assert_eq!(payload.entries.len(), 2);
            assert!(payload
                .entries
                .iter()
                .all(|e| e.name_source == VasNameSource::Live));
            assert_eq!(payload.entries[0].mapped_path, "[heap]");
            assert_eq!(payload.entries[1].mapped_path, "/dev/binder");
            assert_eq!(payload.entries[1].region_type, RegionType::MappedFile);
        }
        other => panic!("expected VAS Map, got {other:?}"),
    }
}

// Compression is entirely libmsl's job (spec Section 4.2.1 Table 9: the whole
// padded payload is compressed behind a u64 UncompressedSize prefix); memslicer
// only hands over raw page data and selects the algorithm.
#[test]
fn memory_region_roundtrips_with_zstd() {
    assert_compressed_region_roundtrips(CompAlgo::Zstd);
}

#[test]
fn memory_region_roundtrips_with_lz4() {
    assert_compressed_region_roundtrips(CompAlgo::Lz4);
}

fn assert_compressed_region_roundtrips(comp_algo: CompAlgo) {
    let bytes = write_capture(comp_algo);
    let (_, blocks) = read_blocks(&bytes);
    match &blocks[1] {
        Block::MemoryRegion { header, payload } => {
            assert_eq!(payload.page_size_log2, 12);
            assert_eq!(payload.page_states, heap_region().page_states);
            assert_eq!(payload.page_data, heap_region().page_data);
            assert_eq!(header.flags & BLOCK_FLAG_COMPRESSED, BLOCK_FLAG_COMPRESSED);
        }
        other => panic!("expected Memory Region, got {other:?}"),
    }
    MslSliceReader::new(&bytes).validate_integrity().unwrap();
}
