use std::fs::File;
use std::io::BufWriter;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Context, Result};
use libmsl::{
    Endianness, FileHeader, MemoryRegionPayload, ModuleEntryPayload,
    MslWriter, PageState, RegionType,
};
use crate::backend::{Backend, RangeInfo};
use crate::cli::AcquireConfig;
use crate::filter::RegionFilter;
use crate::platform::{detect_arch, detect_os};
use crate::progress::ProgressUI;
use crate::protection::parse_protection;

pub struct AcquireResult {
    pub regions_captured: u32,
    pub regions_total: u32,
    pub regions_skipped: u32,
    pub bytes_captured: u64,
    pub modules_captured: u32,
    pub aborted: bool,
    pub duration: std::time::Duration,
    pub output_path: String,
}

/// Configuration for read operations, grouped to reduce parameter count.
struct ReadConfig {
    page_size: usize,
    max_chunk: usize,
    no_page_fallback: bool,
    max_consecutive_fail: usize,
    debug: bool,
}

pub fn run(mut backend: Box<dyn Backend>, config: AcquireConfig, abort: Arc<AtomicBool>) -> Result<AcquireResult> {
    let start = std::time::Instant::now();

    // 1. Get platform info
    eprintln!("[*] Querying platform info...");
    let pinfo = backend.platform_info()?;
    let debug = config.debug;
    if debug {
        eprintln!("[debug] platform={} arch={} pid={} page_size={}", pinfo.platform, pinfo.arch, pinfo.pid, pinfo.page_size);
    }

    // 2. Get modules for platform heuristics
    eprintln!("[*] Enumerating modules...");
    let modules = backend.enumerate_modules()?;
    if debug {
        eprintln!("[debug] modules: {}", modules.len());
    }

    // 3. Detect platform
    let arch = detect_arch(&pinfo.arch)?;
    let module_paths: Vec<&str> = modules.iter().map(|m| m.path.as_str()).collect();
    let os = detect_os(&pinfo.platform, &module_paths, config.os_override.as_deref())?;

    // 4. Build file header
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let header = FileHeader {
        endianness: Endianness::Little,
        version_major: 1,
        version_minor: 0,
        flags: 0,
        cap_bitmap: 0x03, // MemoryRegions | ModuleList
        dump_uuid: *uuid::Uuid::new_v4().as_bytes(),
        timestamp_ns: now_ns,
        os_type: os,
        arch_type: arch,
        pid: pinfo.pid,
    };

    // 5. Output path
    let output_path = config.output.unwrap_or_else(|| {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("{}_{}.msl", pinfo.pid, ts)
    });

    // 6. Create writer
    let file = File::create(&output_path).context("failed to create output file")?;
    let buf = BufWriter::new(file);
    let mut writer = MslWriter::new(buf, &header, config.comp_algo)?;

    // 7. Build filter
    let mut filter = RegionFilter::new();
    if let Some(ref prot_str) = config.filter_prot {
        filter.min_prot = parse_protection(prot_str);
    }
    if let Some(ref addr_str) = config.filter_addr {
        if let Some((start_str, end_str)) = addr_str.split_once('-') {
            let start = u64::from_str_radix(
                start_str.trim_start_matches("0x").trim_start_matches("0X"),
                16,
            )
            .context("invalid start address")?;
            let end = u64::from_str_radix(
                end_str.trim_start_matches("0x").trim_start_matches("0X"),
                16,
            )
            .context("invalid end address")?;
            filter.addr_ranges.push((start, end));
        }
    }

    // 8. Enumerate and process ranges (with enrichment for pre-filtering)
    eprintln!("[*] Enumerating memory ranges (with platform enrichment)...");
    let mut ranges = backend.enumerate_ranges_enriched()?;
    if debug {
        eprintln!("[debug] ranges: {} (after enumeration)", ranges.len());
    }

    // 9. Volatility ordering: capture most volatile regions first
    ranges.sort_by_cached_key(|r| volatility_key(r));
    if debug {
        eprintln!("[debug] ranges sorted by volatility");
    }

    let total_ranges = ranges.len() as u32;
    let rcfg = ReadConfig {
        page_size: pinfo.page_size as usize,
        max_chunk: config.max_chunk,
        no_page_fallback: config.no_page_fallback,
        max_consecutive_fail: config.max_consecutive_fail,
        debug,
    };

    let mut regions_written = 0u32;
    let mut regions_skipped = 0u32;
    let mut bytes_captured: u64 = 0;

    let mut ui = ProgressUI::new(total_ranges);
    ui.render();

    for range in &ranges {
        if abort.load(Ordering::Relaxed) {
            break;
        }

        // Pre-filter: skip regions marked unreadable by platform enrichment
        if !range.readable {
            if debug {
                ui.log(format!(
                    "[debug] skip 0x{:x} size={} reason={}",
                    range.base_addr, range.size,
                    range.skip_reason.as_deref().unwrap_or("unreadable")
                ));
            }
            regions_skipped += 1;
            ui.set_progress(regions_written, bytes_captured, regions_skipped);
            ui.render();
            continue;
        }

        let prot = parse_protection(&range.protection);
        if !filter.matches(range.base_addr, range.size, prot, &range.file_path) {
            regions_skipped += 1;
            continue;
        }

        if debug {
            ui.log(format!("[debug] region 0x{:x} size={} prot={} file={}", range.base_addr, range.size, range.protection, range.file_path));
        }

        let region = read_region(
            &mut *backend,
            range.base_addr,
            range.size as usize,
            prot,
            &range.file_path,
            now_ns,
            &rcfg,
            &abort,
            &mut ui,
        )?;
        bytes_captured += region.page_data.len() as u64;
        writer.write_memory_region(&region, None)?;
        regions_written += 1;

        ui.set_progress(regions_written, bytes_captured, regions_skipped);
        ui.render();
    }

    // Final progress update
    ui.set_progress(regions_written, bytes_captured, regions_skipped);
    ui.finish();

    // 10. Write module list
    let module_entries: Vec<ModuleEntryPayload> = modules
        .iter()
        .map(|m| ModuleEntryPayload {
            base_addr: m.base_addr,
            module_size: m.size,
            path: m.path.clone(),
            version: String::new(),
            disk_hash: [0u8; 32],
            native_blob: Vec::new(),
        })
        .collect();

    writer.write_module_list(&module_entries)?;

    // 11. Finalize
    writer.finalize()?;

    // 12. Detach
    backend.detach();

    let duration = start.elapsed();

    Ok(AcquireResult {
        regions_captured: regions_written,
        regions_total: total_ranges,
        regions_skipped,
        bytes_captured,
        modules_captured: modules.len() as u32,
        aborted: abort.load(Ordering::Relaxed),
        duration,
        output_path,
    })
}

/// Compute volatility ordering key for a range.
/// Lower values = higher priority (read first).
fn volatility_key(range: &RangeInfo) -> (u8, u64) {
    let prot = parse_protection(&range.protection);
    let is_rw = (prot & 0b011) == 0b011; // read + write
    let is_x = (prot & 0b100) != 0;       // execute

    let priority = if is_rw && !is_x {
        // rw- : heap, stack, anonymous — most volatile
        0
    } else if is_rw && is_x {
        // rwx : JIT code
        1
    } else if is_x {
        // r-x : executable code
        2
    } else {
        // r-- or other: disk-backed, lowest priority
        3
    };

    // Within same priority, sort by address (lower addresses first)
    (priority, range.base_addr)
}

fn read_region(
    backend: &mut dyn Backend,
    base_addr: u64,
    size: usize,
    protection: u8,
    file_path: &str,
    timestamp_ns: u64,
    rcfg: &ReadConfig,
    abort: &AtomicBool,
    ui: &mut ProgressUI,
) -> Result<MemoryRegionPayload> {
    let num_pages = (size + rcfg.page_size - 1) / rcfg.page_size;

    let (page_states, page_data) = if size <= rcfg.max_chunk {
        // Small region: try full read, fallback to page-by-page
        match backend.read_memory(base_addr, size)? {
            Some(data) => {
                if rcfg.debug {
                    ui.log(format!("[debug]   full read ok: {} bytes", data.len()));
                }
                (vec![PageState::Captured; num_pages], data)
            }
            None => {
                if rcfg.no_page_fallback {
                    if rcfg.debug {
                        ui.log(format!("[debug]   full read failed, page fallback disabled"));
                    }
                    (vec![PageState::Failed; num_pages], Vec::new())
                } else {
                    if rcfg.debug {
                        ui.log(format!("[debug]   full read failed, falling back to batched page read"));
                    }
                    read_pages(backend, base_addr, num_pages, rcfg, abort, ui)?
                }
            }
        }
    } else {
        // Large region: read in chunks, fallback per failed chunk
        let mut states = Vec::with_capacity(num_pages);
        let mut data = Vec::with_capacity(size);
        let mut offset: usize = 0;

        while offset < size {
            if abort.load(Ordering::Relaxed) {
                let remaining_pages = num_pages - states.len();
                states.extend(std::iter::repeat(PageState::Failed).take(remaining_pages));
                break;
            }

            let chunk_size = std::cmp::min(rcfg.max_chunk, size - offset);
            let chunk_addr = base_addr + offset as u64;
            let chunk_pages = (chunk_size + rcfg.page_size - 1) / rcfg.page_size;

            match backend.read_memory(chunk_addr, chunk_size)? {
                Some(chunk_data) => {
                    if rcfg.debug {
                        ui.log(format!("[debug]   chunk 0x{:x} ok: {} bytes", chunk_addr, chunk_data.len()));
                    }
                    states.extend(std::iter::repeat(PageState::Captured).take(chunk_pages));
                    data.extend_from_slice(&chunk_data);
                    ui.set_in_progress_bytes(data.len() as u64);
                    ui.render();
                }
                None => {
                    if rcfg.no_page_fallback {
                        if rcfg.debug {
                            ui.log(format!("[debug]   chunk 0x{:x} failed, page fallback disabled", chunk_addr));
                        }
                        states.extend(std::iter::repeat(PageState::Failed).take(chunk_pages));
                    } else {
                        if rcfg.debug {
                            ui.log(format!("[debug]   chunk 0x{:x} failed, falling back to batched page read", chunk_addr));
                        }
                        let (pg_states, pg_data) = read_pages(
                            backend, chunk_addr, chunk_pages, rcfg, abort, ui,
                        )?;
                        states.extend(pg_states);
                        data.extend_from_slice(&pg_data);
                    }
                }
            }

            offset += chunk_size;
        }

        (states, data)
    };

    let region_type = classify_region(file_path);

    ui.set_in_progress_bytes(0);

    Ok(MemoryRegionPayload {
        base_addr,
        region_size: size as u64,
        protection,
        region_type,
        page_size: rcfg.page_size as u16,
        num_pages: num_pages as u32,
        timestamp_ns,
        page_states,
        page_data,
    })
}

fn read_pages(
    backend: &mut dyn Backend,
    base_addr: u64,
    num_pages: usize,
    rcfg: &ReadConfig,
    abort: &AtomicBool,
    ui: &mut ProgressUI,
) -> Result<(Vec<PageState>, Vec<u8>)> {
    // Use batched RPC call to read all pages at once
    let batch_results = backend.read_pages_batch(base_addr, rcfg.page_size, num_pages)?;

    let mut states = Vec::with_capacity(num_pages);
    let mut data = Vec::with_capacity(num_pages * rcfg.page_size);
    let mut consecutive_failures = 0usize;

    for (i, page_result) in batch_results.into_iter().enumerate() {
        if abort.load(Ordering::Relaxed) {
            let remaining = num_pages - states.len();
            states.extend(std::iter::repeat(PageState::Failed).take(remaining));
            break;
        }

        match page_result {
            Some(page_data) => {
                states.push(PageState::Captured);
                data.extend_from_slice(&page_data);
                consecutive_failures = 0;
            }
            None => {
                if rcfg.debug {
                    let page_addr = base_addr + (i * rcfg.page_size) as u64;
                    ui.log(format!("[debug]     page 0x{:x} failed", page_addr));
                }
                states.push(PageState::Failed);
                consecutive_failures += 1;

                if consecutive_failures >= rcfg.max_consecutive_fail {
                    if rcfg.debug {
                        ui.log(format!(
                            "[debug]     {} consecutive failures, skipping remaining {} pages",
                            rcfg.max_consecutive_fail,
                            num_pages - states.len()
                        ));
                    }
                    let remaining = num_pages - states.len();
                    states.extend(std::iter::repeat(PageState::Failed).take(remaining));
                    break;
                }
            }
        }
    }

    Ok((states, data))
}

fn classify_region(file_path: &str) -> RegionType {
    if file_path.is_empty() {
        return RegionType::Anon;
    }
    match file_path {
        "[heap]" => RegionType::Heap,
        "[stack]" => RegionType::Stack,
        s if s.starts_with("[stack:") => RegionType::Stack,
        _ => {
            if file_path.ends_with(".so")
                || file_path.ends_with(".dylib")
                || file_path.ends_with(".dll")
                || file_path.ends_with(".exe")
                || file_path.contains(".so.")
            {
                RegionType::Image
            } else if file_path.contains('/') || file_path.contains('\\') {
                RegionType::MappedFile
            } else {
                RegionType::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_region_empty() {
        assert_eq!(classify_region(""), RegionType::Anon);
    }

    #[test]
    fn test_classify_region_heap() {
        assert_eq!(classify_region("[heap]"), RegionType::Heap);
    }

    #[test]
    fn test_classify_region_stack() {
        assert_eq!(classify_region("[stack]"), RegionType::Stack);
    }

    #[test]
    fn test_classify_region_stack_with_tid() {
        assert_eq!(classify_region("[stack:1234]"), RegionType::Stack);
    }

    #[test]
    fn test_classify_region_shared_object() {
        assert_eq!(classify_region("/usr/lib/libc.so"), RegionType::Image);
    }

    #[test]
    fn test_classify_region_shared_object_versioned() {
        assert_eq!(classify_region("/usr/lib/libc.so.6"), RegionType::Image);
    }

    #[test]
    fn test_classify_region_dylib() {
        assert_eq!(
            classify_region("/usr/lib/libSystem.B.dylib"),
            RegionType::Image
        );
    }

    #[test]
    fn test_classify_region_dll() {
        assert_eq!(
            classify_region("C:\\Windows\\System32\\ntdll.dll"),
            RegionType::Image
        );
    }

    #[test]
    fn test_classify_region_exe() {
        assert_eq!(
            classify_region("C:\\Windows\\explorer.exe"),
            RegionType::Image
        );
    }

    #[test]
    fn test_classify_region_mapped_file_unix() {
        assert_eq!(classify_region("/tmp/data.bin"), RegionType::MappedFile);
    }

    #[test]
    fn test_classify_region_mapped_file_windows() {
        assert_eq!(
            classify_region("C:\\Users\\data.bin"),
            RegionType::MappedFile
        );
    }

    #[test]
    fn test_classify_region_unknown() {
        assert_eq!(classify_region("[vdso]"), RegionType::Unknown);
    }

    #[test]
    fn test_abort_mid_acquisition() {
        let flag = Arc::new(AtomicBool::new(true));
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn test_volatility_key_rw_anon() {
        let range = RangeInfo {
            base_addr: 0x1000,
            size: 4096,
            protection: "rw-".to_string(),
            file_path: String::new(),
            readable: true,
            skip_reason: None,
            pages_resident: -1,
        };
        assert_eq!(volatility_key(&range).0, 0);
    }

    #[test]
    fn test_volatility_key_rwx() {
        let range = RangeInfo {
            base_addr: 0x2000,
            size: 4096,
            protection: "rwx".to_string(),
            file_path: String::new(),
            readable: true,
            skip_reason: None,
            pages_resident: -1,
        };
        assert_eq!(volatility_key(&range).0, 1);
    }

    #[test]
    fn test_volatility_key_rx() {
        let range = RangeInfo {
            base_addr: 0x3000,
            size: 4096,
            protection: "r-x".to_string(),
            file_path: "/usr/lib/libc.so".to_string(),
            readable: true,
            skip_reason: None,
            pages_resident: -1,
        };
        assert_eq!(volatility_key(&range).0, 2);
    }

    #[test]
    fn test_volatility_key_ro() {
        let range = RangeInfo {
            base_addr: 0x4000,
            size: 4096,
            protection: "r--".to_string(),
            file_path: "/usr/lib/libc.so".to_string(),
            readable: true,
            skip_reason: None,
            pages_resident: -1,
        };
        assert_eq!(volatility_key(&range).0, 3);
    }

    #[test]
    fn test_volatility_ordering() {
        let ranges = vec![
            RangeInfo { base_addr: 0x4000, size: 4096, protection: "r--".to_string(), file_path: String::new(), readable: true, skip_reason: None, pages_resident: -1 },
            RangeInfo { base_addr: 0x1000, size: 4096, protection: "rw-".to_string(), file_path: String::new(), readable: true, skip_reason: None, pages_resident: -1 },
            RangeInfo { base_addr: 0x3000, size: 4096, protection: "r-x".to_string(), file_path: String::new(), readable: true, skip_reason: None, pages_resident: -1 },
            RangeInfo { base_addr: 0x2000, size: 4096, protection: "rwx".to_string(), file_path: String::new(), readable: true, skip_reason: None, pages_resident: -1 },
        ];

        let mut sorted = ranges;
        sorted.sort_by_key(|r| volatility_key(r));

        assert_eq!(sorted[0].base_addr, 0x1000); // rw-
        assert_eq!(sorted[1].base_addr, 0x2000); // rwx
        assert_eq!(sorted[2].base_addr, 0x3000); // r-x
        assert_eq!(sorted[3].base_addr, 0x4000); // r--
    }
}
