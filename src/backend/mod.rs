pub mod frida;

use crate::cli::Target;

/// Information about a memory range in the target process.
#[derive(Debug, Clone)]
pub struct RangeInfo {
    pub base_addr: u64,
    pub size: u64,
    pub protection: String,    // "rwx" style from the backend
    pub file_path: String,     // empty if anonymous
    pub readable: bool,        // pre-filtering result (true = should attempt read)
    pub skip_reason: Option<String>, // why marked unreadable (for debug)
    pub pages_resident: i64,   // -1 if not available on this platform
}

/// Information about a loaded module.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ModuleInfo {
    pub name: String,
    pub base_addr: u64,
    pub size: u64,
    pub path: String,
}

/// Platform info reported by the backend.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub platform: String,      // "darwin", "linux", "windows"
    pub arch: String,          // "x64", "arm64", "ia32", "arm"
    pub page_size: u32,
    pub pid: u32,
}

/// Trait that all acquisition backends must implement.
pub trait Backend {
    /// Get platform/arch/pid info from the attached process.
    fn platform_info(&mut self) -> anyhow::Result<PlatformInfo>;
    /// Enumerate all memory ranges in the target process.
    fn enumerate_ranges(&mut self) -> anyhow::Result<Vec<RangeInfo>>;
    /// Enumerate ranges with platform-specific enrichment (pre-filtering metadata).
    /// Default implementation calls `enumerate_ranges` and marks all as readable.
    fn enumerate_ranges_enriched(&mut self) -> anyhow::Result<Vec<RangeInfo>> {
        let ranges = self.enumerate_ranges()?;
        Ok(ranges.into_iter().map(|mut r| {
            r.readable = true;
            r.skip_reason = None;
            r.pages_resident = -1;
            r
        }).collect())
    }
    /// Read memory at the given address. Returns None if the read fails (e.g. unreadable page).
    fn read_memory(&mut self, addr: u64, size: usize) -> anyhow::Result<Option<Vec<u8>>>;
    /// Read multiple pages in a single batched RPC call.
    /// Returns a Vec of Option<Vec<u8>>, one per page.
    /// Default implementation falls back to individual read_memory calls.
    fn read_pages_batch(&mut self, base_addr: u64, page_size: usize, page_count: usize) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(page_count);
        for i in 0..page_count {
            let addr = base_addr + (i * page_size) as u64;
            results.push(self.read_memory(addr, page_size)?);
        }
        Ok(results)
    }
    /// Enumerate loaded modules.
    fn enumerate_modules(&mut self) -> anyhow::Result<Vec<ModuleInfo>>;
    /// Detach/disconnect from the target process.
    fn detach(self: Box<Self>);
}

/// Device connection type for Frida.
#[derive(Debug, Clone)]
pub enum DeviceType {
    Local,
    Usb,
    Remote(String),  // host:port
}

/// Per-backend configuration.
#[derive(Debug, Clone)]
pub enum BackendConfig {
    Frida { device_type: DeviceType },
}

/// Create a backend from the given configuration.
pub fn create_backend(config: &BackendConfig, target: &Target, debug: bool) -> anyhow::Result<Box<dyn Backend>> {
    match config {
        BackendConfig::Frida { device_type } => {
            Ok(Box::new(frida::FridaBackend::connect(device_type, target, debug)?))
        }
    }
}
