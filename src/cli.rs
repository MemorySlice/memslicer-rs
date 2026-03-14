use clap::Parser;
use crate::backend::{BackendConfig, DeviceType};
use libmsl::CompAlgo;

/// Target process - either a PID or a process name.
#[derive(Debug, Clone)]
pub enum Target {
    Pid(u32),
    Name(String),
}

/// memslicer — acquire process memory and write MSL format files
#[derive(Parser, Debug)]
#[command(name = "memslicer", version, about = "Acquire process memory into MSL format")]
pub struct Args {
    /// Target process: PID (integer) or process name (string)
    pub target: String,

    /// Output .msl file path (default: {pid}_{timestamp}.msl)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Compression algorithm
    #[arg(short, long, default_value = "none", value_parser = parse_comp_algo)]
    pub compress: CompAlgo,

    /// Acquisition backend
    #[arg(short, long, default_value = "frida")]
    pub backend: String,

    /// Connect to USB device (Frida)
    #[arg(short = 'U', long)]
    pub usb: bool,

    /// Remote Frida server host:port
    #[arg(short = 'R', long)]
    pub remote: Option<String>,

    /// Override OS detection (windows, linux, macos, android, ios)
    #[arg(long)]
    pub os: Option<String>,

    /// Protection filter (e.g. "r--", "rw-")
    #[arg(long)]
    pub filter_prot: Option<String>,

    /// Address range filter: 0xSTART-0xEND
    #[arg(long)]
    pub filter_addr: Option<String>,

    /// Enable debug output (per-region details on stderr)
    #[arg(short = 'd', long)]
    pub debug: bool,

    /// Maximum chunk size in bytes for memory reads (default: 2MB)
    #[arg(long, default_value = "2097152")]
    pub max_chunk: usize,

    /// Disable page-by-page fallback when chunk reads fail
    #[arg(long)]
    pub no_page_fallback: bool,

    /// Number of consecutive page failures before skipping remaining pages in a region (default: 16)
    #[arg(long, default_value = "16")]
    pub max_consecutive_fail: usize,
}

fn parse_comp_algo(s: &str) -> Result<CompAlgo, String> {
    match s {
        "none" => Ok(CompAlgo::None),
        "zstd" => Ok(CompAlgo::Zstd),
        "lz4" => Ok(CompAlgo::Lz4),
        other => Err(format!("unknown compression: {other}. Expected: none, zstd, lz4")),
    }
}

/// Parsed acquisition configuration.
pub struct AcquireConfig {
    pub target: Target,
    pub output: Option<String>,
    pub comp_algo: CompAlgo,
    pub backend: BackendConfig,
    pub os_override: Option<String>,
    pub filter_prot: Option<String>,
    pub filter_addr: Option<String>,
    pub debug: bool,
    pub max_chunk: usize,
    pub no_page_fallback: bool,
    pub max_consecutive_fail: usize,
}

/// Parse Args into AcquireConfig.
pub fn build_config(args: Args) -> anyhow::Result<AcquireConfig> {
    // Parse target: try as u32 PID first, else treat as name
    let target = match args.target.parse::<u32>() {
        Ok(pid) => Target::Pid(pid),
        Err(_) => Target::Name(args.target),
    };

    // Build backend config
    let backend = match args.backend.as_str() {
        "frida" => {
            let device_type = if args.usb {
                DeviceType::Usb
            } else if let Some(remote) = args.remote {
                DeviceType::Remote(remote)
            } else {
                DeviceType::Local
            };
            BackendConfig::Frida { device_type }
        }
        other => anyhow::bail!("unknown backend: {other}"),
    };

    Ok(AcquireConfig {
        target,
        output: args.output,
        comp_algo: args.compress,
        backend,
        os_override: args.os,
        filter_prot: args.filter_prot,
        filter_addr: args.filter_addr,
        debug: args.debug,
        max_chunk: args.max_chunk,
        no_page_fallback: args.no_page_fallback,
        max_consecutive_fail: args.max_consecutive_fail,
    })
}
