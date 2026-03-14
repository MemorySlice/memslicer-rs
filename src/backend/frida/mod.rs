pub mod agent;

use super::{Backend, DeviceType, ModuleInfo, PlatformInfo, RangeInfo};
use crate::cli::Target;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

// ---------------------------------------------------------------------------
// Intermediate structs for deserializing Frida RPC responses
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FridaRange {
    base: String,
    size: u64,
    protection: String,
    #[serde(default)]
    file: Option<FridaFile>,
}

#[derive(Deserialize)]
struct FridaFile {
    path: String,
}

#[derive(Deserialize)]
struct FridaModule {
    name: String,
    base: String,
    size: u64,
    path: String,
}

#[derive(Deserialize)]
struct FridaEnrichedRange {
    base: String,
    size: u64,
    protection: String,
    #[serde(default)]
    file: Option<FridaFile>,
    #[serde(default = "default_readable")]
    readable: bool,
    #[serde(default)]
    #[serde(rename = "skipReason")]
    skip_reason: Option<String>,
    #[serde(default = "default_pages_resident")]
    #[serde(rename = "pagesResident")]
    pages_resident: i64,
}

fn default_readable() -> bool { true }
fn default_pages_resident() -> i64 { -1 }

// ---------------------------------------------------------------------------
// Binary response channel (global to avoid UB in frida crate's handler dispatch)
// ---------------------------------------------------------------------------

struct BinaryResponse {
    metadata: Value,
    data: Option<Vec<u8>>,
}

static BINARY_TX: StdMutex<Option<std::sync::mpsc::Sender<BinaryResponse>>> =
    StdMutex::new(None);
static AGENT_DEBUG: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Agent message handler
// ---------------------------------------------------------------------------

/// Handles non-RPC messages from the injected Frida agent.
///
/// This is a zero-sized type because the frida crate (0.17) has a bug in
/// `call_on_message` where `user_data` (pointing to `CallbackHandler`) is
/// cast to `*mut I` for the ScriptHandler path.  Using a ZST ensures no
/// fields are read through the mis-cast pointer.  All shared state is
/// accessed via module-level statics instead.
///
/// Registering this handler via `script.handle_message()` also connects the
/// GLib "message" signal, which is required for RPC responses to be routed
/// back through the internal mpsc channel used by `exports.call()`.
struct AgentMessageHandler;

impl frida::ScriptHandler for AgentMessageHandler {
    fn on_message(&mut self, message: frida::Message, data: Option<Vec<u8>>) {
        let debug = AGENT_DEBUG.load(Ordering::Relaxed);
        match message {
            frida::Message::Send(send_msg) => {
                if send_msg.payload.r#type == "mem" {
                    let tx_guard = BINARY_TX.lock().unwrap();
                    if let Some(ref tx) = *tx_guard {
                        let _ = tx.send(BinaryResponse {
                            metadata: send_msg.payload.returns,
                            data,
                        });
                    }
                    return;
                }
                if debug {
                    eprintln!("[agent] send: {:?}", send_msg.payload.returns);
                }
            }
            frida::Message::Log(log) => {
                if debug {
                    eprintln!("[agent] {}", log.payload);
                }
            }
            frida::Message::Error(err) => {
                eprintln!("[agent error] {}", err.description);
                if debug && !err.stack.is_empty() {
                    eprintln!("[agent error] {}", err.stack);
                }
            }
            _ => {
                if debug {
                    eprintln!("[agent] message: {message:?}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FridaBackend
// ---------------------------------------------------------------------------

/// Backend implementation that uses Frida to attach to a target process and
/// read its memory via an injected JavaScript agent.
///
/// # Lifetime management
///
/// The `frida` crate ties many objects together with lifetimes
/// (`DeviceManager<'a>`, `Session<'a>`, `Script<'a>`).  Storing them all in
/// one struct triggers self-referential borrow issues.  We side-step this by
/// leaking the long-lived handles (`Frida`, `DeviceManager`) into `&'static`
/// references -- they live for the entire process anyway -- and owning the
/// `Session` and `Script` directly.
pub struct FridaBackend {
    _frida: &'static frida::Frida,
    _device_manager: &'static frida::DeviceManager<'static>,
    _device: &'static frida::Device<'static>,
    _session: &'static frida::Session<'static>,
    script: frida::Script<'static>,
    rx: std::sync::mpsc::Receiver<BinaryResponse>,
    next_id: AtomicU64,
}

impl FridaBackend {
    /// Connect to a device, attach to the target process, inject the agent,
    /// and return a ready-to-use backend.
    pub fn connect(device_type: &DeviceType, target: &Target, debug: bool) -> Result<Self> {
        // 1. Obtain Frida runtime (singleton).
        eprintln!("[*] Initializing Frida runtime...");
        // SAFETY: Frida::obtain() is marked unsafe in the crate.
        let frida: &'static frida::Frida = {
            let f = unsafe { frida::Frida::obtain() };
            Box::leak(Box::new(f))
        };

        // 2. Obtain DeviceManager (leaked to 'static).
        let device_manager: &'static frida::DeviceManager<'static> = {
            let dm = frida::DeviceManager::obtain(frida);
            Box::leak(Box::new(dm))
        };

        // 3. Get the appropriate device (leaked to 'static).
        let device_label = match device_type {
            DeviceType::Local => "local",
            DeviceType::Usb => "USB",
            DeviceType::Remote(host) => host.as_str(),
        };
        eprintln!("[*] Connecting to {device_label} device...");
        let device: &'static frida::Device<'static> = {
            let dev = match device_type {
                DeviceType::Local => device_manager
                    .get_local_device()
                    .context("failed to get local Frida device")?,
                DeviceType::Usb => device_manager
                    .get_device_by_type(frida::DeviceType::USB)
                    .context("failed to get USB Frida device")?,
                DeviceType::Remote(host) => device_manager
                    .get_remote_device(host)
                    .context(format!("failed to connect to remote Frida device at {host}"))?,
            };
            Box::leak(Box::new(dev))
        };
        if debug {
            eprintln!("[debug] Device obtained successfully");
        }

        // 4. Resolve the target PID.
        let pid: u32 = match target {
            Target::Pid(p) => *p,
            Target::Name(name) => {
                eprintln!("[*] Searching for process '{name}'...");
                let processes = device.enumerate_processes();
                if debug {
                    eprintln!("[debug] Enumerated {} processes", processes.len());
                }
                let proc = processes
                    .iter()
                    .find(|p| p.get_name() == name.as_str())
                    .with_context(|| format!("process '{name}' not found on device"))?;
                proc.get_pid()
            }
        };
        eprintln!("[*] Found target with PID {pid}");

        // 5. Attach to the target process (leaked to 'static).
        eprintln!("[*] Attaching to PID {pid}...");
        let session: &'static frida::Session<'static> = {
            let sess = device
                .attach(pid)
                .with_context(|| format!("failed to attach to PID {pid}"))?;
            Box::leak(Box::new(sess))
        };

        // 6. Set up binary response channel for memory reads.
        let (tx, rx) = std::sync::mpsc::channel();
        *BINARY_TX.lock().unwrap() = Some(tx);
        AGENT_DEBUG.store(debug, Ordering::Relaxed);

        // 7. Create and load the agent script.
        eprintln!("[*] Loading agent script...");
        let mut option = frida::ScriptOption::new();
        let mut script = session
            .create_script(agent::AGENT_SCRIPT, &mut option)
            .context("failed to create Frida script")?;

        script.load().context("failed to load Frida script")?;

        // Register message handler *after* load but *before* any RPC call.
        // This connects the GLib "message" signal on the script, which is
        // required for `exports.call()` responses to be routed back through
        // the internal mpsc channel.  Binary memory responses from send()
        // are also routed through this handler to our binary channel.
        let handler = AgentMessageHandler;
        script
            .handle_message(handler)
            .context("failed to register script message handler")?;

        eprintln!("[*] Connected successfully.");

        Ok(Self {
            _frida: frida,
            _device_manager: device_manager,
            _device: device,
            _session: session,
            script,
            rx,
            next_id: AtomicU64::new(0),
        })
    }

    // ------------------------------------------------------------------
    // RPC helpers (used for non-binary operations)
    // ------------------------------------------------------------------

    /// Call an RPC export on the injected agent and return the result as a
    /// `serde_json::Value`.
    fn rpc_call(&mut self, method: &str, args: Option<Value>) -> Result<Value> {
        let result = self
            .script
            .exports
            .call(method, args)
            .map_err(|e| anyhow::anyhow!("RPC call '{method}' failed: {e}"))?;

        Ok(result.unwrap_or(Value::Null))
    }

    /// Convenience wrapper for zero-argument RPC calls.
    fn rpc_call_no_args(&mut self, method: &str) -> Result<Value> {
        self.rpc_call(method, None)
    }
}

// ---------------------------------------------------------------------------
// Backend trait implementation
// ---------------------------------------------------------------------------

impl Backend for FridaBackend {
    fn platform_info(&mut self) -> Result<PlatformInfo> {
        let info = self.rpc_call_no_args("getPlatformInfo")?;
        Ok(PlatformInfo {
            platform: info["platform"].as_str().unwrap_or("unknown").to_string(),
            arch: info["arch"].as_str().unwrap_or("unknown").to_string(),
            page_size: info["pageSize"].as_u64().unwrap_or(4096) as u32,
            pid: info["pid"].as_u64().unwrap_or(0) as u32,
        })
    }

    fn enumerate_ranges(&mut self) -> Result<Vec<RangeInfo>> {
        let args = serde_json::json!(["r--"]);
        let value = self.rpc_call("enumerateRanges", Some(args))?;

        let frida_ranges: Vec<FridaRange> = serde_json::from_value(value)
            .context("failed to parse enumerateRanges response")?;

        let ranges = frida_ranges
            .into_iter()
            .filter_map(|r| {
                let base_addr = parse_hex_address(&r.base)?;
                Some(RangeInfo {
                    base_addr,
                    size: r.size,
                    protection: r.protection,
                    file_path: r.file.map(|f| f.path).unwrap_or_default(),
                    readable: true,
                    skip_reason: None,
                    pages_resident: -1,
                })
            })
            .collect();

        Ok(ranges)
    }

    fn enumerate_ranges_enriched(&mut self) -> Result<Vec<RangeInfo>> {
        let value = self.rpc_call_no_args("enumerateRangesEnriched")?;

        let enriched: Vec<FridaEnrichedRange> = serde_json::from_value(value)
            .context("failed to parse enumerateRangesEnriched response")?;

        let ranges = enriched
            .into_iter()
            .filter_map(|r| {
                let base_addr = parse_hex_address(&r.base)?;
                Some(RangeInfo {
                    base_addr,
                    size: r.size,
                    protection: r.protection,
                    file_path: r.file.map(|f| f.path).unwrap_or_default(),
                    readable: r.readable,
                    skip_reason: r.skip_reason,
                    pages_resident: r.pages_resident,
                })
            })
            .collect();

        Ok(ranges)
    }

    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Option<Vec<u8>>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = serde_json::json!({
            "type": "read",
            "id": id,
            "addr": format!("0x{addr:x}"),
            "size": size
        });
        self.script
            .post(msg.to_string(), None)
            .map_err(|e| anyhow::anyhow!("failed to post read request: {e:?}"))?;

        let resp = self
            .rx
            .recv()
            .map_err(|_| anyhow::anyhow!("binary channel closed"))?;

        let ok = resp
            .metadata
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if ok {
            Ok(resp.data)
        } else {
            Ok(None)
        }
    }

    fn read_pages_batch(
        &mut self,
        base_addr: u64,
        page_size: usize,
        page_count: usize,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = serde_json::json!({
            "type": "readPages",
            "id": id,
            "addr": format!("0x{base_addr:x}"),
            "pageSize": page_size,
            "pageCount": page_count
        });
        self.script
            .post(msg.to_string(), None)
            .map_err(|e| anyhow::anyhow!("failed to post readPages request: {e:?}"))?;

        let resp = self
            .rx
            .recv()
            .map_err(|_| anyhow::anyhow!("binary channel closed"))?;

        let ok = resp
            .metadata
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !ok {
            return Ok(vec![None; page_count]);
        }

        let page_map = resp
            .metadata
            .get("pageMap")
            .and_then(|v| v.as_array())
            .context("missing pageMap in readPages response")?;

        let combined_data = resp.data.unwrap_or_default();
        let mut pages = Vec::with_capacity(page_count);
        let mut offset = 0;

        for entry in page_map {
            let page_ok = entry.as_bool().unwrap_or(false);
            if page_ok {
                let end = offset + page_size;
                if end <= combined_data.len() {
                    pages.push(Some(combined_data[offset..end].to_vec()));
                    offset = end;
                } else {
                    pages.push(None);
                }
            } else {
                pages.push(None);
            }
        }

        while pages.len() < page_count {
            pages.push(None);
        }

        Ok(pages)
    }

    fn enumerate_modules(&mut self) -> Result<Vec<ModuleInfo>> {
        let value = self.rpc_call_no_args("enumerateModules")?;

        let frida_modules: Vec<FridaModule> = serde_json::from_value(value)
            .context("failed to parse enumerateModules response")?;

        let modules = frida_modules
            .into_iter()
            .filter_map(|m| {
                let base_addr = parse_hex_address(&m.base)?;
                Some(ModuleInfo {
                    name: m.name,
                    base_addr,
                    size: m.size,
                    path: m.path,
                })
            })
            .collect();

        Ok(modules)
    }

    fn detach(self: Box<Self>) {
        let _ = self._session.detach();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex address string (with or without "0x" prefix) into a u64.
fn parse_hex_address(s: &str) -> Option<u64> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).ok()
}
