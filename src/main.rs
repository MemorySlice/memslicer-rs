mod cli;
mod backend;
mod acquire;
mod platform;
mod filter;
mod progress;
mod protection;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let config = cli::build_config(args)?;

    // Set up Ctrl+C handler *before* connecting so users can interrupt a hung connection.
    let abort = Arc::new(AtomicBool::new(false));
    let abort_clone = abort.clone();
    let ctrl_c_count = Arc::new(AtomicU32::new(0));
    let ctrl_c_clone = ctrl_c_count.clone();
    ctrlc::set_handler(move || {
        let count = ctrl_c_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= 2 {
            eprintln!("\nForce quit.");
            std::process::exit(1);
        }
        eprintln!("\nCtrl+C received, finishing current region... (press again to force quit)");
        abort_clone.store(true, Ordering::Relaxed);
    }).expect("failed to set Ctrl+C handler");

    let backend = backend::create_backend(&config.backend, &config.target, config.debug)?;

    let result = acquire::run(backend, config, abort)?;
    if result.aborted {
        eprintln!("Aborted by user. Partial dump saved.");
    }
    let file_size = std::fs::metadata(&result.output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    eprintln!("  Regions : {}/{} ({} skipped)", result.regions_captured, result.regions_total, result.regions_skipped);
    eprintln!("  Bytes   : {}", result.bytes_captured);
    eprintln!("  Modules : {}", result.modules_captured);
    eprintln!("  Duration: {:.2}s", result.duration.as_secs_f64());
    eprintln!("  File    : {} ({} bytes)", result.output_path, file_size);

    Ok(())
}
