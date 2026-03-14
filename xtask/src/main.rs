use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use glob::glob;
use tar::Archive;
use xz2::read::XzDecoder;

#[derive(Parser)]
#[command(name = "xtask", about = "Frida devkit setup helper for memslicer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download and install the Frida core devkit into the frida-sys crate
    Setup {
        /// Override detected host OS (macos, linux, windows)
        #[arg(long)]
        os: Option<String>,
        /// Override detected host architecture (arm64, x86_64)
        #[arg(long)]
        arch: Option<String>,
        /// Override Frida version (read from frida-sys FRIDA_VERSION by default)
        #[arg(long)]
        frida_version: Option<String>,
    },
    /// Build memslicer with the correct BINDGEN_EXTRA_CLANG_ARGS
    Build,
}

/// Find the workspace root by walking up from CARGO_MANIFEST_DIR (the xtask crate dir).
fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let xtask_dir = PathBuf::from(manifest_dir);
    let root = xtask_dir
        .parent()
        .context("failed to find workspace root (parent of xtask dir)")?;
    Ok(root.to_path_buf())
}

/// Map `std::env::consts::OS` to Frida devkit OS name.
fn map_os(os: &str) -> Result<&str> {
    match os {
        "macos" => Ok("macos"),
        "linux" => Ok("linux"),
        "windows" => Ok("windows"),
        other => bail!("unsupported OS: {other}"),
    }
}

/// Map `std::env::consts::ARCH` to Frida devkit arch name.
fn map_arch(arch: &str) -> Result<&str> {
    match arch {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x86_64"),
        other => bail!("unsupported architecture: {other}"),
    }
}

/// Locate the frida-sys crate directory inside the Cargo registry.
fn find_frida_sys_dir() -> Result<PathBuf> {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .context("could not determine home directory")?;
    let pattern = format!("{}/.cargo/registry/src/*/frida-sys-*", home);

    let mut matches: Vec<PathBuf> = glob(&pattern)
        .context("failed to evaluate glob pattern")?
        .filter_map(|entry| entry.ok())
        .filter(|p| p.is_dir())
        .collect();

    matches.sort();

    matches
        .into_iter()
        .next()
        .context("frida-sys not found in cargo registry. Run `cargo fetch` first.")
}

/// Read the FRIDA_VERSION file from the frida-sys crate directory.
fn read_frida_version(frida_sys_dir: &Path) -> Result<String> {
    let version_file = frida_sys_dir.join("FRIDA_VERSION");
    let content = fs::read_to_string(&version_file)
        .with_context(|| format!("failed to read {}", version_file.display()))?;
    Ok(content.trim().to_string())
}

/// Download a URL to a local path, printing progress along the way.
/// Skips the download if the file already exists.
fn download_file(url: &str, dest: &Path) -> Result<()> {
    if dest.exists() {
        println!("[xtask] Archive already cached at {}", dest.display());
        println!("[xtask] Skipping download.");
        return Ok(());
    }

    println!("[xtask] Downloading: {url}");

    let response = reqwest::blocking::get(url)
        .with_context(|| format!("failed to start download from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "download failed with HTTP {}: {url}",
            response.status()
        );
    }

    let total_size = response.content_length();
    if let Some(total) = total_size {
        println!("[xtask] Total size: {:.2} MB", total as f64 / 1_048_576.0);
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache dir {}", parent.display()))?;
    }

    let mut out_file = fs::File::create(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;

    let mut reader = response;
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    let mut buf = [0u8; 8192];

    loop {
        let n = reader.read(&mut buf).context("error reading from network")?;
        if n == 0 {
            break;
        }
        out_file
            .write_all(&buf[..n])
            .context("error writing to cache file")?;
        downloaded += n as u64;

        // Report progress every ~512 KB
        if downloaded - last_report >= 524_288 {
            if let Some(total) = total_size {
                let pct = (downloaded as f64 / total as f64) * 100.0;
                println!(
                    "[xtask]   {:.2} / {:.2} MB ({:.1}%)",
                    downloaded as f64 / 1_048_576.0,
                    total as f64 / 1_048_576.0,
                    pct
                );
            } else {
                println!(
                    "[xtask]   {:.2} MB downloaded",
                    downloaded as f64 / 1_048_576.0
                );
            }
            last_report = downloaded;
        }
    }

    println!(
        "[xtask] Download complete: {:.2} MB",
        downloaded as f64 / 1_048_576.0
    );
    Ok(())
}

/// Extract a .tar.xz archive into the given directory.
fn extract_tar_xz(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    println!(
        "[xtask] Extracting {} -> {}",
        archive_path.display(),
        dest_dir.display()
    );

    fs::create_dir_all(dest_dir)
        .with_context(|| format!("failed to create extraction dir {}", dest_dir.display()))?;

    let xz_file =
        fs::File::open(archive_path).with_context(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = XzDecoder::new(xz_file);
    let mut archive = Archive::new(decoder);

    archive
        .unpack(dest_dir)
        .with_context(|| format!("failed to extract {}", archive_path.display()))?;

    println!("[xtask] Extraction complete.");
    Ok(())
}

/// Copy a file from src to dst, printing a message.
fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    println!(
        "[xtask] Copying {} -> {}",
        src.display(),
        dst.display()
    );
    fs::copy(src, dst).with_context(|| {
        format!(
            "failed to copy {} -> {}",
            src.display(),
            dst.display()
        )
    })?;
    Ok(())
}

fn cmd_setup(
    os_override: Option<String>,
    arch_override: Option<String>,
    frida_version_override: Option<String>,
) -> Result<()> {
    // 1. Detect or override OS and arch
    let host_os = match &os_override {
        Some(o) => o.as_str().to_string(),
        None => map_os(std::env::consts::OS)?.to_string(),
    };
    let host_arch = match &arch_override {
        Some(a) => a.as_str().to_string(),
        None => map_arch(std::env::consts::ARCH)?.to_string(),
    };

    println!("[xtask] Target platform: {host_os}-{host_arch}");

    // 2. Run cargo fetch to ensure frida-sys is available
    println!("[xtask] Running `cargo fetch` to ensure dependencies are available...");
    let workspace = workspace_root()?;
    let status = Command::new("cargo")
        .arg("fetch")
        .current_dir(&workspace)
        .status()
        .context("failed to run `cargo fetch`")?;
    if !status.success() {
        bail!("`cargo fetch` failed with exit code: {}", status);
    }

    // 3. Find frida-sys directory
    let frida_sys_dir = find_frida_sys_dir()?;
    println!("[xtask] Found frida-sys at: {}", frida_sys_dir.display());

    // 4. Determine Frida version
    let frida_version = match frida_version_override {
        Some(v) => {
            println!("[xtask] Using user-specified Frida version: {v}");
            v
        }
        None => {
            let v = read_frida_version(&frida_sys_dir)?;
            println!("[xtask] Detected Frida version from frida-sys: {v}");
            v
        }
    };

    // 5. Build download URL
    let archive_name =
        format!("frida-core-devkit-{frida_version}-{host_os}-{host_arch}.tar.xz");
    let url = format!(
        "https://github.com/frida/frida/releases/download/{frida_version}/{archive_name}"
    );

    // 6. Prepare cache directory
    let cache_dir = workspace.join("target").join("xtask-cache");
    fs::create_dir_all(&cache_dir)
        .with_context(|| format!("failed to create cache dir {}", cache_dir.display()))?;
    let archive_path = cache_dir.join(&archive_name);

    // 7. Download (or skip if cached)
    download_file(&url, &archive_path)?;

    // 8. Extract
    let extract_dir = cache_dir.join(format!(
        "extracted-{frida_version}-{host_os}-{host_arch}"
    ));
    extract_tar_xz(&archive_path, &extract_dir)?;

    // 9. Copy libfrida-core.a and frida-core.h into frida-sys dir
    let lib_src = extract_dir.join("libfrida-core.a");
    let header_src = extract_dir.join("frida-core.h");

    if !lib_src.exists() {
        bail!(
            "expected libfrida-core.a not found in extracted archive at {}",
            lib_src.display()
        );
    }
    if !header_src.exists() {
        bail!(
            "expected frida-core.h not found in extracted archive at {}",
            header_src.display()
        );
    }

    copy_file(&lib_src, &frida_sys_dir.join("libfrida-core.a"))?;
    copy_file(&header_src, &frida_sys_dir.join("frida-core.h"))?;

    println!();
    println!("[xtask] Frida devkit setup complete!");
    println!("[xtask] libfrida-core.a and frida-core.h installed into:");
    println!("[xtask]   {}", frida_sys_dir.display());
    println!();
    println!("[xtask] Next step: run `cargo xtask build` to compile memslicer.");

    Ok(())
}

fn cmd_build() -> Result<()> {
    let workspace = workspace_root()?;

    // 1. Find frida-sys directory
    let frida_sys_dir = find_frida_sys_dir()?;
    println!("[xtask] Found frida-sys at: {}", frida_sys_dir.display());

    // 2. Verify libfrida-core.a exists
    let lib_path = frida_sys_dir.join("libfrida-core.a");
    if !lib_path.exists() {
        bail!(
            "libfrida-core.a not found in {}.\n\
             Please run `cargo xtask setup` first to download and install the Frida devkit.",
            frida_sys_dir.display()
        );
    }
    println!("[xtask] Verified libfrida-core.a exists.");

    // 3. Build memslicer with BINDGEN_EXTRA_CLANG_ARGS
    let clang_args = format!("-I{}", frida_sys_dir.display());
    println!("[xtask] Setting BINDGEN_EXTRA_CLANG_ARGS={clang_args}");
    println!("[xtask] Running `cargo build --release -p memslicer`...");

    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg("memslicer")
        .env("BINDGEN_EXTRA_CLANG_ARGS", &clang_args)
        .current_dir(&workspace)
        .status()
        .context("failed to run `cargo build`")?;

    if !status.success() {
        bail!("`cargo build --release -p memslicer` failed with exit code: {status}");
    }

    println!("[xtask] Build complete!");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            os,
            arch,
            frida_version,
        } => cmd_setup(os, arch, frida_version),
        Commands::Build => cmd_build(),
    }
}
