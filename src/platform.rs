use libmsl::{ArchType, OsType};

/// Detect architecture from a Frida arch string.
pub fn detect_arch(arch_str: &str) -> anyhow::Result<ArchType> {
    match arch_str {
        "ia32" => Ok(ArchType::X86),
        "x64" => Ok(ArchType::X86_64),
        "arm" => Ok(ArchType::ARM32),
        "arm64" => Ok(ArchType::ARM64),
        other => anyhow::bail!("unknown architecture: {}", other),
    }
}

/// Detect OS type from platform string and loaded modules.
///
/// `os_override` takes precedence if `Some`.
/// `platform_str` is Frida's `Process.platform`: `"darwin"`, `"linux"`, `"windows"`.
/// `module_paths` is a list of module file paths used for heuristic detection
/// (e.g. distinguishing iOS from macOS or Android from Linux).
pub fn detect_os(
    platform_str: &str,
    module_paths: &[&str],
    os_override: Option<&str>,
) -> anyhow::Result<OsType> {
    if let Some(ov) = os_override {
        return match ov {
            "windows" => Ok(OsType::Windows),
            "linux" => Ok(OsType::Linux),
            "macos" => Ok(OsType::MacOS),
            "android" => Ok(OsType::Android),
            "ios" => Ok(OsType::IOS),
            other => anyhow::bail!("unknown OS override: {}", other),
        };
    }

    match platform_str {
        "darwin" => {
            let is_ios = module_paths.iter().any(|p| {
                p.contains("UIKit") || p.contains("iPhoneOS") || p.contains("Xcode.app")
            });
            if is_ios {
                Ok(OsType::IOS)
            } else {
                Ok(OsType::MacOS)
            }
        }
        "linux" => {
            let is_android = module_paths.iter().any(|p| {
                p.contains("libandroid_runtime.so")
                    || p.contains("libart.so")
                    || is_android_linker(p)
            });
            if is_android {
                Ok(OsType::Android)
            } else {
                Ok(OsType::Linux)
            }
        }
        "windows" => Ok(OsType::Windows),
        other => anyhow::bail!("unknown platform: {}", other),
    }
}

/// Check whether a module path refers to the Android linker.
///
/// Matches paths whose filename component is exactly `"linker"` or `"linker64"`.
fn is_android_linker(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename == "linker" || filename == "linker64"
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // detect_arch
    // -----------------------------------------------------------------------

    #[test]
    fn arch_ia32() {
        assert_eq!(detect_arch("ia32").unwrap(), ArchType::X86);
    }

    #[test]
    fn arch_x64() {
        assert_eq!(detect_arch("x64").unwrap(), ArchType::X86_64);
    }

    #[test]
    fn arch_arm() {
        assert_eq!(detect_arch("arm").unwrap(), ArchType::ARM32);
    }

    #[test]
    fn arch_arm64() {
        assert_eq!(detect_arch("arm64").unwrap(), ArchType::ARM64);
    }

    #[test]
    fn arch_unknown() {
        assert!(detect_arch("mips").is_err());
    }

    // -----------------------------------------------------------------------
    // detect_os – override
    // -----------------------------------------------------------------------

    #[test]
    fn os_override_windows() {
        assert_eq!(
            detect_os("linux", &[], Some("windows")).unwrap(),
            OsType::Windows,
        );
    }

    #[test]
    fn os_override_linux() {
        assert_eq!(
            detect_os("darwin", &[], Some("linux")).unwrap(),
            OsType::Linux,
        );
    }

    #[test]
    fn os_override_macos() {
        assert_eq!(
            detect_os("linux", &[], Some("macos")).unwrap(),
            OsType::MacOS,
        );
    }

    #[test]
    fn os_override_android() {
        assert_eq!(
            detect_os("darwin", &[], Some("android")).unwrap(),
            OsType::Android,
        );
    }

    #[test]
    fn os_override_ios() {
        assert_eq!(
            detect_os("linux", &[], Some("ios")).unwrap(),
            OsType::IOS,
        );
    }

    #[test]
    fn os_override_unknown() {
        assert!(detect_os("linux", &[], Some("haiku")).is_err());
    }

    // -----------------------------------------------------------------------
    // detect_os – darwin
    // -----------------------------------------------------------------------

    #[test]
    fn darwin_defaults_to_macos() {
        let modules = &["/usr/lib/libSystem.B.dylib"];
        assert_eq!(detect_os("darwin", modules, None).unwrap(), OsType::MacOS);
    }

    #[test]
    fn darwin_uikit_means_ios() {
        let modules = &[
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            "/usr/lib/libSystem.B.dylib",
        ];
        assert_eq!(detect_os("darwin", modules, None).unwrap(), OsType::IOS);
    }

    #[test]
    fn darwin_iphoneos_means_ios() {
        let modules =
            &["/Library/Developer/iPhoneOS.platform/some.dylib"];
        assert_eq!(detect_os("darwin", modules, None).unwrap(), OsType::IOS);
    }

    #[test]
    fn darwin_xcode_means_ios() {
        let modules = &["/Applications/Xcode.app/Contents/some.dylib"];
        assert_eq!(detect_os("darwin", modules, None).unwrap(), OsType::IOS);
    }

    // -----------------------------------------------------------------------
    // detect_os – linux
    // -----------------------------------------------------------------------

    #[test]
    fn linux_defaults_to_linux() {
        let modules = &["/usr/lib/libc.so.6"];
        assert_eq!(detect_os("linux", modules, None).unwrap(), OsType::Linux);
    }

    #[test]
    fn linux_linker64_means_android() {
        let modules = &["/system/bin/linker64"];
        assert_eq!(
            detect_os("linux", modules, None).unwrap(),
            OsType::Android,
        );
    }

    #[test]
    fn linux_linker_means_android() {
        let modules = &["/system/bin/linker"];
        assert_eq!(
            detect_os("linux", modules, None).unwrap(),
            OsType::Android,
        );
    }

    #[test]
    fn linux_linker_substring_not_matched() {
        // A path that *contains* "linker" as a substring but is not the
        // standalone filename should NOT trigger Android detection.
        let modules = &["/usr/lib/liblinker_utils.so"];
        assert_eq!(detect_os("linux", modules, None).unwrap(), OsType::Linux);
    }

    #[test]
    fn linux_libandroid_runtime_means_android() {
        let modules = &["/system/lib64/libandroid_runtime.so"];
        assert_eq!(
            detect_os("linux", modules, None).unwrap(),
            OsType::Android,
        );
    }

    #[test]
    fn linux_libart_means_android() {
        let modules = &["/apex/com.android.art/lib64/libart.so"];
        assert_eq!(
            detect_os("linux", modules, None).unwrap(),
            OsType::Android,
        );
    }

    // -----------------------------------------------------------------------
    // detect_os – windows
    // -----------------------------------------------------------------------

    #[test]
    fn windows_platform() {
        assert_eq!(
            detect_os("windows", &[], None).unwrap(),
            OsType::Windows,
        );
    }

    // -----------------------------------------------------------------------
    // detect_os – unknown platform
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_platform() {
        assert!(detect_os("freebsd", &[], None).is_err());
    }
}
