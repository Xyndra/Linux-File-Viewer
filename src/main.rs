//! Linux File Explorer
//!
//! A Windows application for browsing both Windows and Linux filesystems.
//!
//! This application provides access to:
//! - Native Windows drives (NTFS, FAT32, exFAT, etc.)
//! - Linux filesystems (ext4, btrfs) on raw partitions
//! - LUKS-encrypted Linux partitions
//!
//! Note: Accessing Linux partitions requires running as Administrator.
//! The application will request elevation on startup if needed.

// Hide the console window when launched by double-clicking the exe.
// When launched from an existing console (e.g. `cargo run --release`), the
// console remains visible because it's already attached.
#![windows_subsystem = "windows"]

mod fs;
mod ui;

use eframe::egui;

/// Check if the current process is running with administrator privileges
fn is_running_as_admin() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Restart the current process with administrator privileges using ShellExecuteW "runas".
/// Returns true if the elevation was initiated (caller should exit).
fn restart_as_admin() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let exe_path_str = exe_path.to_string_lossy();

    let operation: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = format!("{}\0", exe_path_str).encode_utf16().collect();

    // Forward any command-line arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");
    let parameters: Vec<u16> = format!("{}\0", args_str).encode_utf16().collect();

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );

        // ShellExecuteW returns a value > 32 on success
        result.0 as isize > 32
    }
}

fn main() -> eframe::Result<()> {
    #[cfg(debug_assertions)]
    {
        // SAFETY: This is only called once at startup before any threads are spawned
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    // Request elevation if not already running as admin
    if !is_running_as_admin() {
        if restart_as_admin() {
            // The elevated process has been spawned — exit this one
            std::process::exit(0);
        }
        // If the user cancelled the UAC prompt or it failed, continue
        // without admin. Windows filesystem browsing will still work,
        // but raw disk access for Linux partitions will not.
        eprintln!(
            "Warning: not running as Administrator. Linux partition access will not be available."
        );
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Linux File Explorer")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Linux File Explorer",
        options,
        Box::new(|cc| Ok(Box::new(ui::FileExplorerApp::new(cc)))),
    )
}
