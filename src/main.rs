//! Linux File Viewer
//!
//! A Windows application for browsing both Windows and Linux filesystems.
//!
//! This application provides read-only access to:
//! - Native Windows drives (NTFS, FAT32, exFAT, etc.)
//! - Linux filesystems (ext4, btrfs) on raw partitions
//! - LUKS-encrypted Linux partitions
//!
//! Note: Accessing Linux partitions requires running as Administrator.
//! The application will automatically request elevation if needed.

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

        // Open the process token
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

        // Close the token handle
        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Restart the current process with administrator privileges
/// Returns true if the elevation was initiated (process should exit)
/// Returns false if elevation failed or was cancelled
fn restart_as_admin() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Get the current executable path
    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let exe_path_str = exe_path.to_string_lossy();

    // Convert strings to wide (UTF-16) format
    let operation: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = format!("{}\0", exe_path_str).encode_utf16().collect();

    // Get command line arguments (skip the executable name)
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

/// Show a message box with an error
fn show_error_message(title: &str, message: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        MessageBoxW(
            None,
            PCWSTR(message_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

/// Check if --no-admin-check flag is present (debug builds only)
fn should_skip_admin_check() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::args().any(|arg| arg == "--no-admin-check" || arg == "-n")
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn main() -> eframe::Result<()> {
    // Set up logging for debug builds
    #[cfg(debug_assertions)]
    {
        // SAFETY: This is only called once at startup before any threads are spawned
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    // Check for administrator privileges (can be skipped in debug builds)
    let skip_admin_check = should_skip_admin_check();

    if !skip_admin_check && !is_running_as_admin() {
        // Try to restart with admin privileges
        if restart_as_admin() {
            // Elevation initiated, exit current process
            std::process::exit(0);
        } else {
            // Elevation failed or was cancelled by user
            show_error_message(
                "Administrator Privileges Required",
                "Linux File Viewer requires administrator privileges to access raw disk partitions.\n\n\
                 The UAC elevation request was cancelled or failed.\n\n\
                 Please try running the application again and accept the UAC prompt,\n\
                 or right-click the application and select 'Run as administrator'.\n\n\
                 The application will now exit."
            );
            std::process::exit(1);
        }
    }

    #[cfg(debug_assertions)]
    if skip_admin_check {
        eprintln!("Warning: Running without admin check. Linux partition access will not work.");
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Linux File Viewer")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Linux File Viewer",
        options,
        Box::new(|cc| Ok(Box::new(ui::FileViewerApp::new(cc)))),
    )
}
