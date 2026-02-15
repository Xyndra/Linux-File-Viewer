//! Build script to embed the Windows manifest for administrator privileges
//!
//! The manifest is only embedded for release builds to allow `cargo run` to work
//! in debug mode without requiring an elevated command prompt.

fn main() {
    // Only run on Windows
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        // Only embed the manifest for release builds
        // This allows `cargo run` to work in debug mode without elevation
        let profile = std::env::var("PROFILE").unwrap_or_default();

        if profile == "release" {
            // Embed the manifest file for release builds
            let mut res = winresource::WindowsResource::new();
            res.set_manifest_file("app.manifest");

            // Set application icon (optional - uncomment if you have an icon)
            // res.set_icon("app.ico");

            if let Err(e) = res.compile() {
                eprintln!("Warning: Failed to compile Windows resources: {}", e);
            }
        } else {
            // For debug builds, print a note
            println!("cargo:warning=Debug build: manifest not embedded. Run as Administrator manually if needed for raw disk access.");
        }
    }
}
