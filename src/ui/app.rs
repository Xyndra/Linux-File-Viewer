//! Main application state and UI
//!
//! This module contains the main application struct that manages filesystems
//! and renders the main UI.

use std::sync::Arc;

use eframe::egui;
use egui::{CentralPanel, Context, RichText, SidePanel, TopBottomPanel};
use std::path::Path;

use crate::fs::btrfs_fs::{BtrfsFs, BTRFS_SUPERBLOCK_OFFSET};
use crate::fs::disk::{
    detect_partitions, enumerate_physical_drives, get_partition_geometry, is_potentially_ext4,
    RawDisk,
};
use crate::fs::linux_fs::{LinuxFs, PartitionReader};
use crate::fs::luks::{is_luks, LuksReader};
use crate::fs::windows_fs::WindowsFs;
use crate::fs::{DetectedFsType, FsEntry, MountedFs, PartitionInfo};

use super::file_browser::{FileBrowser, FileBrowserAction};

/// The main file explorer application
pub struct FileExplorerApp {
    /// Available filesystems
    filesystems: Vec<FilesystemEntry>,
    /// Currently selected filesystem index
    selected_fs: usize,
    /// File browser instance
    browser: FileBrowser,
    /// File preview content
    preview_content: Option<PreviewContent>,
    /// Status message
    status_message: Option<StatusMessage>,
    /// Detected partitions that could be mounted
    detected_partitions: Vec<DetectedPartition>,
    /// All detected partitions (for debugging)
    all_detected_partitions: Vec<(u32, PartitionInfo)>,
    /// Whether the partition scan has been performed
    partitions_scanned: bool,
    /// Whether to show all partitions (debug mode)
    show_all_partitions: bool,
    /// LUKS password dialog state
    luks_dialog: Option<LuksDialogState>,
    /// Clipboard for copy/cut/paste operations
    clipboard: Option<Clipboard>,
}

/// Clipboard operation kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClipboardOp {
    Copy,
    Cut,
}

/// Clipboard contents — entries and their source filesystem
#[derive(Debug, Clone)]
struct Clipboard {
    /// The operation (copy or cut)
    op: ClipboardOp,
    /// Index of the source filesystem these entries came from
    source_fs: usize,
    /// The entries on the clipboard
    entries: Vec<FsEntry>,
}

/// An entry in the filesystem list
struct FilesystemEntry {
    /// Display name
    name: String,
    /// The mounted filesystem
    fs: MountedFs,
    /// Icon for the filesystem type
    icon: &'static str,
}

/// Information about a detected but not mounted partition
#[derive(Clone)]
struct DetectedPartition {
    drive_number: u32,
    partition: PartitionInfo,
    offset: u64,
    size: u64,
    /// Detected filesystem type
    fs_type: DetectedFsType,
}

/// Content being previewed
enum PreviewContent {
    Text(String),
    Image(egui::TextureHandle),
    Binary { size: u64, hex_preview: String },
    Error(String),
}

/// Status message to display
struct StatusMessage {
    text: String,
    is_error: bool,
}

/// LUKS password dialog state
struct LuksDialogState {
    /// The partition we're trying to unlock
    partition: DetectedPartition,
    /// Password input
    password: String,
    /// Error message from last attempt
    error: Option<String>,
}

impl FileExplorerApp {
    /// Create a new application instance
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load Windows system fonts: Segoe UI for text, Segoe UI Symbol for
        // icons/symbols.  We replace egui's default font list entirely so that
        // the built-in NotoEmoji (B&W emoji) never appears.
        let mut fonts = egui::FontDefinitions::default();

        // Remove the bundled emoji font so we never fall back to it
        fonts.font_data.remove("emoji-icon-font");

        if let Ok(data) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts.font_data.insert(
                "segoe_ui".into(),
                Arc::new(egui::FontData::from_owned(data)),
            );
        }
        if let Ok(data) = std::fs::read("C:\\Windows\\Fonts\\seguisym.ttf") {
            fonts.font_data.insert(
                "segoe_symbol".into(),
                Arc::new(egui::FontData::from_owned(data)),
            );
        }

        // Proportional: Segoe UI first, then Segoe UI Symbol for glyphs
        // Segoe UI doesn't cover, then whatever egui defaults remain.
        if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            list.retain(|name| name != "emoji-icon-font");
            list.insert(0, "segoe_symbol".into());
            list.insert(0, "segoe_ui".into());
        }
        // Monospace: keep egui's default mono font first, add Segoe UI as
        // fallback so symbols still render.
        if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            list.retain(|name| name != "emoji-icon-font");
            list.push("segoe_ui".into());
            list.push("segoe_symbol".into());
        }

        cc.egui_ctx.set_fonts(fonts);

        let mut app = Self {
            filesystems: Vec::new(),
            selected_fs: 0,
            browser: FileBrowser::new(),
            preview_content: None,
            status_message: None,
            detected_partitions: Vec::new(),
            all_detected_partitions: Vec::new(),
            partitions_scanned: false,
            show_all_partitions: false,
            luks_dialog: None,
            clipboard: None,
        };

        // Add Windows filesystem by default
        app.add_windows_filesystem();

        // Navigate to first root
        if let Some(entry) = app.filesystems.first() {
            if let Ok(roots) = entry.fs.roots() {
                if let Some(root) = roots.first() {
                    app.browser.navigate_to(root, &entry.fs);
                }
            }
        }

        app
    }

    /// Add the Windows filesystem
    fn add_windows_filesystem(&mut self) {
        let windows_fs = WindowsFs::new();

        // Add each Windows drive as a separate entry, or one unified entry
        self.filesystems.push(FilesystemEntry {
            name: "Windows".to_string(),
            fs: MountedFs::Windows(windows_fs),
            icon: "\u{229E}", // ⊞
        });
    }

    /// Probe a partition to detect its filesystem type
    fn probe_partition_type(drive_number: u32, offset: u64, _size: u64) -> DetectedFsType {
        // Try to open the partition and probe for filesystem types
        let mut disk = match RawDisk::open_physical_drive(drive_number) {
            Ok(d) => d,
            Err(_) => return DetectedFsType::Unknown,
        };

        // Read the first few KB to probe
        let mut probe_buffer = vec![0u8; 128 * 1024]; // 128 KB
        if disk.read_at(offset, &mut probe_buffer).is_err() {
            return DetectedFsType::Unknown;
        }

        // Check for LUKS magic
        if is_luks(&probe_buffer) {
            let version = u16::from_be_bytes([probe_buffer[6], probe_buffer[7]]);
            return DetectedFsType::Luks { version };
        }

        // Check for btrfs magic (at offset 0x10000 = 64KB within partition)
        // We need to read at the correct offset
        let btrfs_offset = offset + BTRFS_SUPERBLOCK_OFFSET;
        let mut btrfs_probe = vec![0u8; 4096];
        if disk.read_at(btrfs_offset, &mut btrfs_probe).is_ok() {
            // Check for btrfs magic at offset 0x40 within superblock
            if btrfs_probe.len() >= 0x48 && &btrfs_probe[0x40..0x48] == b"_BHRfS_M" {
                return DetectedFsType::Btrfs;
            }
        }

        // Check for ext4 superblock magic at offset 1024 (0x400)
        // Ext4 magic is 0xEF53 at offset 0x38 within superblock
        let ext_sb_offset = 1024;
        if probe_buffer.len() >= ext_sb_offset + 0x40 {
            let magic = u16::from_le_bytes([
                probe_buffer[ext_sb_offset + 0x38],
                probe_buffer[ext_sb_offset + 0x39],
            ]);
            if magic == 0xEF53 {
                return DetectedFsType::Ext4;
            }
        }

        DetectedFsType::Unknown
    }

    /// Scan for Linux partitions
    fn scan_for_partitions(&mut self) {
        self.detected_partitions.clear();
        self.all_detected_partitions.clear();
        self.partitions_scanned = true;

        let drives = enumerate_physical_drives();
        let mut all_partitions_found = 0;
        let mut linux_partitions_found = 0;
        let mut scan_errors: Vec<String> = Vec::new();

        for drive_number in drives {
            match detect_partitions(drive_number) {
                Ok(partitions) => {
                    all_partitions_found += partitions.len();

                    // Store all partitions for debugging
                    for part_info in &partitions {
                        self.all_detected_partitions
                            .push((drive_number, part_info.clone()));
                    }

                    for part_info in &partitions {
                        // Check if this could be a Linux partition
                        if is_potentially_ext4(part_info) {
                            linux_partitions_found += 1;

                            // Get the partition geometry (offset and size)
                            match get_partition_geometry(drive_number, part_info.partition_number) {
                                Ok((offset, size)) => {
                                    // Probe the actual filesystem type
                                    let fs_type =
                                        Self::probe_partition_type(drive_number, offset, size);

                                    self.detected_partitions.push(DetectedPartition {
                                        drive_number,
                                        partition: part_info.clone(),
                                        offset,
                                        size,
                                        fs_type,
                                    });
                                }
                                Err(e) => {
                                    scan_errors.push(format!(
                                        "Drive {} partition {}: {}",
                                        drive_number, part_info.partition_number, e
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    scan_errors.push(format!("Drive {}: {}", drive_number, e));
                    continue;
                }
            }
        }

        // Build status message
        let status_text = if self.detected_partitions.is_empty() {
            if all_partitions_found == 0 {
                "No partitions found. Make sure you're running as Administrator.".to_string()
            } else if linux_partitions_found == 0 {
                format!(
                    "Found {} partition(s) but none are Linux filesystems.",
                    all_partitions_found
                )
            } else {
                format!(
                    "Found {} Linux partition(s) but couldn't read geometry. Errors: {:?}",
                    linux_partitions_found, scan_errors
                )
            }
        } else {
            let luks_count = self
                .detected_partitions
                .iter()
                .filter(|p| matches!(p.fs_type, DetectedFsType::Luks { .. }))
                .count();
            let btrfs_count = self
                .detected_partitions
                .iter()
                .filter(|p| p.fs_type == DetectedFsType::Btrfs)
                .count();
            let ext4_count = self
                .detected_partitions
                .iter()
                .filter(|p| p.fs_type == DetectedFsType::Ext4)
                .count();

            let mut parts = Vec::new();
            if ext4_count > 0 {
                parts.push(format!("{} ext4", ext4_count));
            }
            if btrfs_count > 0 {
                parts.push(format!("{} btrfs", btrfs_count));
            }
            if luks_count > 0 {
                parts.push(format!("{} LUKS", luks_count));
            }

            format!(
                "Found {} Linux partition(s): {}",
                self.detected_partitions.len(),
                parts.join(", ")
            )
        };

        self.status_message = Some(StatusMessage {
            text: status_text,
            is_error: self.detected_partitions.is_empty() && linux_partitions_found > 0,
        });
    }

    /// Get a display string for the filesystem type
    fn fs_type_display(fs_type: &DetectedFsType) -> &'static str {
        match fs_type {
            DetectedFsType::Ext4 => "ext4",
            DetectedFsType::Btrfs => "btrfs",
            DetectedFsType::Luks { version: 1 } => "LUKS1",
            DetectedFsType::Luks { version: 2 } => "LUKS2",
            DetectedFsType::Luks { .. } => "LUKS",
            DetectedFsType::Unknown => "unknown",
        }
    }

    /// Mount a detected Linux partition
    fn mount_partition(&mut self, partition: &DetectedPartition) {
        match &partition.fs_type {
            DetectedFsType::Luks { .. } => {
                // Show password dialog
                self.luks_dialog = Some(LuksDialogState {
                    partition: partition.clone(),
                    password: String::new(),
                    error: None,
                });
            }
            DetectedFsType::Btrfs => {
                self.mount_btrfs_partition(partition);
            }
            DetectedFsType::Ext4 | DetectedFsType::Unknown => {
                // Try ext4 first, then btrfs as fallback
                self.mount_ext4_partition(partition);
            }
        }
    }

    /// Mount an ext4 partition
    fn mount_ext4_partition(&mut self, partition: &DetectedPartition) {
        let reader = match PartitionReader::open_partition(
            partition.drive_number,
            partition.offset,
            partition.size,
        ) {
            Ok(r) => r,
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to open partition: {}", e),
                    is_error: true,
                });
                return;
            }
        };

        let label =
            partition.partition.label.clone().unwrap_or_else(|| {
                format!("Linux Partition {}", partition.partition.partition_number)
            });

        match LinuxFs::new(reader, Some(label.clone())) {
            Ok(linux_fs) => {
                self.filesystems.push(FilesystemEntry {
                    name: label,
                    fs: MountedFs::Linux(linux_fs),
                    icon: "\u{1F427}", // penguin
                });

                self.status_message = Some(StatusMessage {
                    text: "ext4 partition mounted successfully".to_string(),
                    is_error: false,
                });

                // Switch to the new filesystem
                self.selected_fs = self.filesystems.len() - 1;
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.navigate_to_root(&entry.fs);
                }
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to mount partition: {}", e),
                    is_error: true,
                });
            }
        }
    }

    /// Mount a btrfs partition
    fn mount_btrfs_partition(&mut self, partition: &DetectedPartition) {
        let reader = match PartitionReader::open_partition(
            partition.drive_number,
            partition.offset,
            partition.size,
        ) {
            Ok(r) => r,
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to open partition: {}", e),
                    is_error: true,
                });
                return;
            }
        };

        let label =
            partition.partition.label.clone().unwrap_or_else(|| {
                format!("Btrfs Partition {}", partition.partition.partition_number)
            });

        match BtrfsFs::new(reader, Some(label.clone())) {
            Ok(btrfs_fs) => {
                self.filesystems.push(FilesystemEntry {
                    name: label,
                    fs: MountedFs::Btrfs(Box::new(btrfs_fs) as Box<dyn crate::fs::BtrfsFsOps>),
                    icon: "\u{2663}", // ♣
                });

                self.status_message = Some(StatusMessage {
                    text: "btrfs partition mounted successfully".to_string(),
                    is_error: false,
                });

                // Switch to the new filesystem
                self.selected_fs = self.filesystems.len() - 1;
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.navigate_to_root(&entry.fs);
                }
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to mount btrfs partition: {}", e),
                    is_error: true,
                });
            }
        }
    }

    /// Try to unlock a LUKS partition with the given password
    fn try_unlock_luks(
        &mut self,
        partition: &DetectedPartition,
        password: &str,
    ) -> Result<(), String> {
        // Open the raw disk
        let disk = RawDisk::open_physical_drive(partition.drive_number)
            .map_err(|e| format!("Failed to open drive: {}", e))?;

        // Create LUKS reader
        let mut luks_reader = LuksReader::open(disk, partition.offset)
            .map_err(|e| format!("Failed to read LUKS header: {}", e))?;

        // Try to unlock
        let unlocked = luks_reader
            .unlock(password)
            .map_err(|e| format!("Failed to unlock: {}", e))?;

        if !unlocked {
            return Err("Incorrect password".to_string());
        }

        // Create decrypted reader
        let decrypted_reader = crate::fs::luks::DecryptedLuksReader::new(luks_reader)
            .map_err(|e| format!("Failed to create decrypted reader: {}", e))?;

        // Probe the decrypted filesystem
        // Read some data to check the filesystem type
        let mut probe_reader = decrypted_reader;

        // Check for btrfs first (at offset 64KB)
        use std::io::{Read, Seek, SeekFrom};
        probe_reader
            .seek(SeekFrom::Start(BTRFS_SUPERBLOCK_OFFSET))
            .map_err(|e| format!("Seek failed: {}", e))?;

        let mut btrfs_probe = [0u8; 0x48];
        if probe_reader.read(&mut btrfs_probe).is_ok() && &btrfs_probe[0x40..0x48] == b"_BHRfS_M" {
            // It's btrfs!
            // Reset position
            probe_reader
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("Seek failed: {}", e))?;

            let label = partition.partition.label.clone().unwrap_or_else(|| {
                format!(
                    "LUKS+Btrfs Partition {}",
                    partition.partition.partition_number
                )
            });

            let btrfs_fs = BtrfsFs::new(probe_reader, Some(label.clone()))
                .map_err(|e| format!("Failed to mount btrfs: {}", e))?;

            self.filesystems.push(FilesystemEntry {
                name: label,
                fs: MountedFs::Btrfs(Box::new(btrfs_fs) as Box<dyn crate::fs::BtrfsFsOps>),
                icon: "\u{1F513}", // unlocked
            });

            self.status_message = Some(StatusMessage {
                text: "LUKS+btrfs partition unlocked and mounted successfully".to_string(),
                is_error: false,
            });

            // Switch to the new filesystem
            self.selected_fs = self.filesystems.len() - 1;
            if let Some(entry) = self.filesystems.get(self.selected_fs) {
                self.browser.navigate_to_root(&entry.fs);
            }

            return Ok(());
        }

        // Check for ext4 (superblock at offset 1024)
        probe_reader
            .seek(SeekFrom::Start(1024))
            .map_err(|e| format!("Seek failed: {}", e))?;

        let mut ext4_probe = [0u8; 0x40];
        if probe_reader.read(&mut ext4_probe).is_ok() {
            let magic = u16::from_le_bytes([ext4_probe[0x38], ext4_probe[0x39]]);
            if magic == 0xEF53 {
                // It's ext4 - but we need a PartitionReader for LinuxFs
                // For now, report that ext4 inside LUKS is not yet fully supported
                return Err("ext4 inside LUKS detected but not yet fully supported. Btrfs inside LUKS is supported.".to_string());
            }
        }

        Err("Unknown filesystem inside LUKS container".to_string())
    }

    /// Handle file preview request
    fn preview_file(&mut self, path: &str, ctx: &Context) {
        let Some(entry) = self.filesystems.get(self.selected_fs) else {
            return;
        };

        match entry.fs.read_file(path) {
            Ok(data) => {
                self.preview_content = Some(Self::create_preview(&data, path, ctx));
            }
            Err(e) => {
                self.preview_content =
                    Some(PreviewContent::Error(format!("Failed to read file: {}", e)));
            }
        }
    }

    /// Create preview content from file data
    fn create_preview(data: &[u8], path: &str, ctx: &Context) -> PreviewContent {
        let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();

        // Try to load as image
        if matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico") {
            if let Ok(image) = image::load_from_memory(data) {
                let size = [image.width() as usize, image.height() as usize];
                let rgba = image.to_rgba8();
                let pixels = rgba.as_flat_samples();

                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

                let texture = ctx.load_texture(path, color_image, egui::TextureOptions::default());

                return PreviewContent::Image(texture);
            }
        }

        // Try to interpret as text
        if let Ok(text) = String::from_utf8(data.to_vec()) {
            // Limit text preview size
            let preview = if text.len() > 100_000 {
                format!(
                    "{}\n\n... [File truncated, showing first 100KB of {} total]",
                    &text[..100_000],
                    humansize::format_size(data.len() as u64, humansize::BINARY)
                )
            } else {
                text
            };
            return PreviewContent::Text(preview);
        }

        // Binary file
        let hex_preview: String = data
            .iter()
            .take(256)
            .enumerate()
            .map(|(i, b)| {
                if i > 0 && i % 16 == 0 {
                    format!("\n{:02X}", b)
                } else if i > 0 && i % 8 == 0 {
                    format!("  {:02X}", b)
                } else if i > 0 {
                    format!(" {:02X}", b)
                } else {
                    format!("{:02X}", b)
                }
            })
            .collect();

        PreviewContent::Binary {
            size: data.len() as u64,
            hex_preview,
        }
    }

    /// Render the LUKS password dialog
    fn render_luks_dialog(&mut self, ctx: &Context) {
        let mut close_dialog = false;
        let mut try_unlock = false;

        if let Some(ref mut dialog) = self.luks_dialog {
            egui::Window::new("\u{1F512} LUKS Encrypted Partition")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical(|ui| {
                        // Show partition info
                        let label = dialog
                            .partition
                            .partition
                            .label
                            .as_deref()
                            .unwrap_or("Unnamed");
                        let size = humansize::format_size(dialog.partition.size, humansize::BINARY);

                        ui.label(format!("Partition: {}", label));
                        ui.label(format!(
                            "Drive {} • Partition {} • {}",
                            dialog.partition.drive_number,
                            dialog.partition.partition.partition_number,
                            size
                        ));
                        ui.label(format!(
                            "Encryption: {}",
                            Self::fs_type_display(&dialog.partition.fs_type)
                        ));

                        ui.separator();

                        // Error message
                        if let Some(ref error) = dialog.error {
                            ui.colored_label(egui::Color32::RED, error);
                            ui.separator();
                        }

                        // Password input
                        ui.label("Enter password:");
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut dialog.password)
                                .password(true)
                                .desired_width(300.0),
                        );

                        // Enter key triggers unlock
                        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            try_unlock = true;
                        }

                        ui.separator();

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                close_dialog = true;
                            }

                            if ui.button("Unlock").clicked() {
                                try_unlock = true;
                            }
                        });
                    });
                });
        }

        if try_unlock {
            if let Some(ref dialog) = self.luks_dialog {
                let partition = dialog.partition.clone();
                let password = dialog.password.clone();

                match self.try_unlock_luks(&partition, &password) {
                    Ok(()) => {
                        close_dialog = true;
                    }
                    Err(e) => {
                        if let Some(ref mut dialog) = self.luks_dialog {
                            dialog.error = Some(e);
                            dialog.password.clear();
                        }
                    }
                }
            }
        }

        if close_dialog {
            self.luks_dialog = None;
        }
    }

    /// Render the sidebar with filesystem list
    fn render_sidebar(&mut self, ctx: &Context) {
        SidePanel::left("filesystem_panel")
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.heading("Filesystems");
                ui.separator();

                // Filesystem list
                let mut new_selected = self.selected_fs;

                for (idx, entry) in self.filesystems.iter().enumerate() {
                    let is_selected = idx == self.selected_fs;
                    let text = format!("{} {}", entry.icon, entry.name);

                    if ui.selectable_label(is_selected, text).clicked() {
                        new_selected = idx;
                    }
                }

                if new_selected != self.selected_fs {
                    self.selected_fs = new_selected;
                    self.preview_content = None;
                    if let Some(entry) = self.filesystems.get(self.selected_fs) {
                        self.browser.navigate_to_root(&entry.fs);
                    }
                }

                ui.separator();

                // Linux partition controls
                ui.heading("Linux Partitions");

                if ui.button("Scan for partitions").clicked() {
                    self.scan_for_partitions();
                }

                if !self.detected_partitions.is_empty() {
                    ui.separator();
                    ui.label(format!(
                        "Detected partitions ({}):",
                        self.detected_partitions.len()
                    ));

                    let partitions = self.detected_partitions.clone();
                    for partition in &partitions {
                        let label = partition.partition.label.as_deref().unwrap_or("Unnamed");
                        let size = humansize::format_size(partition.size, humansize::BINARY);

                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                let icon = match &partition.fs_type {
                                    DetectedFsType::Luks { .. } => "\u{1F512}",
                                    DetectedFsType::Btrfs => "\u{2663}",
                                    _ => "\u{1F427}",
                                };
                                ui.label(format!("{} {}", icon, label));
                                ui.label(
                                    RichText::new(format!(
                                        "Drive {} • Part {} • {}",
                                        partition.drive_number,
                                        partition.partition.partition_number,
                                        size
                                    ))
                                    .small()
                                    .weak(),
                                );
                                ui.label(
                                    RichText::new(Self::fs_type_display(&partition.fs_type))
                                        .small()
                                        .weak(),
                                );

                                let button_text = match &partition.fs_type {
                                    DetectedFsType::Luks { .. } => "Unlock",
                                    _ => "Mount",
                                };

                                if ui.button(button_text).clicked() {
                                    self.mount_partition(partition);
                                }
                            });
                        });
                    }
                } else if self.partitions_scanned {
                    ui.separator();
                    ui.label(RichText::new("No Linux partitions detected").weak());
                    ui.label(RichText::new("Try running as Administrator").small().weak());
                }

                // Debug: show all partitions toggle
                if self.partitions_scanned {
                    ui.separator();
                    ui.checkbox(&mut self.show_all_partitions, "Show all partitions (debug)");

                    if self.show_all_partitions && !self.all_detected_partitions.is_empty() {
                        ui.separator();
                        ui.label(RichText::new("All detected partitions:").strong());

                        for (drive_num, part) in &self.all_detected_partitions {
                            let size = humansize::format_size(part.size, humansize::BINARY);
                            let is_linux = is_potentially_ext4(part);

                            ui.group(|ui| {
                                ui.vertical(|ui| {
                                    let icon = if is_linux { "\u{1F427}" } else { "\u{1F5B4}" };
                                    ui.label(format!(
                                        "{} Drive {} Part {}",
                                        icon, drive_num, part.partition_number
                                    ));
                                    ui.label(RichText::new(&part.fs_type).small());
                                    ui.label(
                                        RichText::new(format!("Size: {}", size)).small().weak(),
                                    );
                                    if let Some(label) = &part.label {
                                        ui.label(
                                            RichText::new(format!("Label: {}", label))
                                                .small()
                                                .weak(),
                                        );
                                    }
                                });
                            });
                        }
                    }
                }

                // Drive roots for Windows
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    if let MountedFs::Windows(_) = &entry.fs {
                        ui.separator();
                        ui.heading("Drives");

                        if let Ok(roots) = entry.fs.roots() {
                            for root in roots {
                                if ui.button(&root).clicked() {
                                    self.browser.navigate_to(&root, &entry.fs);
                                }
                            }
                        }
                    }
                }
            });
    }

    /// Render the preview panel
    fn render_preview(&mut self, ctx: &Context) {
        if self.preview_content.is_some() {
            SidePanel::right("preview_panel")
                .default_width(400.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Preview");
                        if ui.button("\u{2716}").clicked() {
                            self.preview_content = None;
                        }
                    });
                    ui.separator();

                    match &self.preview_content {
                        Some(PreviewContent::Text(text)) => {
                            egui::ScrollArea::both().show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut text.as_str())
                                        .code_editor()
                                        .desired_width(f32::INFINITY),
                                );
                            });
                        }
                        Some(PreviewContent::Image(texture)) => {
                            egui::ScrollArea::both().show(ui, |ui| {
                                let size = texture.size_vec2();
                                let available = ui.available_size();

                                // Scale to fit
                                let scale =
                                    (available.x / size.x).min(available.y / size.y).min(1.0);
                                let display_size = size * scale;

                                ui.image((texture.id(), display_size));
                            });
                        }
                        Some(PreviewContent::Binary { size, hex_preview }) => {
                            ui.label(format!(
                                "Binary file: {}",
                                humansize::format_size(*size, humansize::BINARY)
                            ));
                            ui.separator();
                            egui::ScrollArea::both().show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut hex_preview.as_str())
                                        .code_editor()
                                        .desired_width(f32::INFINITY),
                                );
                            });
                        }
                        Some(PreviewContent::Error(e)) => {
                            ui.colored_label(egui::Color32::RED, e);
                        }
                        None => {}
                    }
                });
        }
    }

    /// Render the status bar
    fn render_status_bar(&mut self, ctx: &Context) {
        TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref msg) = self.status_message {
                    let text = RichText::new(&msg.text);
                    let text = if msg.is_error {
                        text.color(egui::Color32::RED)
                    } else {
                        text
                    };
                    ui.label(text);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(entry) = self.filesystems.get(self.selected_fs) {
                        ui.label(format!("{} {}", entry.icon, entry.name));
                    }
                });
            });
        });
    }

    // ── File operation handlers ───────────────────────────────────────

    /// Handle a `FileBrowserAction` returned by the browser widget.
    fn handle_browser_action(&mut self, action: FileBrowserAction, ctx: &Context) {
        match action {
            FileBrowserAction::OpenFile(path) => {
                self.preview_file(&path, ctx);
            }
            FileBrowserAction::CopyEntries(entries) => {
                self.clipboard = Some(Clipboard {
                    op: ClipboardOp::Copy,
                    source_fs: self.selected_fs,
                    entries,
                });
                self.status_message = Some(StatusMessage {
                    text: "Copied to clipboard".to_string(),
                    is_error: false,
                });
            }
            FileBrowserAction::CutEntries(entries) => {
                self.clipboard = Some(Clipboard {
                    op: ClipboardOp::Cut,
                    source_fs: self.selected_fs,
                    entries,
                });
                self.status_message = Some(StatusMessage {
                    text: "Cut to clipboard".to_string(),
                    is_error: false,
                });
            }
            FileBrowserAction::PasteInto(target_dir) => {
                self.paste_clipboard(&target_dir);
                // Refresh browser after paste
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.refresh(&entry.fs);
                }
            }
            FileBrowserAction::RenamePath(old_path, new_name) => {
                self.rename_entry(&old_path, &new_name);
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.refresh(&entry.fs);
                }
            }
            FileBrowserAction::DeletePath(path) => {
                self.delete_entry(&path);
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.refresh(&entry.fs);
                }
            }
            FileBrowserAction::CreateDirectory(parent, name) => {
                self.create_directory(&parent, &name);
                if let Some(entry) = self.filesystems.get(self.selected_fs) {
                    self.browser.refresh(&entry.fs);
                }
            }
        }
    }

    /// Paste clipboard contents into `target_dir`.
    fn paste_clipboard(&mut self, target_dir: &str) {
        let clipboard = match self.clipboard.clone() {
            Some(c) => c,
            None => {
                self.status_message = Some(StatusMessage {
                    text: "Nothing on the clipboard".to_string(),
                    is_error: true,
                });
                return;
            }
        };

        let dest_fs = match self.filesystems.get(self.selected_fs) {
            Some(e) => &e.fs,
            None => return,
        };

        if !dest_fs.is_writable() {
            self.status_message = Some(StatusMessage {
                text: "Destination filesystem is read-only".to_string(),
                is_error: true,
            });
            return;
        }

        let same_fs = clipboard.source_fs == self.selected_fs;
        let mut ok_count = 0usize;
        let mut err_count = 0usize;

        for src_entry in &clipboard.entries {
            let dest_path = dest_fs
                .unique_destination(target_dir, &src_entry.metadata.name)
                .to_string_lossy()
                .to_string();

            let result: Result<(), crate::fs::FsError> = if same_fs {
                // Same (Windows) filesystem — use native operations
                if clipboard.op == ClipboardOp::Cut {
                    dest_fs.move_path(&src_entry.path, &dest_path)
                } else if src_entry.metadata.is_dir() {
                    dest_fs.copy_dir(&src_entry.path, &dest_path)
                } else {
                    dest_fs.copy_file(&src_entry.path, &dest_path)
                }
            } else {
                // Cross-filesystem: read from source, write to destination.
                // Cut from a read-only fs is just a copy.
                let source_fs = match self.filesystems.get(clipboard.source_fs) {
                    Some(e) => &e.fs,
                    None => {
                        err_count += 1;
                        continue;
                    }
                };
                Self::cross_fs_copy(
                    source_fs,
                    &src_entry.path,
                    src_entry.metadata.is_dir(),
                    dest_fs,
                    &dest_path,
                )
            };

            match result {
                Ok(()) => ok_count += 1,
                Err(e) => {
                    err_count += 1;
                    self.status_message = Some(StatusMessage {
                        text: format!("Error pasting \"{}\": {}", src_entry.metadata.name, e),
                        is_error: true,
                    });
                }
            }
        }

        // If cut was successful, clear the clipboard
        if clipboard.op == ClipboardOp::Cut && err_count == 0 {
            self.clipboard = None;
        }

        if err_count == 0 {
            let verb = if clipboard.op == ClipboardOp::Cut {
                "Moved"
            } else {
                "Pasted"
            };
            self.status_message = Some(StatusMessage {
                text: format!("{} {} item(s)", verb, ok_count),
                is_error: false,
            });
        }
    }

    /// Copy a single entry (file or directory) across filesystems by reading
    /// from `src_fs` and writing to `dst_fs`.
    fn cross_fs_copy(
        src_fs: &MountedFs,
        src_path: &str,
        is_dir: bool,
        dst_fs: &MountedFs,
        dst_path: &str,
    ) -> Result<(), crate::fs::FsError> {
        if is_dir {
            dst_fs.create_dir(dst_path)?;
            let children = src_fs.list_dir(src_path)?;
            for child in &children {
                let child_dst = format!(
                    "{}{}{}",
                    dst_path,
                    std::path::MAIN_SEPARATOR,
                    child.metadata.name
                );
                Self::cross_fs_copy(
                    src_fs,
                    &child.path,
                    child.metadata.is_dir(),
                    dst_fs,
                    &child_dst,
                )?;
            }
            Ok(())
        } else {
            let data = src_fs.read_file(src_path)?;
            dst_fs.write_file(dst_path, &data)
        }
    }

    /// Rename an entry (file or directory).
    fn rename_entry(&mut self, old_path: &str, new_name: &str) {
        let fs = match self.filesystems.get(self.selected_fs) {
            Some(e) => &e.fs,
            None => return,
        };

        // Build the new full path by replacing the last component
        let new_path = match Path::new(old_path).parent() {
            Some(parent) => parent.join(new_name).to_string_lossy().to_string(),
            None => new_name.to_string(),
        };

        match fs.rename(old_path, &new_path) {
            Ok(()) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Renamed to \"{}\"", new_name),
                    is_error: false,
                });
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Rename failed: {}", e),
                    is_error: true,
                });
            }
        }
    }

    /// Delete a file or directory.
    fn delete_entry(&mut self, path: &str) {
        let fs = match self.filesystems.get(self.selected_fs) {
            Some(e) => &e.fs,
            None => return,
        };

        match fs.delete(path) {
            Ok(()) => {
                self.status_message = Some(StatusMessage {
                    text: "Deleted successfully".to_string(),
                    is_error: false,
                });
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Delete failed: {}", e),
                    is_error: true,
                });
            }
        }
    }

    /// Create a new directory inside `parent`.
    fn create_directory(&mut self, parent: &str, name: &str) {
        let fs = match self.filesystems.get(self.selected_fs) {
            Some(e) => &e.fs,
            None => return,
        };

        let full = Path::new(parent).join(name).to_string_lossy().to_string();

        match fs.create_dir(&full) {
            Ok(()) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Created folder \"{}\"", name),
                    is_error: false,
                });
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to create folder: {}", e),
                    is_error: true,
                });
            }
        }
    }
}

impl eframe::App for FileExplorerApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Render LUKS dialog if open
        self.render_luks_dialog(ctx);

        // Render sidebar
        self.render_sidebar(ctx);

        // Render preview panel
        self.render_preview(ctx);

        // Render status bar
        self.render_status_bar(ctx);

        // Render main file browser
        CentralPanel::default().show(ctx, |ui| {
            if let Some(entry) = self.filesystems.get(self.selected_fs) {
                let action = self.browser.ui(ui, &entry.fs);

                if let Some(browser_action) = action {
                    self.handle_browser_action(browser_action, ctx);
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("No filesystem selected");
                });
            }
        });
    }
}
