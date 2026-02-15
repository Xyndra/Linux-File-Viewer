//! Main application state and UI
//!
//! This module contains the main application struct that manages filesystems
//! and renders the main UI.

use eframe::egui;
use egui::{CentralPanel, Context, RichText, SidePanel, TopBottomPanel};

use crate::fs::btrfs_fs::{BtrfsFs, BTRFS_SUPERBLOCK_OFFSET};
use crate::fs::disk::{
    detect_partitions, enumerate_physical_drives, get_partition_geometry, is_potentially_ext4,
    RawDisk,
};
use crate::fs::linux_fs::{LinuxFs, PartitionReader};
use crate::fs::luks::{is_luks, LuksReader};
use crate::fs::windows_fs::WindowsFs;
use crate::fs::{DetectedFsType, MountedFs, PartitionInfo};

use super::file_browser::{FileBrowser, FileBrowserAction};

/// The main file viewer application
pub struct FileViewerApp {
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

impl FileViewerApp {
    /// Create a new application instance
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
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
            icon: "🪟",
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
                    icon: "🐧",
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
                    icon: "🌲",
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
                icon: "🔓",
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
            egui::Window::new("🔐 LUKS Encrypted Partition")
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

                if ui.button("🔍 Scan for partitions").clicked() {
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
                                    DetectedFsType::Luks { .. } => "🔐",
                                    DetectedFsType::Btrfs => "🌲",
                                    _ => "🐧",
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
                                    let icon = if is_linux { "🐧" } else { "💾" };
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
                        if ui.button("✖").clicked() {
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
}

impl eframe::App for FileViewerApp {
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

                if let Some(FileBrowserAction::OpenFile(path)) = action {
                    self.preview_file(&path, ctx);
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("No filesystem selected");
                });
            }
        });
    }
}
