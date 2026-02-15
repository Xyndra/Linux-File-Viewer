//! File browser component
//!
//! This module provides the file browser panel that displays directory contents
//! and allows navigation through the filesystem.

#![allow(dead_code)]

use egui::{RichText, Ui, Vec2};
use humansize::{format_size, BINARY};

use crate::fs::{EntryType, FsEntry, MountedFs};

/// State for a file browser panel
pub struct FileBrowser {
    /// Current path being displayed
    current_path: String,
    /// Entries in the current directory
    entries: Vec<FsEntry>,
    /// Selected entry index
    selected_index: Option<usize>,
    /// Error message to display
    error_message: Option<String>,
    /// Whether to show hidden files
    show_hidden: bool,
    /// Path history for back navigation
    history: Vec<String>,
    /// Current position in history
    history_index: usize,
    /// Search/filter text
    filter_text: String,
}

impl FileBrowser {
    pub fn new() -> Self {
        Self {
            current_path: String::new(),
            entries: Vec::new(),
            selected_index: None,
            error_message: None,
            show_hidden: false,
            history: Vec::new(),
            history_index: 0,
            filter_text: String::new(),
        }
    }

    /// Get the current path
    pub fn current_path(&self) -> &str {
        &self.current_path
    }

    /// Set whether to show hidden files
    pub fn set_show_hidden(&mut self, show: bool) {
        self.show_hidden = show;
    }

    /// Navigate to a path
    pub fn navigate_to(&mut self, path: &str, fs: &MountedFs) {
        // Add current path to history before navigating
        if !self.current_path.is_empty() {
            // Truncate forward history if we're not at the end
            self.history.truncate(self.history_index + 1);
            self.history.push(self.current_path.clone());
            self.history_index = self.history.len();
        }

        self.load_directory(path, fs);
    }

    /// Navigate to root
    pub fn navigate_to_root(&mut self, fs: &MountedFs) {
        match fs.roots() {
            Ok(roots) => {
                if let Some(root) = roots.first() {
                    self.navigate_to(root, fs);
                }
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to get roots: {}", e));
            }
        }
    }

    /// Go back in history
    pub fn go_back(&mut self, fs: &MountedFs) {
        if self.history_index > 0 {
            self.history_index -= 1;
            if let Some(path) = self.history.get(self.history_index).cloned() {
                self.load_directory(&path, fs);
            }
        }
    }

    /// Go forward in history
    pub fn go_forward(&mut self, fs: &MountedFs) {
        if self.history_index < self.history.len().saturating_sub(1) {
            self.history_index += 1;
            if let Some(path) = self.history.get(self.history_index).cloned() {
                self.load_directory(&path, fs);
            }
        }
    }

    /// Go to parent directory
    pub fn go_up(&mut self, fs: &MountedFs) {
        if let Some(parent) = fs.parent(&self.current_path) {
            if !parent.is_empty() {
                self.navigate_to(&parent, fs);
            }
        }
    }

    /// Load a directory without affecting history
    fn load_directory(&mut self, path: &str, fs: &MountedFs) {
        self.current_path = path.to_string();
        self.selected_index = None;
        self.error_message = None;
        self.filter_text.clear();

        match fs.list_dir(path) {
            Ok(entries) => {
                self.entries = entries;
            }
            Err(e) => {
                self.entries.clear();
                self.error_message = Some(format!("Error: {}", e));
            }
        }
    }

    /// Refresh the current directory
    pub fn refresh(&mut self, fs: &MountedFs) {
        self.load_directory(&self.current_path.clone(), fs);
    }

    /// Get the selected entry
    pub fn selected_entry(&self) -> Option<&FsEntry> {
        self.selected_index.and_then(|i| self.entries.get(i))
    }

    /// Get filtered entries based on current filter and hidden file settings
    /// Get indices and cloned entries that pass the filter
    fn filtered_entries(&self) -> Vec<(usize, FsEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                // Filter by hidden
                if !self.show_hidden && entry.metadata.hidden {
                    return false;
                }
                // Filter by search text
                if !self.filter_text.is_empty() {
                    if !entry
                        .metadata
                        .name
                        .to_lowercase()
                        .contains(&self.filter_text.to_lowercase())
                    {
                        return false;
                    }
                }
                true
            })
            .map(|(idx, entry)| (idx, entry.clone()))
            .collect()
    }

    /// Render the file browser UI
    pub fn ui(&mut self, ui: &mut Ui, fs: &MountedFs) -> Option<FileBrowserAction> {
        let mut action = None;

        // Navigation bar
        ui.horizontal(|ui| {
            // Back button
            if ui
                .add_enabled(self.history_index > 0, egui::Button::new("⬅"))
                .on_hover_text("Back")
                .clicked()
            {
                self.go_back(fs);
            }

            // Forward button
            if ui
                .add_enabled(
                    self.history_index < self.history.len().saturating_sub(1),
                    egui::Button::new("➡"),
                )
                .on_hover_text("Forward")
                .clicked()
            {
                self.go_forward(fs);
            }

            // Up button
            if ui
                .add_enabled(
                    fs.parent(&self.current_path).is_some(),
                    egui::Button::new("⬆"),
                )
                .on_hover_text("Up")
                .clicked()
            {
                self.go_up(fs);
            }

            // Refresh button
            if ui.button("🔄").on_hover_text("Refresh").clicked() {
                self.refresh(fs);
            }

            ui.separator();

            // Path display/edit
            ui.label("Path:");
            let mut path_text = self.current_path.clone();
            let response = ui.add(
                egui::TextEdit::singleline(&mut path_text)
                    .desired_width(ui.available_width() - 100.0),
            );
            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                if fs.exists(&path_text) && fs.is_dir(&path_text) {
                    self.navigate_to(&path_text, fs);
                } else {
                    self.error_message = Some("Invalid path".to_string());
                }
            }
        });

        // Filter/search bar
        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter_text)
                    .hint_text("Filter files...")
                    .desired_width(200.0),
            );

            ui.separator();

            ui.checkbox(&mut self.show_hidden, "Show hidden");
        });

        ui.separator();

        // Error message
        if let Some(ref error) = self.error_message {
            ui.colored_label(egui::Color32::RED, error);
            ui.separator();
        }

        // File listing
        let filtered = self.filtered_entries();
        let row_height = 24.0;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, filtered.len(), |ui, row_range| {
                for row_idx in row_range {
                    if let Some((original_idx, entry)) = filtered.get(row_idx) {
                        let original_idx = *original_idx;
                        let is_selected = self.selected_index == Some(original_idx);

                        let response = ui.allocate_response(
                            Vec2::new(ui.available_width(), row_height),
                            egui::Sense::click(),
                        );

                        // Draw background for selected item
                        if is_selected {
                            ui.painter().rect_filled(
                                response.rect,
                                0.0,
                                ui.style().visuals.selection.bg_fill,
                            );
                        } else if response.hovered() {
                            ui.painter().rect_filled(
                                response.rect,
                                0.0,
                                ui.style().visuals.widgets.hovered.bg_fill,
                            );
                        }

                        // Draw entry content
                        let rect = response.rect;
                        let painter = ui.painter();

                        // Icon
                        let icon = match entry.metadata.entry_type {
                            EntryType::Directory => "📁",
                            EntryType::File => Self::file_icon(&entry.metadata.name),
                            EntryType::Symlink => "🔗",
                            EntryType::Other => "❓",
                        };

                        let icon_pos = rect.left_center() + egui::vec2(8.0, 0.0);
                        painter.text(
                            icon_pos,
                            egui::Align2::LEFT_CENTER,
                            icon,
                            egui::FontId::default(),
                            ui.style().visuals.text_color(),
                        );

                        // Name
                        let name_color = if entry.metadata.hidden {
                            ui.style().visuals.weak_text_color()
                        } else {
                            ui.style().visuals.text_color()
                        };
                        let name_pos = rect.left_center() + egui::vec2(32.0, 0.0);
                        painter.text(
                            name_pos,
                            egui::Align2::LEFT_CENTER,
                            &entry.metadata.name,
                            egui::FontId::default(),
                            name_color,
                        );

                        // Size (for files)
                        if entry.metadata.entry_type == EntryType::File {
                            let size_text = format_size(entry.metadata.size, BINARY);
                            let size_pos = rect.right_center() - egui::vec2(100.0, 0.0);
                            painter.text(
                                size_pos,
                                egui::Align2::RIGHT_CENTER,
                                size_text,
                                egui::FontId::default(),
                                ui.style().visuals.weak_text_color(),
                            );
                        }

                        // Modified date
                        if let Some(modified) = entry.metadata.modified {
                            let date_text = modified.format("%Y-%m-%d %H:%M").to_string();
                            let date_pos = rect.right_center() - egui::vec2(8.0, 0.0);
                            painter.text(
                                date_pos,
                                egui::Align2::RIGHT_CENTER,
                                date_text,
                                egui::FontId::default(),
                                ui.style().visuals.weak_text_color(),
                            );
                        }

                        // Handle clicks
                        if response.clicked() {
                            self.selected_index = Some(original_idx);
                        }

                        if response.double_clicked() {
                            if entry.metadata.is_dir() {
                                self.navigate_to(&entry.path, fs);
                            } else {
                                action = Some(FileBrowserAction::OpenFile(entry.path.clone()));
                            }
                        }

                        // Context menu
                        response.context_menu(|ui| {
                            if entry.metadata.is_dir() {
                                if ui.button("Open").clicked() {
                                    self.navigate_to(&entry.path, fs);
                                    ui.close_menu();
                                }
                            } else {
                                if ui.button("View").clicked() {
                                    action = Some(FileBrowserAction::OpenFile(entry.path.clone()));
                                    ui.close_menu();
                                }
                            }
                            if ui.button("Copy path").clicked() {
                                ui.ctx().copy_text(entry.path.clone());
                                ui.close_menu();
                            }
                        });
                    }
                }
            });

        // Status bar
        ui.separator();
        ui.horizontal(|ui| {
            let total = self.entries.len();
            let shown = filtered.len();
            let hidden = total - shown;

            ui.label(format!("{} items", shown));
            if hidden > 0 {
                ui.label(RichText::new(format!("({} hidden)", hidden)).weak());
            }

            if let Some(idx) = self.selected_index {
                if let Some(entry) = self.entries.get(idx) {
                    ui.separator();
                    ui.label(&entry.metadata.name);
                }
            }
        });

        action
    }

    /// Get appropriate icon for a file based on extension
    fn file_icon(filename: &str) -> &'static str {
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

        match ext.as_str() {
            // Images
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "svg" | "webp" => "🖼",
            // Documents
            "pdf" => "📕",
            "doc" | "docx" | "odt" => "📘",
            "xls" | "xlsx" | "ods" => "📗",
            "ppt" | "pptx" | "odp" => "📙",
            "txt" | "md" | "rst" => "📄",
            // Code
            "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "hpp" | "java" | "go" | "rb" => "📜",
            "html" | "css" | "scss" | "sass" => "🌐",
            "json" | "yaml" | "yml" | "toml" | "xml" => "⚙",
            // Archives
            "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => "📦",
            // Media
            "mp3" | "wav" | "flac" | "ogg" | "m4a" => "🎵",
            "mp4" | "mkv" | "avi" | "mov" | "webm" => "🎬",
            // Executables
            "exe" | "msi" | "dll" => "⚡",
            "sh" | "bash" | "bat" | "cmd" | "ps1" => "📟",
            // Default
            _ => "📄",
        }
    }
}

impl Default for FileBrowser {
    fn default() -> Self {
        Self::new()
    }
}

/// Actions that can be triggered from the file browser
#[derive(Debug, Clone)]
pub enum FileBrowserAction {
    /// Request to open/view a file
    OpenFile(String),
}
