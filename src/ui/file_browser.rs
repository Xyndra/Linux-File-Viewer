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
    /// Inline rename state
    rename_state: Option<RenameState>,
    /// New folder dialog state
    new_folder_state: Option<NewFolderState>,
    /// Delete confirmation state
    delete_confirm: Option<DeleteConfirmState>,
}

/// State for inline renaming
struct RenameState {
    /// Index of the entry being renamed (in the unfiltered entries list)
    original_index: usize,
    /// The new name being typed
    new_name: String,
    /// Whether focus has been set on the text edit yet
    focus_set: bool,
}

/// State for the new-folder dialog
struct NewFolderState {
    name: String,
    focus_set: bool,
}

/// State for delete confirmation
struct DeleteConfirmState {
    /// Path to delete
    path: String,
    /// Display name
    name: String,
    /// Whether it's a directory
    is_dir: bool,
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
            rename_state: None,
            new_folder_state: None,
            delete_confirm: None,
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
        self.rename_state = None;
        self.new_folder_state = None;
        self.delete_confirm = None;

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
                if !self.filter_text.is_empty()
                    && !entry
                        .metadata
                        .name
                        .to_lowercase()
                        .contains(&self.filter_text.to_lowercase())
                {
                    return false;
                }
                true
            })
            .map(|(idx, entry)| (idx, entry.clone()))
            .collect()
    }

    /// Render the file browser UI
    pub fn ui(&mut self, ui: &mut Ui, fs: &MountedFs) -> Option<FileBrowserAction> {
        let mut action = None;
        let is_writable = fs.is_writable();

        // ── Keyboard shortcuts ────────────────────────────────────────
        // Only process when no inline editor is active
        if self.rename_state.is_none() && self.new_folder_state.is_none() {
            let kb = &ui.input(|i| {
                (
                    i.modifiers.ctrl,
                    i.key_pressed(egui::Key::C),
                    i.key_pressed(egui::Key::X),
                    i.key_pressed(egui::Key::V),
                    i.key_pressed(egui::Key::Delete),
                    i.key_pressed(egui::Key::F2),
                    i.key_pressed(egui::Key::N),
                )
            });
            let (ctrl, c, x, v, del, f2, n) = *kb;

            if let Some(idx) = self.selected_index {
                if let Some(entry) = self.entries.get(idx).cloned() {
                    if ctrl && c {
                        action = Some(FileBrowserAction::CopyEntries(vec![entry.clone()]));
                    }
                    if ctrl && x && is_writable {
                        action = Some(FileBrowserAction::CutEntries(vec![entry.clone()]));
                    }
                    if del && is_writable {
                        self.delete_confirm = Some(DeleteConfirmState {
                            path: entry.path.clone(),
                            name: entry.metadata.name.clone(),
                            is_dir: entry.metadata.is_dir(),
                        });
                    }
                    if f2 && is_writable {
                        self.rename_state = Some(RenameState {
                            original_index: idx,
                            new_name: entry.metadata.name.clone(),
                            focus_set: false,
                        });
                    }
                }
            }

            if ctrl && v {
                action = Some(FileBrowserAction::PasteInto(self.current_path.clone()));
            }
            if ctrl && n && is_writable {
                self.new_folder_state = Some(NewFolderState {
                    name: String::new(),
                    focus_set: false,
                });
            }
        }

        // Navigation bar
        ui.horizontal(|ui| {
            // Back button
            if ui
                .add_enabled(
                    self.history_index > 0,
                    egui::Button::new("\u{2190}"), // ←
                )
                .on_hover_text("Back")
                .clicked()
            {
                self.go_back(fs);
            }

            // Forward button
            if ui
                .add_enabled(
                    self.history_index < self.history.len().saturating_sub(1),
                    egui::Button::new("\u{2192}"), // →
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
                    egui::Button::new("\u{2191}"), // ↑
                )
                .on_hover_text("Up")
                .clicked()
            {
                self.go_up(fs);
            }

            // Refresh button
            if ui
                .button("\u{21BB}") // ↻
                .on_hover_text("Refresh")
                .clicked()
            {
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
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter_text)
                    .hint_text("Filter files...")
                    .desired_width(200.0),
            );

            ui.separator();

            ui.checkbox(&mut self.show_hidden, "Show hidden");

            // New folder button (writable filesystems only)
            if is_writable {
                ui.separator();
                if ui.button("\u{2795} New folder").clicked() {
                    // ✚
                    self.new_folder_state = Some(NewFolderState {
                        name: String::new(),
                        focus_set: false,
                    });
                }
            }
        });

        ui.separator();

        // Error message
        if let Some(ref error) = self.error_message {
            ui.colored_label(egui::Color32::RED, error);
            ui.separator();
        }

        // ── New Folder inline editor ──────────────────────────────────
        if self.new_folder_state.is_some() {
            let mut nf = self.new_folder_state.take().unwrap();
            let mut keep = true;
            ui.horizontal(|ui| {
                ui.label("\u{1F4C1} New folder name:"); // 📁 — will render via symbol font
                let te = ui.add(
                    egui::TextEdit::singleline(&mut nf.name)
                        .desired_width(250.0)
                        .hint_text("folder name"),
                );
                if !nf.focus_set {
                    te.request_focus();
                    nf.focus_set = true;
                }
                let enter = te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("\u{2714} Create").clicked() || enter {
                    // ✔
                    let name = nf.name.trim().to_string();
                    if !name.is_empty() {
                        action = Some(FileBrowserAction::CreateDirectory(
                            self.current_path.clone(),
                            name,
                        ));
                    }
                    keep = false;
                }
                if ui.button("\u{2716} Cancel").clicked()
                    || ui.input(|i| i.key_pressed(egui::Key::Escape))
                {
                    // ✖
                    keep = false;
                }
            });
            ui.separator();
            if keep {
                self.new_folder_state = Some(nf);
            }
        }

        // ── Delete confirmation bar ──────────────────────────────────
        let mut clear_delete = false;
        if let Some(ref dc) = self.delete_confirm {
            ui.horizontal(|ui| {
                let kind = if dc.is_dir { "directory" } else { "file" };
                ui.colored_label(
                    egui::Color32::YELLOW,
                    format!("Delete {} \"{}\"?", kind, dc.name),
                );
                if ui.button("Yes, delete").clicked() {
                    action = Some(FileBrowserAction::DeletePath(dc.path.clone()));
                    clear_delete = true;
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    clear_delete = true;
                }
            });
            ui.separator();
        }
        if clear_delete {
            self.delete_confirm = None;
        }

        // File listing
        let filtered = self.filtered_entries();
        let row_height = 24.0;

        // Track whether any row handled a secondary (right) click so we
        // can fall back to a background context menu if none did.
        let mut row_ctx_opened = false;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, filtered.len(), |ui, row_range| {
                for row_idx in row_range {
                    if let Some((original_idx, entry)) = filtered.get(row_idx) {
                        let original_idx = *original_idx;
                        let is_selected = self.selected_index == Some(original_idx);

                        // ── Inline rename mode ────────────────────────
                        let is_renaming = self
                            .rename_state
                            .as_ref()
                            .map_or(false, |r| r.original_index == original_idx);

                        if is_renaming {
                            let mut rs = self.rename_state.take().unwrap();
                            let mut keep = true;
                            ui.horizontal(|ui| {
                                let icon = match entry.metadata.entry_type {
                                    EntryType::Directory => Self::DIR_ICON,
                                    EntryType::File => Self::file_icon(&entry.metadata.name),
                                    EntryType::Symlink => Self::SYMLINK_ICON,
                                    EntryType::Other => Self::OTHER_ICON,
                                };
                                ui.label(icon);
                                let te = ui.add(
                                    egui::TextEdit::singleline(&mut rs.new_name)
                                        .desired_width(300.0),
                                );
                                if !rs.focus_set {
                                    te.request_focus();
                                    rs.focus_set = true;
                                }
                                let enter = te.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if enter || ui.button("\u{2714}").clicked() {
                                    // ✔
                                    let new_name = rs.new_name.trim().to_string();
                                    if !new_name.is_empty() && new_name != entry.metadata.name {
                                        action = Some(FileBrowserAction::RenamePath(
                                            entry.path.clone(),
                                            new_name,
                                        ));
                                    }
                                    keep = false;
                                }
                                if ui.button("\u{2716}").clicked()
                                    || ui.input(|i| i.key_pressed(egui::Key::Escape))
                                {
                                    // ✖
                                    keep = false;
                                }
                            });
                            if keep {
                                self.rename_state = Some(rs);
                            }
                            continue;
                        }

                        // ── Normal row ────────────────────────────────
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
                            EntryType::Directory => Self::DIR_ICON,
                            EntryType::File => Self::file_icon(&entry.metadata.name),
                            EntryType::Symlink => Self::SYMLINK_ICON,
                            EntryType::Other => Self::OTHER_ICON,
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

                        // Handle left clicks
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

                        // Also select on right-click so the context menu
                        // always applies to the clicked item.
                        if response.secondary_clicked() {
                            self.selected_index = Some(original_idx);
                            row_ctx_opened = true;
                        }

                        // Context menu on individual entries
                        response.context_menu(|ui| {
                            // Open / View
                            if entry.metadata.is_dir() {
                                if ui.button("Open").clicked() {
                                    self.navigate_to(&entry.path, fs);
                                    ui.close_menu();
                                }
                            } else if ui.button("View").clicked() {
                                action = Some(FileBrowserAction::OpenFile(entry.path.clone()));
                                ui.close_menu();
                            }

                            ui.separator();

                            // Copy (always available – works across filesystems)
                            if ui.button("Copy        Ctrl+C").clicked() {
                                action = Some(FileBrowserAction::CopyEntries(vec![entry.clone()]));
                                ui.close_menu();
                            }

                            // Cut (writable only)
                            if is_writable {
                                if ui.button("Cut         Ctrl+X").clicked() {
                                    action =
                                        Some(FileBrowserAction::CutEntries(vec![entry.clone()]));
                                    ui.close_menu();
                                }
                            }

                            // Paste
                            if ui.button("Paste       Ctrl+V").clicked() {
                                let target = if entry.metadata.is_dir() {
                                    entry.path.clone()
                                } else {
                                    self.current_path.clone()
                                };
                                action = Some(FileBrowserAction::PasteInto(target));
                                ui.close_menu();
                            }

                            if is_writable {
                                ui.separator();

                                if ui.button("Rename      F2").clicked() {
                                    self.rename_state = Some(RenameState {
                                        original_index: original_idx,
                                        new_name: entry.metadata.name.clone(),
                                        focus_set: false,
                                    });
                                    ui.close_menu();
                                }

                                if ui.button("Delete      Del").clicked() {
                                    self.delete_confirm = Some(DeleteConfirmState {
                                        path: entry.path.clone(),
                                        name: entry.metadata.name.clone(),
                                        is_dir: entry.metadata.is_dir(),
                                    });
                                    ui.close_menu();
                                }
                            }

                            ui.separator();

                            if ui.button("Copy path").clicked() {
                                ui.ctx().copy_text(entry.path.clone());
                                ui.close_menu();
                            }
                        });
                    }
                }
            });

        // Background context menu: only when no row handled the right-click.
        // We detect a secondary click anywhere in the central area manually.
        if !row_ctx_opened {
            let bg_secondary =
                ui.input(|i| i.pointer.button_clicked(egui::PointerButton::Secondary));
            if bg_secondary {
                // egui popup menus are id-based; open one tied to the browser bg
                ui.memory_mut(|mem| mem.toggle_popup(ui.id().with("browser_bg_ctx")));
            }
            egui::popup_below_widget(
                ui,
                ui.id().with("browser_bg_ctx"),
                &ui.response(),
                egui::PopupCloseBehavior::CloseOnClickOutside,
                |ui| {
                    if ui.button("Paste here   Ctrl+V").clicked() {
                        action = Some(FileBrowserAction::PasteInto(self.current_path.clone()));
                        ui.close_menu();
                    }
                    if is_writable {
                        if ui.button("New folder   Ctrl+N").clicked() {
                            self.new_folder_state = Some(NewFolderState {
                                name: String::new(),
                                focus_set: false,
                            });
                            ui.close_menu();
                        }
                    }
                },
            );
        }

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

    // ── Icon constants ────────────────────────────────────────────────
    // All icons are single Unicode code points from Segoe UI Symbol so
    // they render natively on Windows without colour-emoji issues.

    const DIR_ICON: &'static str = "\u{1F4C1}"; // 📁
    const SYMLINK_ICON: &'static str = "\u{1F517}"; // 🔗
    const OTHER_ICON: &'static str = "?";

    /// Get appropriate icon for a file based on extension
    fn file_icon(filename: &str) -> &'static str {
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

        match ext.as_str() {
            // Images
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "svg" | "webp" => "\u{1F5BC}", // 🖼
            // Documents
            "pdf" => "\u{1F4D5}",                  // 📕
            "doc" | "docx" | "odt" => "\u{1F4D8}", // 📘
            "xls" | "xlsx" | "ods" => "\u{1F4D7}", // 📗
            "ppt" | "pptx" | "odp" => "\u{1F4D9}", // 📙
            "txt" | "md" | "rst" => "\u{1F4C4}",   // 📄
            // Code
            "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "hpp" | "java" | "go" | "rb" => {
                "\u{1F4DC}" // 📜
            }
            "html" | "css" | "scss" | "sass" => "\u{1F310}", // 🌐
            "json" | "yaml" | "yml" | "toml" | "xml" => "\u{2699}", // ⚙
            // Archives
            "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => "\u{1F4E6}", // 📦
            // Media
            "mp3" | "wav" | "flac" | "ogg" | "m4a" => "\u{266B}", // ♫
            "mp4" | "mkv" | "avi" | "mov" | "webm" => "\u{25B6}", // ▶
            // Executables
            "exe" | "msi" | "dll" => "\u{2699}", // ⚙
            "sh" | "bash" | "bat" | "cmd" | "ps1" => ">_",
            // Default
            _ => "\u{1F4C4}", // 📄
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
    /// Request to open/preview a file
    OpenFile(String),
    /// Copy entries to the clipboard
    CopyEntries(Vec<FsEntry>),
    /// Cut entries to the clipboard (copy + delete on paste)
    CutEntries(Vec<FsEntry>),
    /// Paste the current clipboard contents into the given directory
    PasteInto(String),
    /// Rename a path: (old_path, new_name)
    RenamePath(String, String),
    /// Delete a path
    DeletePath(String),
    /// Create a directory inside the given parent with the given name
    CreateDirectory(String, String),
}
