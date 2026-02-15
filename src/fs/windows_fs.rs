//! Windows filesystem implementation using standard library

#![allow(dead_code)]

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};

use super::{EntryMetadata, EntryType, FsEntry, FsError, FsResult};

/// Windows filesystem implementation
pub struct WindowsFs {
    name: String,
}

impl WindowsFs {
    pub fn new() -> Self {
        Self {
            name: "Windows Filesystem".to_string(),
        }
    }

    /// Get all available drive letters
    pub fn get_drives() -> Vec<String> {
        let mut drives = Vec::new();

        // Check drive letters A-Z
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            if Path::new(&drive).exists() {
                drives.push(drive);
            }
        }

        drives
    }

    fn path_to_metadata(path: &Path) -> FsResult<EntryMetadata> {
        let metadata = fs::metadata(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
            std::io::ErrorKind::PermissionDenied => {
                FsError::PermissionDenied(path.display().to_string())
            }
            _ => FsError::Io(e),
        })?;

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());

        let entry_type = if metadata.is_dir() {
            EntryType::Directory
        } else if metadata.is_symlink() {
            EntryType::Symlink
        } else if metadata.is_file() {
            EntryType::File
        } else {
            EntryType::Other
        };

        let modified = metadata.modified().ok().map(|t| DateTime::<Utc>::from(t));

        let created = metadata.created().ok().map(|t| DateTime::<Utc>::from(t));

        let accessed = metadata.accessed().ok().map(|t| DateTime::<Utc>::from(t));

        // Check for hidden attribute on Windows
        #[cfg(windows)]
        let hidden = {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            (metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN) != 0
        };

        #[cfg(not(windows))]
        let hidden = name.starts_with('.');

        Ok(EntryMetadata {
            name,
            entry_type,
            size: metadata.len(),
            modified,
            created,
            accessed,
            readonly: metadata.permissions().readonly(),
            hidden,
        })
    }

    /// Get the display name of this filesystem
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the root path(s) of this filesystem
    pub fn roots(&self) -> FsResult<Vec<String>> {
        Ok(Self::get_drives())
    }

    /// List entries in a directory
    pub fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>> {
        let path = Path::new(path);

        if !path.exists() {
            return Err(FsError::NotFound(path.display().to_string()));
        }

        if !path.is_dir() {
            return Err(FsError::NotADirectory(path.display().to_string()));
        }

        let mut entries = Vec::new();

        let read_dir = fs::read_dir(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                FsError::PermissionDenied(path.display().to_string())
            }
            _ => FsError::Io(e),
        })?;

        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // Skip entries we can't read
            };

            let entry_path = entry.path();
            let metadata = match Self::path_to_metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => continue, // Skip entries we can't get metadata for
            };

            entries.push(FsEntry {
                path: entry_path.to_string_lossy().to_string(),
                metadata,
            });
        }

        // Sort: directories first, then by name
        entries.sort_by(|a, b| match (a.metadata.is_dir(), b.metadata.is_dir()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .metadata
                .name
                .to_lowercase()
                .cmp(&b.metadata.name.to_lowercase()),
        });

        Ok(entries)
    }

    /// Get metadata for a path
    pub fn metadata(&self, path: &str) -> FsResult<EntryMetadata> {
        Self::path_to_metadata(Path::new(path))
    }

    /// Read file contents
    pub fn read_file(&self, path: &str) -> FsResult<Vec<u8>> {
        let path = Path::new(path);

        if !path.exists() {
            return Err(FsError::NotFound(path.display().to_string()));
        }

        if path.is_dir() {
            return Err(FsError::NotAFile(path.display().to_string()));
        }

        fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                FsError::PermissionDenied(path.display().to_string())
            }
            _ => FsError::Io(e),
        })
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    /// Check if path is a directory
    pub fn is_dir(&self, path: &str) -> bool {
        Path::new(path).is_dir()
    }

    /// Get the parent directory of a path
    pub fn parent(&self, path: &str) -> Option<String> {
        let path = Path::new(path);
        path.parent().map(|p| p.to_string_lossy().to_string())
    }
}

impl Default for WindowsFs {
    fn default() -> Self {
        Self::new()
    }
}
