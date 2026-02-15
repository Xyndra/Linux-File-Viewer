//! Windows filesystem implementation using standard library
use std::fs;
use std::path::{Path, PathBuf};

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

        let modified = metadata.modified().ok().map(DateTime::<Utc>::from);

        let created = metadata.created().ok().map(DateTime::<Utc>::from);

        let accessed = metadata.accessed().ok().map(DateTime::<Utc>::from);

        // Check for hidden attribute on Windows
        #[cfg(windows)]
        let hidden = {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            (metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN) != 0
        };

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

    // ── Write operations ──────────────────────────────────────────────

    /// Write data to a file, creating it if it doesn't exist and overwriting if it does
    pub fn write_file(&self, path: &str, data: &[u8]) -> FsResult<()> {
        fs::write(path, data).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(path.to_string()),
            _ => FsError::Io(e),
        })
    }

    /// Delete a file or directory (directories are removed recursively)
    pub fn delete(&self, path: &str) -> FsResult<()> {
        let p = Path::new(path);
        if !p.exists() {
            return Err(FsError::NotFound(path.to_string()));
        }

        if p.is_dir() {
            fs::remove_dir_all(p)
        } else {
            fs::remove_file(p)
        }
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(path.to_string()),
            _ => FsError::Io(e),
        })
    }

    /// Rename (or move within the same volume) a file or directory
    pub fn rename(&self, old_path: &str, new_path: &str) -> FsResult<()> {
        fs::rename(old_path, new_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(old_path.to_string()),
            std::io::ErrorKind::NotFound => FsError::NotFound(old_path.to_string()),
            _ => FsError::Io(e),
        })
    }

    /// Create a directory (and all missing parents)
    pub fn create_dir(&self, path: &str) -> FsResult<()> {
        fs::create_dir_all(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(path.to_string()),
            _ => FsError::Io(e),
        })
    }

    /// Copy a single file to a destination path
    pub fn copy_file(&self, src: &str, dst: &str) -> FsResult<()> {
        // Make sure the destination parent directory exists
        if let Some(parent) = Path::new(dst).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(FsError::Io)?;
            }
        }
        fs::copy(src, dst).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(src.to_string()),
            std::io::ErrorKind::NotFound => FsError::NotFound(src.to_string()),
            _ => FsError::Io(e),
        })?;
        Ok(())
    }

    /// Recursively copy a directory and all its contents
    pub fn copy_dir(&self, src: &str, dst: &str) -> FsResult<()> {
        let src_path = Path::new(src);
        let dst_path = Path::new(dst);

        if !src_path.is_dir() {
            return Err(FsError::NotADirectory(src.to_string()));
        }

        fs::create_dir_all(dst_path).map_err(FsError::Io)?;

        Self::copy_dir_recursive(src_path, dst_path)
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) -> FsResult<()> {
        for entry in fs::read_dir(src).map_err(FsError::Io)? {
            let entry = entry.map_err(FsError::Io)?;
            let src_child = entry.path();
            let dst_child = dst.join(entry.file_name());

            if src_child.is_dir() {
                fs::create_dir_all(&dst_child).map_err(FsError::Io)?;
                Self::copy_dir_recursive(&src_child, &dst_child)?;
            } else {
                fs::copy(&src_child, &dst_child).map_err(FsError::Io)?;
            }
        }
        Ok(())
    }

    /// Move a file or directory to a new location.
    /// Works across drives by falling back to copy-then-delete.
    pub fn move_path(&self, src: &str, dst: &str) -> FsResult<()> {
        // Try a fast rename first (works on the same volume)
        match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // If it failed for a reason other than cross-device, propagate
                // On Windows the error kind for cross-device is Other / raw OS error 17
                let is_cross_device = e.raw_os_error() == Some(17) // EXDEV
                    || e.raw_os_error() == Some(0x11) // same in hex
                    || e.kind() == std::io::ErrorKind::Other;
                if !is_cross_device {
                    return Err(match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            FsError::PermissionDenied(src.to_string())
                        }
                        std::io::ErrorKind::NotFound => FsError::NotFound(src.to_string()),
                        _ => FsError::Io(e),
                    });
                }
                // Cross-device: fall through to copy + delete
            }
        }

        let src_path = Path::new(src);
        if src_path.is_dir() {
            self.copy_dir(src, dst)?;
            fs::remove_dir_all(src).map_err(FsError::Io)?;
        } else {
            self.copy_file(src, dst)?;
            fs::remove_file(src).map_err(FsError::Io)?;
        }
        Ok(())
    }

    /// Determine a unique destination path so we don't silently overwrite.
    /// Given `/some/dir` and filename `hello.txt`, if `hello.txt` already
    /// exists it returns `hello (1).txt`, `hello (2).txt`, etc.
    pub fn unique_destination(dir: &str, name: &str) -> PathBuf {
        let base = Path::new(dir).join(name);
        if !base.exists() {
            return base;
        }

        let stem = Path::new(name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = Path::new(name)
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();

        for i in 1u32.. {
            let candidate = Path::new(dir).join(format!("{} ({}){}", stem, i, ext));
            if !candidate.exists() {
                return candidate;
            }
        }
        base // unreachable in practice
    }
}

impl Default for WindowsFs {
    fn default() -> Self {
        Self::new()
    }
}
