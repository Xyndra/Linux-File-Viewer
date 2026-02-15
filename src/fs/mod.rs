//! Filesystem abstraction layer
//!
//! This module provides a unified interface for accessing both Windows and Linux filesystems.

#![allow(dead_code)]

use std::path::PathBuf;

pub mod btrfs_fs;
pub mod disk;
pub mod linux_fs;
pub mod luks;
pub mod windows_fs;

use chrono::{DateTime, Utc};
use std::io::{Read, Seek};
use thiserror::Error;

/// Errors that can occur during filesystem operations
#[derive(Error, Debug)]
pub enum FsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Path not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Filesystem error: {0}")]
    FilesystemError(String),

    #[error("Not a directory: {0}")]
    NotADirectory(String),

    #[error("Not a file: {0}")]
    NotAFile(String),

    #[error("Raw disk access error: {0}")]
    RawDiskError(String),

    #[error("Unsupported filesystem: {0}")]
    UnsupportedFilesystem(String),

    #[error("LUKS locked: {0}")]
    LuksLocked(String),
}

pub type FsResult<T> = Result<T, FsError>;

/// Type of filesystem entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    File,
    Directory,
    Symlink,
    Other,
}

/// Metadata for a filesystem entry
#[derive(Debug, Clone)]
pub struct EntryMetadata {
    pub name: String,
    pub entry_type: EntryType,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub readonly: bool,
    pub hidden: bool,
}

impl EntryMetadata {
    pub fn is_dir(&self) -> bool {
        self.entry_type == EntryType::Directory
    }

    pub fn is_file(&self) -> bool {
        self.entry_type == EntryType::File
    }
}

/// A filesystem entry (file or directory)
#[derive(Debug, Clone)]
pub struct FsEntry {
    pub path: String,
    pub metadata: EntryMetadata,
}

/// Information about a detected filesystem/partition
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub device_path: String,
    pub label: Option<String>,
    pub fs_type: String,
    pub size: u64,
    pub partition_number: u32,
}

/// Detected filesystem type for a partition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedFsType {
    /// ext4 filesystem
    Ext4,
    /// btrfs filesystem
    Btrfs,
    /// LUKS-encrypted container (inner type unknown until decrypted)
    Luks { version: u16 },
    /// Unknown or unsupported
    Unknown,
}

/// Trait for btrfs filesystem operations (type-erased)
pub trait BtrfsFsOps {
    fn name(&self) -> &str;
    fn roots(&self) -> FsResult<Vec<String>>;
    fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>>;
    fn metadata(&self, path: &str) -> FsResult<EntryMetadata>;
    fn read_file(&self, path: &str) -> FsResult<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
    fn is_dir(&self, path: &str) -> bool;
    fn parent(&self, path: &str) -> Option<String>;
}

/// Implement BtrfsFsOps for any BtrfsFs<R>
impl<R: Read + Seek> BtrfsFsOps for btrfs_fs::BtrfsFs<R> {
    fn name(&self) -> &str {
        self.name()
    }

    fn roots(&self) -> FsResult<Vec<String>> {
        self.roots()
    }

    fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>> {
        self.list_dir(path)
    }

    fn metadata(&self, path: &str) -> FsResult<EntryMetadata> {
        self.metadata(path)
    }

    fn read_file(&self, path: &str) -> FsResult<Vec<u8>> {
        self.read_file(path)
    }

    fn exists(&self, path: &str) -> bool {
        self.exists(path)
    }

    fn is_dir(&self, path: &str) -> bool {
        self.is_dir(path)
    }

    fn parent(&self, path: &str) -> Option<String> {
        self.parent(path)
    }
}

/// Represents a mounted/accessible filesystem
/// Note: This enum is not Send+Sync because some variants use RefCell internally
pub enum MountedFs {
    Windows(windows_fs::WindowsFs),
    Linux(linux_fs::LinuxFs),
    Btrfs(Box<dyn BtrfsFsOps>),
}

impl MountedFs {
    /// Get the display name of this filesystem
    pub fn name(&self) -> &str {
        match self {
            MountedFs::Windows(fs) => fs.name(),
            MountedFs::Linux(fs) => fs.name(),
            MountedFs::Btrfs(fs) => fs.name(),
        }
    }

    /// Get the root path(s) of this filesystem
    pub fn roots(&self) -> FsResult<Vec<String>> {
        match self {
            MountedFs::Windows(fs) => fs.roots(),
            MountedFs::Linux(fs) => fs.roots(),
            MountedFs::Btrfs(fs) => fs.roots(),
        }
    }

    /// List entries in a directory
    pub fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>> {
        match self {
            MountedFs::Windows(fs) => fs.list_dir(path),
            MountedFs::Linux(fs) => fs.list_dir(path),
            MountedFs::Btrfs(fs) => fs.list_dir(path),
        }
    }

    /// Get metadata for a path
    pub fn metadata(&self, path: &str) -> FsResult<EntryMetadata> {
        match self {
            MountedFs::Windows(fs) => fs.metadata(path),
            MountedFs::Linux(fs) => fs.metadata(path),
            MountedFs::Btrfs(fs) => fs.metadata(path),
        }
    }

    /// Read file contents
    pub fn read_file(&self, path: &str) -> FsResult<Vec<u8>> {
        match self {
            MountedFs::Windows(fs) => fs.read_file(path),
            MountedFs::Linux(fs) => fs.read_file(path),
            MountedFs::Btrfs(fs) => fs.read_file(path),
        }
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        match self {
            MountedFs::Windows(fs) => fs.exists(path),
            MountedFs::Linux(fs) => fs.exists(path),
            MountedFs::Btrfs(fs) => fs.exists(path),
        }
    }

    /// Check if path is a directory
    pub fn is_dir(&self, path: &str) -> bool {
        match self {
            MountedFs::Windows(fs) => fs.is_dir(path),
            MountedFs::Linux(fs) => fs.is_dir(path),
            MountedFs::Btrfs(fs) => fs.is_dir(path),
        }
    }

    /// Get the parent directory of a path
    pub fn parent(&self, path: &str) -> Option<String> {
        match self {
            MountedFs::Windows(fs) => fs.parent(path),
            MountedFs::Linux(fs) => fs.parent(path),
            MountedFs::Btrfs(fs) => fs.parent(path),
        }
    }

    // ── Write operations ──────────────────────────────────────────────

    /// Whether this filesystem supports write operations
    pub fn is_writable(&self) -> bool {
        matches!(self, MountedFs::Windows(_))
    }

    /// Write data to a file (Windows only)
    pub fn write_file(&self, path: &str, data: &[u8]) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.write_file(path, data),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Delete a file or directory (Windows only)
    pub fn delete(&self, path: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.delete(path),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Rename a file or directory (Windows only)
    pub fn rename(&self, old_path: &str, new_path: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.rename(old_path, new_path),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Create a directory (Windows only)
    pub fn create_dir(&self, path: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.create_dir(path),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Copy a single file (Windows only)
    pub fn copy_file(&self, src: &str, dst: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.copy_file(src, dst),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Recursively copy a directory (Windows only)
    pub fn copy_dir(&self, src: &str, dst: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.copy_dir(src, dst),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Move a file or directory, works across drives (Windows only)
    pub fn move_path(&self, src: &str, dst: &str) -> FsResult<()> {
        match self {
            MountedFs::Windows(fs) => fs.move_path(src, dst),
            _ => Err(FsError::PermissionDenied(
                "Filesystem is read-only".to_string(),
            )),
        }
    }

    /// Determine a unique destination path to avoid overwrites
    pub fn unique_destination(&self, dir: &str, name: &str) -> PathBuf {
        match self {
            MountedFs::Windows(_) => windows_fs::WindowsFs::unique_destination(dir, name),
            _ => PathBuf::from(dir).join(name),
        }
    }
}
