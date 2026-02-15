//! Linux filesystem implementation using the ext4-view crate
//!
//! This module provides read-only access to ext4 filesystems on raw partitions.

#![allow(dead_code)]

use std::cell::RefCell;
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use ext4_view::{Ext4, Ext4Read, FileType as Ext4FileType};

use super::disk::RawDisk;
use super::{EntryMetadata, EntryType, FsEntry, FsError, FsResult};

/// Default sector size for raw disk access
const DEFAULT_SECTOR_SIZE: u64 = 512;

/// Linux filesystem implementation for ext4
pub struct LinuxFs {
    name: String,
    ext4: RefCell<Ext4>,
}

/// Wrapper around RawDisk that implements the traits needed by ext4-view
/// and handles sector-aligned reads required by Windows raw disk access.
pub struct PartitionReader {
    disk: RefCell<RawDisk>,
    partition_offset: u64,
    sector_size: u64,
    /// Buffer for handling unaligned reads
    sector_buffer: RefCell<Vec<u8>>,
    /// Current logical position within the partition
    position: RefCell<u64>,
}

impl PartitionReader {
    pub fn new(disk: RawDisk, partition_offset: u64) -> Self {
        let sector_size = disk.sector_size();
        let sector_size = if sector_size == 0 {
            DEFAULT_SECTOR_SIZE
        } else {
            sector_size
        };

        Self {
            disk: RefCell::new(disk),
            partition_offset,
            sector_size,
            sector_buffer: RefCell::new(vec![0u8; sector_size as usize]),
            position: RefCell::new(0),
        }
    }

    /// Open a partition from a physical drive at a specific offset
    pub fn open_partition(
        drive_number: u32,
        partition_offset: u64,
        _partition_size: u64,
    ) -> FsResult<Self> {
        let disk = RawDisk::open_physical_drive(drive_number)?;
        Ok(Self::new(disk, partition_offset))
    }

    /// Read data at a specific offset within the partition, handling alignment
    fn read_aligned(&self, offset: u64, dst: &mut [u8]) -> std::io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }

        let mut disk = self.disk.borrow_mut();
        let sector_size = self.sector_size as usize;

        // Calculate the absolute offset on disk
        let absolute_offset = self.partition_offset + offset;

        // Calculate alignment
        let start_sector = absolute_offset / self.sector_size;
        let offset_in_start_sector = (absolute_offset % self.sector_size) as usize;

        let end_offset = absolute_offset + dst.len() as u64;
        let end_sector = (end_offset + self.sector_size - 1) / self.sector_size;
        let num_sectors = (end_sector - start_sector) as usize;

        // If the read is already sector-aligned and sector-sized, do direct read
        if offset_in_start_sector == 0 && dst.len() % sector_size == 0 {
            let aligned_offset = start_sector * self.sector_size;
            disk.seek(SeekFrom::Start(aligned_offset))?;
            return disk.read(dst);
        }

        // For unaligned reads, read full sectors and extract the needed bytes
        let aligned_offset = start_sector * self.sector_size;
        let total_read_size = num_sectors * sector_size;

        // Use a buffer for the aligned read
        let mut aligned_buffer = vec![0u8; total_read_size];
        disk.seek(SeekFrom::Start(aligned_offset))?;

        let bytes_read = disk.read(&mut aligned_buffer)?;
        if bytes_read == 0 {
            return Ok(0);
        }

        // Extract the requested portion
        let available = bytes_read.saturating_sub(offset_in_start_sector);
        let copy_len = std::cmp::min(dst.len(), available);

        if copy_len > 0 {
            dst[..copy_len].copy_from_slice(
                &aligned_buffer[offset_in_start_sector..offset_in_start_sector + copy_len],
            );
        }

        Ok(copy_len)
    }
}

impl Ext4Read for PartitionReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let mut total_read = 0;
        while total_read < dst.len() {
            let offset = start_byte + total_read as u64;
            let remaining = &mut dst[total_read..];

            match self.read_aligned(offset, remaining) {
                Ok(0) => {
                    // EOF reached
                    if total_read == 0 {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Unexpected end of partition",
                        )));
                    }
                    break;
                }
                Ok(n) => {
                    total_read += n;
                }
                Err(e) => {
                    return Err(Box::new(e));
                }
            }
        }
        Ok(())
    }
}

impl Read for PartitionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = *self.position.borrow();
        let bytes_read = self.read_aligned(pos, buf)?;
        *self.position.borrow_mut() += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for PartitionReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => {
                let current = *self.position.borrow();
                if n >= 0 {
                    current.saturating_add(n as u64)
                } else {
                    current.saturating_sub((-n) as u64)
                }
            }
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SeekFrom::End not supported for PartitionReader",
                ));
            }
        };
        *self.position.borrow_mut() = new_pos;
        Ok(new_pos)
    }
}

impl LinuxFs {
    /// Create a new LinuxFs from a partition reader
    pub fn new(reader: PartitionReader, label: Option<String>) -> FsResult<Self> {
        let name = label.unwrap_or_else(|| "Linux Partition".to_string());

        let ext4 = Ext4::load(Box::new(reader)).map_err(|e| {
            FsError::FilesystemError(format!("Failed to load ext4 filesystem: {:?}", e))
        })?;

        Ok(Self {
            name,
            ext4: RefCell::new(ext4),
        })
    }

    /// Create a LinuxFs from a physical drive and partition info
    pub fn from_partition(
        drive_number: u32,
        partition_offset: u64,
        partition_size: u64,
        label: Option<String>,
    ) -> FsResult<Self> {
        let reader =
            PartitionReader::open_partition(drive_number, partition_offset, partition_size)?;
        Self::new(reader, label)
    }

    fn file_type_to_entry_type(file_type: Ext4FileType) -> EntryType {
        match file_type {
            Ext4FileType::Regular => EntryType::File,
            Ext4FileType::Directory => EntryType::Directory,
            Ext4FileType::Symlink => EntryType::Symlink,
            _ => EntryType::Other,
        }
    }

    /// Get the display name of this filesystem
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the root path(s) of this filesystem
    pub fn roots(&self) -> FsResult<Vec<String>> {
        // Linux filesystem has a single root
        Ok(vec!["/".to_string()])
    }

    /// List entries in a directory
    pub fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>> {
        let ext4 = self.ext4.borrow();

        // Normalize path
        let normalized_path = if path.is_empty() || path == "/" {
            "/"
        } else {
            path
        };

        // Check if path exists and is a directory
        let metadata = ext4.metadata(normalized_path).map_err(|e| {
            FsError::NotFound(format!("Path not found: {} ({:?})", normalized_path, e))
        })?;

        if metadata.file_type() != Ext4FileType::Directory {
            return Err(FsError::NotADirectory(normalized_path.to_string()));
        }

        let mut entries = Vec::new();

        // Read directory entries
        let read_dir = ext4
            .read_dir(normalized_path)
            .map_err(|e| FsError::FilesystemError(format!("Failed to read directory: {:?}", e)))?;

        for entry_result in read_dir {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Get file name as string
            let entry_name = {
                let name_bytes = entry.file_name();
                // DirEntryName has as_str() method
                match name_bytes.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                }
            };

            // Skip . and .. entries
            if entry_name == "." || entry_name == ".." {
                continue;
            }

            // Construct the full path
            let entry_path = if normalized_path == "/" {
                format!("/{}", entry_name)
            } else {
                format!("{}/{}", normalized_path, entry_name)
            };

            // Get metadata for this entry
            let entry_metadata = match ext4.metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let entry_type = Self::file_type_to_entry_type(entry_metadata.file_type());

            let metadata = EntryMetadata {
                name: entry_name.clone(),
                entry_type,
                size: entry_metadata.len(),
                modified: None, // ext4-view doesn't expose timestamps
                created: None,
                accessed: None,
                readonly: (entry_metadata.mode() & 0o222) == 0, // No write bits
                hidden: entry_name.starts_with('.'),
            };

            entries.push(FsEntry {
                path: entry_path,
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
        let ext4 = self.ext4.borrow();

        let normalized_path = if path.is_empty() { "/" } else { path };

        let meta = ext4.metadata(normalized_path).map_err(|e| {
            FsError::NotFound(format!("Path not found: {} ({:?})", normalized_path, e))
        })?;

        let entry_type = Self::file_type_to_entry_type(meta.file_type());

        let name = normalized_path
            .rsplit('/')
            .next()
            .unwrap_or(normalized_path)
            .to_string();

        let name = if name.is_empty() {
            "/".to_string()
        } else {
            name
        };

        Ok(EntryMetadata {
            name: name.clone(),
            entry_type,
            size: meta.len(),
            modified: None,
            created: None,
            accessed: None,
            readonly: (meta.mode() & 0o222) == 0,
            hidden: name.starts_with('.'),
        })
    }

    /// Read file contents
    pub fn read_file(&self, path: &str) -> FsResult<Vec<u8>> {
        let ext4 = self.ext4.borrow();

        let meta = ext4
            .metadata(path)
            .map_err(|e| FsError::NotFound(format!("Path not found: {} ({:?})", path, e)))?;

        if meta.file_type() != Ext4FileType::Regular {
            return Err(FsError::NotAFile(path.to_string()));
        }

        ext4.read(path)
            .map_err(|e| FsError::FilesystemError(format!("Failed to read file: {:?}", e)))
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        let ext4 = self.ext4.borrow();
        let normalized_path = if path.is_empty() { "/" } else { path };

        match ext4.exists(normalized_path) {
            Ok(exists) => exists,
            Err(_) => false,
        }
    }

    /// Check if path is a directory
    pub fn is_dir(&self, path: &str) -> bool {
        let ext4 = self.ext4.borrow();
        let normalized_path = if path.is_empty() { "/" } else { path };

        match ext4.metadata(normalized_path) {
            Ok(meta) => meta.file_type() == Ext4FileType::Directory,
            Err(_) => false,
        }
    }

    /// Get the parent directory of a path
    pub fn parent(&self, path: &str) -> Option<String> {
        if path == "/" || path.is_empty() {
            return None;
        }

        let path = path.trim_end_matches('/');

        match path.rsplit_once('/') {
            Some(("", _)) => Some("/".to_string()),
            Some((parent, _)) => Some(parent.to_string()),
            None => Some("/".to_string()),
        }
    }
}
