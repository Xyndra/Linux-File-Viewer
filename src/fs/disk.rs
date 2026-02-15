//! Raw disk access for Windows
//!
//! This module provides low-level access to physical drives and partitions,
//! which is necessary for reading Linux filesystems on Windows.
//!
//! Windows raw disk access requires sector-aligned reads. This module handles
//! alignment internally to provide a seamless interface.

#![allow(dead_code)]

use std::io::{Read, Seek, SeekFrom};
use std::ptr;

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::core::PCWSTR;

use super::{FsError, FsResult, PartitionInfo};

/// A handle to a raw disk or partition with automatic sector alignment
pub struct RawDisk {
    handle: HANDLE,
    device_path: String,
    sector_size: u64,
    total_size: u64,
    current_position: u64,
}

impl RawDisk {
    /// Open a physical drive (e.g., "\\\\.\\PhysicalDrive0")
    pub fn open_physical_drive(drive_number: u32) -> FsResult<Self> {
        let device_path = format!("\\\\.\\PhysicalDrive{}", drive_number);
        Self::open(&device_path)
    }

    /// Open a partition by drive letter (e.g., "\\\\.\\E:")
    pub fn open_partition(letter: char) -> FsResult<Self> {
        let device_path = format!("\\\\.\\{}:", letter);
        Self::open(&device_path)
    }

    /// Open a device by path
    pub fn open(device_path: &str) -> FsResult<Self> {
        let wide_path: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|e| {
            FsError::RawDiskError(format!(
                "Failed to open {}: {} (Run as Administrator?)",
                device_path, e
            ))
        })?;

        // Get disk geometry to determine sector size
        let (sector_size, total_size) = Self::get_disk_geometry(handle)?;

        Ok(Self {
            handle,
            device_path: device_path.to_string(),
            sector_size,
            total_size,
            current_position: 0,
        })
    }

    fn get_disk_geometry(handle: HANDLE) -> FsResult<(u64, u64)> {
        use windows::Win32::System::IO::DeviceIoControl;
        use windows::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY_EX;

        #[repr(C)]
        #[derive(Default)]
        struct DiskGeometryEx {
            geometry: DiskGeometry,
            disk_size: i64,
            data: [u8; 1],
        }

        #[repr(C)]
        #[derive(Default)]
        struct DiskGeometry {
            cylinders: i64,
            media_type: u32,
            tracks_per_cylinder: u32,
            sectors_per_track: u32,
            bytes_per_sector: u32,
        }

        let mut geometry = DiskGeometryEx::default();
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(ptr::addr_of_mut!(geometry) as *mut _),
                std::mem::size_of::<DiskGeometryEx>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            Ok((
                geometry.geometry.bytes_per_sector as u64,
                geometry.disk_size as u64,
            ))
        } else {
            // Default to 512 bytes if we can't get geometry
            Ok((512, 0))
        }
    }

    /// Get the sector size
    pub fn sector_size(&self) -> u64 {
        self.sector_size
    }

    /// Get total disk size in bytes
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Get the device path
    pub fn device_path(&self) -> &str {
        &self.device_path
    }

    /// Perform a raw read at the current file pointer position (must be sector-aligned)
    fn raw_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;

        let mut bytes_read: u32 = 0;

        unsafe {
            ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        self.current_position += bytes_read as u64;
        Ok(bytes_read as usize)
    }

    /// Perform a raw seek (sets the file pointer)
    fn raw_seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        use windows::Win32::Storage::FileSystem::{SetFilePointerEx, FILE_BEGIN, FILE_CURRENT, FILE_END};

        let (method, distance) = match pos {
            SeekFrom::Start(n) => (FILE_BEGIN, n as i64),
            SeekFrom::Current(n) => (FILE_CURRENT, n),
            SeekFrom::End(n) => (FILE_END, n),
        };

        let mut new_position: i64 = 0;

        unsafe {
            SetFilePointerEx(self.handle, distance, Some(&mut new_position), method)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        self.current_position = new_position as u64;
        Ok(self.current_position)
    }

    /// Read at a specific offset with automatic sector alignment
    pub fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let sector_size = self.sector_size as usize;

        // Calculate alignment
        let start_sector = offset / self.sector_size;
        let offset_in_start_sector = (offset % self.sector_size) as usize;
        let end_offset = offset + buffer.len() as u64;
        let end_sector = (end_offset + self.sector_size - 1) / self.sector_size;
        let num_sectors = (end_sector - start_sector) as usize;

        // Calculate aligned read parameters
        let aligned_offset = start_sector * self.sector_size;
        let total_read_size = num_sectors * sector_size;

        // Seek to the aligned position
        self.raw_seek(SeekFrom::Start(aligned_offset))?;

        // Read aligned sectors
        let mut aligned_buffer = vec![0u8; total_read_size];
        let bytes_read = self.raw_read(&mut aligned_buffer).map_err(FsError::Io)?;

        if bytes_read == 0 {
            return Ok(0);
        }

        // Extract the requested portion
        let available = bytes_read.saturating_sub(offset_in_start_sector);
        let copy_len = std::cmp::min(buffer.len(), available);

        if copy_len > 0 {
            buffer[..copy_len].copy_from_slice(
                &aligned_buffer[offset_in_start_sector..offset_in_start_sector + copy_len],
            );
        }

        Ok(copy_len)
    }

    /// Read exactly the requested number of bytes at a specific offset
    pub fn read_exact_at(&mut self, offset: u64, buffer: &mut [u8]) -> FsResult<()> {
        let mut total_read = 0;
        while total_read < buffer.len() {
            let n = self.read_at(offset + total_read as u64, &mut buffer[total_read..])?;
            if n == 0 {
                return Err(FsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected end of disk",
                )));
            }
            total_read += n;
        }
        Ok(())
    }
}

impl Read for RawDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let sector_size = self.sector_size as usize;
        let offset = self.current_position;

        // Calculate alignment
        let start_sector = offset / self.sector_size;
        let offset_in_start_sector = (offset % self.sector_size) as usize;
        let end_offset = offset + buf.len() as u64;
        let end_sector = (end_offset + self.sector_size - 1) / self.sector_size;
        let num_sectors = (end_sector - start_sector) as usize;

        // Calculate aligned read parameters
        let aligned_offset = start_sector * self.sector_size;
        let total_read_size = num_sectors * sector_size;

        // Seek to the aligned position
        self.raw_seek(SeekFrom::Start(aligned_offset))?;

        // Read aligned sectors
        let mut aligned_buffer = vec![0u8; total_read_size];
        let bytes_read = self.raw_read(&mut aligned_buffer)?;

        if bytes_read == 0 {
            return Ok(0);
        }

        // Extract the requested portion
        let available = bytes_read.saturating_sub(offset_in_start_sector);
        let copy_len = std::cmp::min(buf.len(), available);

        if copy_len > 0 {
            buf[..copy_len].copy_from_slice(
                &aligned_buffer[offset_in_start_sector..offset_in_start_sector + copy_len],
            );
        }

        // Update our logical position
        self.current_position = offset + copy_len as u64;

        Ok(copy_len)
    }
}

impl Seek for RawDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        // Just update the logical position - actual seeking happens in read
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.current_position.saturating_add(n as u64)
                } else {
                    self.current_position.saturating_sub((-n) as u64)
                }
            }
            SeekFrom::End(n) => {
                if self.total_size == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "SeekFrom::End not supported when total size is unknown",
                    ));
                }
                if n >= 0 {
                    self.total_size.saturating_add(n as u64)
                } else {
                    self.total_size.saturating_sub((-n) as u64)
                }
            }
        };

        self.current_position = new_pos;
        Ok(self.current_position)
    }
}

impl Drop for RawDisk {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Enumerate physical drives on the system
pub fn enumerate_physical_drives() -> Vec<u32> {
    let mut drives = Vec::new();

    // Try to open drives 0-15 (most systems won't have more)
    for i in 0..16 {
        if let Ok(disk) = RawDisk::open_physical_drive(i) {
            if disk.total_size() > 0 {
                drives.push(i);
            }
        }
    }

    drives
}

/// Detect all partitions on a physical drive (GPT and MBR)
pub fn detect_partitions(drive_number: u32) -> FsResult<Vec<PartitionInfo>> {
    // First, check if this is a GPT disk by looking for the protective MBR
    if is_gpt_disk(drive_number)? {
        // This is a GPT disk, use GPT parsing only
        return detect_gpt_partitions(drive_number);
    }

    // This is a pure MBR disk
    detect_mbr_partitions(drive_number)
}

/// Check if a disk uses GPT by looking for the protective MBR or GPT signature
fn is_gpt_disk(drive_number: u32) -> FsResult<bool> {
    let mut disk = RawDisk::open_physical_drive(drive_number)?;
    let sector_size = disk.sector_size();

    // Read the first two sectors (MBR + GPT header)
    let mut buffer = vec![0u8; (sector_size * 2) as usize];
    disk.read_at(0, &mut buffer)?;

    // Check MBR for protective MBR (partition type 0xEE)
    if buffer.len() >= 512 && buffer[510] == 0x55 && buffer[511] == 0xAA {
        // Check the first partition entry for type 0xEE (GPT protective)
        let part_type = buffer[446 + 4];
        if part_type == 0xEE {
            return Ok(true);
        }
    }

    // Also check for GPT signature "EFI PART" at sector 1
    if buffer.len() >= sector_size as usize + 8 {
        let gpt_offset = sector_size as usize;
        if &buffer[gpt_offset..gpt_offset + 8] == b"EFI PART" {
            return Ok(true);
        }
    }

    Ok(false)
}

/// GPT Header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GptHeader {
    signature: [u8; 8],
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    partition_entry_lba: u64,
    num_partition_entries: u32,
    partition_entry_size: u32,
    partition_array_crc32: u32,
}

/// GPT Partition Entry structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GptPartitionEntry {
    type_guid: [u8; 16],
    partition_guid: [u8; 16],
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: [u16; 36],
}

/// Convert a GUID bytes array to a formatted string
fn guid_to_string(guid: &[u8; 16]) -> String {
    // GUID is stored in mixed-endian format
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid[3], guid[2], guid[1], guid[0],
        guid[5], guid[4],
        guid[7], guid[6],
        guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// Detect partitions on a physical drive using GPT (custom implementation using RawDisk)
pub fn detect_gpt_partitions(drive_number: u32) -> FsResult<Vec<PartitionInfo>> {
    let mut disk = RawDisk::open_physical_drive(drive_number)?;
    let sector_size = disk.sector_size();

    // Read LBA 1 (GPT header)
    let mut header_buf = vec![0u8; sector_size as usize];
    disk.read_at(sector_size, &mut header_buf)?;

    // Check GPT signature
    if &header_buf[0..8] != b"EFI PART" {
        return Err(FsError::FilesystemError("Invalid GPT signature".to_string()));
    }

    // Parse GPT header
    let header: GptHeader = unsafe {
        std::ptr::read_unaligned(header_buf.as_ptr() as *const GptHeader)
    };

    let num_entries = header.num_partition_entries;
    let entry_size = header.partition_entry_size;
    let entries_start_lba = header.partition_entry_lba;

    // Read partition entries
    let entries_size = (num_entries as u64) * (entry_size as u64);
    let entries_sectors = (entries_size + sector_size - 1) / sector_size;
    let mut entries_buf = vec![0u8; (entries_sectors * sector_size) as usize];
    disk.read_at(entries_start_lba * sector_size, &mut entries_buf)?;

    let mut partitions = Vec::new();
    let mut partition_number = 0u32;

    for i in 0..num_entries {
        let offset = (i as usize) * (entry_size as usize);
        if offset + 128 > entries_buf.len() {
            break;
        }

        let entry: GptPartitionEntry = unsafe {
            std::ptr::read_unaligned(entries_buf[offset..].as_ptr() as *const GptPartitionEntry)
        };

        // Check if entry is used (type GUID is not all zeros)
        let type_guid_zero = entry.type_guid.iter().all(|&b| b == 0);
        if type_guid_zero {
            continue;
        }

        partition_number += 1;

        let type_guid_str = guid_to_string(&entry.type_guid);
        let fs_type = identify_gpt_partition_type(&type_guid_str);

        let first_lba = entry.first_lba;
        let last_lba = entry.last_lba;
        let size = (last_lba - first_lba + 1) * sector_size;

        // Parse partition name (UTF-16LE, null-terminated)
        // Read directly from buffer to avoid unaligned access on packed struct
        let name_offset = offset + 56; // name starts at byte 56 of the partition entry
        let mut name_u16: Vec<u16> = Vec::new();
        for j in 0..36 {
            let char_offset = name_offset + j * 2;
            if char_offset + 2 <= entries_buf.len() {
                let ch = u16::from_le_bytes([entries_buf[char_offset], entries_buf[char_offset + 1]]);
                if ch == 0 {
                    break;
                }
                name_u16.push(ch);
            }
        }
        let name = String::from_utf16_lossy(&name_u16);

        partitions.push(PartitionInfo {
            device_path: format!("\\\\.\\PhysicalDrive{}", drive_number),
            label: if name.is_empty() { None } else { Some(name) },
            fs_type,
            size,
            partition_number,
        });
    }

    Ok(partitions)
}

/// MBR partition entry structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MbrPartitionEntry {
    boot_indicator: u8,
    start_head: u8,
    start_sector_cylinder: u16,
    partition_type: u8,
    end_head: u8,
    end_sector_cylinder: u16,
    start_lba: u32,
    size_sectors: u32,
}

/// Detect partitions on a physical drive using MBR (only for non-GPT disks)
pub fn detect_mbr_partitions(drive_number: u32) -> FsResult<Vec<PartitionInfo>> {
    let mut disk = RawDisk::open_physical_drive(drive_number)?;
    let sector_size = disk.sector_size();

    // Read the MBR (first sector)
    let mut mbr = vec![0u8; sector_size as usize];
    disk.read_at(0, &mut mbr)?;

    // Check MBR signature (0x55AA at offset 510)
    if mbr.len() < 512 || mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(FsError::FilesystemError("Invalid MBR signature".to_string()));
    }

    let mut partitions = Vec::new();

    // Parse the 4 primary partition entries (starting at offset 446)
    for i in 0..4 {
        let offset = 446 + i * 16;
        let entry = parse_mbr_entry(&mbr[offset..offset + 16]);

        if entry.partition_type != 0 && entry.size_sectors > 0 {
            let fs_type = identify_mbr_partition_type(entry.partition_type);
            let start_offset = entry.start_lba as u64 * sector_size;
            let size = entry.size_sectors as u64 * sector_size;

            // Skip GPT protective MBR entries - these should be handled by GPT parser
            if entry.partition_type == 0xEE {
                continue;
            }

            // Check if this is an extended partition
            if entry.partition_type == 0x05 || entry.partition_type == 0x0F {
                // Parse extended partitions recursively
                if let Ok(extended) = parse_extended_partitions(&mut disk, start_offset, sector_size, partitions.len() as u32 + 1) {
                    partitions.extend(extended);
                }
            } else {
                partitions.push(PartitionInfo {
                    device_path: format!("\\\\.\\PhysicalDrive{}", drive_number),
                    label: None,
                    fs_type,
                    size,
                    partition_number: (i + 1) as u32,
                });
            }
        }
    }

    Ok(partitions)
}

fn parse_mbr_entry(data: &[u8]) -> MbrPartitionEntry {
    MbrPartitionEntry {
        boot_indicator: data[0],
        start_head: data[1],
        start_sector_cylinder: u16::from_le_bytes([data[2], data[3]]),
        partition_type: data[4],
        end_head: data[5],
        end_sector_cylinder: u16::from_le_bytes([data[6], data[7]]),
        start_lba: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        size_sectors: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    }
}

/// Parse extended (logical) partitions
fn parse_extended_partitions(
    disk: &mut RawDisk,
    extended_start: u64,
    sector_size: u64,
    start_number: u32,
) -> FsResult<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();
    let mut current_ebr_offset = extended_start;
    let mut partition_number = start_number;

    // Limit iterations to prevent infinite loops
    for _ in 0..128 {
        let mut ebr = vec![0u8; sector_size as usize];
        disk.read_at(current_ebr_offset, &mut ebr)?;

        // Check EBR signature
        if ebr.len() < 512 || ebr[510] != 0x55 || ebr[511] != 0xAA {
            break;
        }

        // First entry: the logical partition
        let entry1 = parse_mbr_entry(&ebr[446..462]);
        if entry1.partition_type != 0 && entry1.size_sectors > 0 {
            let fs_type = identify_mbr_partition_type(entry1.partition_type);
            let size = entry1.size_sectors as u64 * sector_size;

            partitions.push(PartitionInfo {
                device_path: format!("Extended partition"),
                label: None,
                fs_type,
                size,
                partition_number,
            });
            partition_number += 1;
        }

        // Second entry: link to next EBR (relative to extended partition start)
        let entry2 = parse_mbr_entry(&ebr[462..478]);
        if entry2.partition_type == 0 || entry2.start_lba == 0 {
            break;
        }

        current_ebr_offset = extended_start + entry2.start_lba as u64 * sector_size;
    }

    Ok(partitions)
}

/// Get the starting offset and size for a partition (for mounting)
pub fn get_partition_geometry(drive_number: u32, partition_number: u32) -> FsResult<(u64, u64)> {
    // Try GPT first if this is a GPT disk
    if is_gpt_disk(drive_number).unwrap_or(false) {
        let mut disk = RawDisk::open_physical_drive(drive_number)?;
        let sector_size = disk.sector_size();

        // Read GPT header
        let mut header_buf = vec![0u8; sector_size as usize];
        disk.read_at(sector_size, &mut header_buf)?;

        if &header_buf[0..8] == b"EFI PART" {
            let header: GptHeader = unsafe {
                std::ptr::read_unaligned(header_buf.as_ptr() as *const GptHeader)
            };

            let num_entries = header.num_partition_entries;
            let entry_size = header.partition_entry_size;
            let entries_start_lba = header.partition_entry_lba;

            // Read partition entries
            let entries_size = (num_entries as u64) * (entry_size as u64);
            let entries_sectors = (entries_size + sector_size - 1) / sector_size;
            let mut entries_buf = vec![0u8; (entries_sectors * sector_size) as usize];
            disk.read_at(entries_start_lba * sector_size, &mut entries_buf)?;

            let mut current_partition = 0u32;

            for i in 0..num_entries {
                let offset = (i as usize) * (entry_size as usize);
                if offset + 128 > entries_buf.len() {
                    break;
                }

                let entry: GptPartitionEntry = unsafe {
                    std::ptr::read_unaligned(entries_buf[offset..].as_ptr() as *const GptPartitionEntry)
                };

                // Check if entry is used
                let type_guid_zero = entry.type_guid.iter().all(|&b| b == 0);
                if type_guid_zero {
                    continue;
                }

                current_partition += 1;

                if current_partition == partition_number {
                    let start_offset = entry.first_lba * sector_size;
                    let size = (entry.last_lba - entry.first_lba + 1) * sector_size;
                    return Ok((start_offset, size));
                }
            }
        }

        return Err(FsError::NotFound(format!("Partition {} not found in GPT", partition_number)));
    }

    // Fall back to MBR
    let mut disk = RawDisk::open_physical_drive(drive_number)?;
    let sector_size = disk.sector_size();

    let mut mbr = vec![0u8; sector_size as usize];
    disk.read_at(0, &mut mbr)?;

    if mbr.len() < 512 || mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(FsError::FilesystemError("Invalid MBR signature".to_string()));
    }

    let mut current_partition = 1u32;

    // Check primary partitions
    for i in 0..4 {
        let offset = 446 + i * 16;
        let entry = parse_mbr_entry(&mbr[offset..offset + 16]);

        if entry.partition_type != 0 && entry.size_sectors > 0 {
            // Extended partition - need to parse logical partitions
            if entry.partition_type == 0x05 || entry.partition_type == 0x0F {
                let extended_start = entry.start_lba as u64 * sector_size;
                let mut current_ebr_offset = extended_start;

                for _ in 0..128 {
                    let mut ebr = vec![0u8; sector_size as usize];
                    if disk.read_at(current_ebr_offset, &mut ebr).is_err() {
                        break;
                    }

                    if ebr.len() < 512 || ebr[510] != 0x55 || ebr[511] != 0xAA {
                        break;
                    }

                    let entry1 = parse_mbr_entry(&ebr[446..462]);
                    if entry1.partition_type != 0 && entry1.size_sectors > 0 {
                        current_partition += 1;
                        if current_partition == partition_number {
                            let start_offset = current_ebr_offset + entry1.start_lba as u64 * sector_size;
                            let size = entry1.size_sectors as u64 * sector_size;
                            return Ok((start_offset, size));
                        }
                    }

                    let entry2 = parse_mbr_entry(&ebr[462..478]);
                    if entry2.partition_type == 0 || entry2.start_lba == 0 {
                        break;
                    }
                    current_ebr_offset = extended_start + entry2.start_lba as u64 * sector_size;
                }
            } else {
                current_partition += 1;
                if current_partition == partition_number {
                    let start_offset = entry.start_lba as u64 * sector_size;
                    let size = entry.size_sectors as u64 * sector_size;
                    return Ok((start_offset, size));
                }
            }
        }
    }

    Err(FsError::NotFound(format!("Partition {} not found", partition_number)))
}

/// Identify partition type from GPT GUID
fn identify_gpt_partition_type(guid: &str) -> String {
    let guid_upper = guid.to_uppercase();

    match guid_upper.as_str() {
        // Linux filesystem GUIDs
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem".to_string(),
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM".to_string(),
        "933AC7E1-2EB4-4F13-B844-0E14E2AEF915" => "Linux /home".to_string(),
        "3B8F8425-20E0-4F3B-907F-1A25A76F98E8" => "Linux /srv".to_string(),
        "4D21B016-B534-45C2-A9FB-5C16E091FD2D" => "Linux /var".to_string(),
        "7EC6F557-3BC5-4ACA-B293-16EF5DF639D1" => "Linux /tmp".to_string(),
        "BC13C2FF-59E6-4262-A352-B275FD6F7172" => "Linux /boot".to_string(),
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap".to_string(),
        "CA7D7CCB-63ED-4C53-861C-1742536059CC" => "Linux LUKS".to_string(),
        "8DA63339-0007-60C0-C436-083AC8230908" => "Linux reserved".to_string(),

        // Windows filesystem GUIDs
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Windows Basic Data".to_string(),
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved".to_string(),
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery".to_string(),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System".to_string(),

        _ => format!("Unknown ({})", guid),
    }
}

/// Identify partition type from MBR type byte
fn identify_mbr_partition_type(partition_type: u8) -> String {
    match partition_type {
        // Linux types
        0x83 => "Linux filesystem".to_string(),
        0x82 => "Linux swap".to_string(),
        0x8E => "Linux LVM".to_string(),
        0xFD => "Linux RAID".to_string(),

        // Extended partitions
        0x05 => "Extended (CHS)".to_string(),
        0x0F => "Extended (LBA)".to_string(),

        // Windows/DOS types
        0x01 => "FAT12".to_string(),
        0x04 => "FAT16 <32MB".to_string(),
        0x06 => "FAT16".to_string(),
        0x07 => "NTFS/exFAT/HPFS".to_string(),
        0x0B => "FAT32 (CHS)".to_string(),
        0x0C => "FAT32 (LBA)".to_string(),
        0x0E => "FAT16 (LBA)".to_string(),
        0x11 => "Hidden FAT12".to_string(),
        0x14 => "Hidden FAT16 <32MB".to_string(),
        0x16 => "Hidden FAT16".to_string(),
        0x17 => "Hidden NTFS".to_string(),
        0x1B => "Hidden FAT32 (CHS)".to_string(),
        0x1C => "Hidden FAT32 (LBA)".to_string(),
        0x1E => "Hidden FAT16 (LBA)".to_string(),
        0x27 => "Windows Recovery".to_string(),

        // EFI
        0xEE => "GPT Protective MBR".to_string(),
        0xEF => "EFI System".to_string(),

        // Other
        0x00 => "Empty".to_string(),
        _ => format!("Unknown (0x{:02X})", partition_type),
    }
}

/// Check if we can potentially read this partition as ext4
pub fn is_potentially_ext4(partition: &PartitionInfo) -> bool {
    let fs = &partition.fs_type;
    (fs.contains("Linux") || fs.contains("linux"))
        && !fs.contains("swap")
        && !fs.contains("Swap")
        && !fs.contains("GPT Protective")
}
