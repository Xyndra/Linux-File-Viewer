//! Btrfs filesystem implementation
//!
//! This module provides read-only access to btrfs filesystems.
//! Currently supports basic file and directory listing.

#![allow(dead_code)]

use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};

use btrfs_diskformat::SuperBlock;

use super::{EntryMetadata, EntryType, FsEntry, FsError, FsResult};

/// Btrfs magic number
pub const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";

/// Btrfs superblock offset
pub const BTRFS_SUPERBLOCK_OFFSET: u64 = 0x10000; // 64 KiB

/// Minimum sector size
pub const BTRFS_SECTOR_SIZE: u64 = 4096;

/// Object IDs
pub const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
pub const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
pub const BTRFS_CHUNK_TREE_OBJECTID: u64 = 3;
pub const BTRFS_DEV_TREE_OBJECTID: u64 = 4;
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;
pub const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;
pub const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;

/// Item types
pub const BTRFS_INODE_ITEM_KEY: u8 = 1;
pub const BTRFS_INODE_REF_KEY: u8 = 12;
pub const BTRFS_DIR_ITEM_KEY: u8 = 84;
pub const BTRFS_DIR_INDEX_KEY: u8 = 96;
pub const BTRFS_EXTENT_DATA_KEY: u8 = 108;
pub const BTRFS_ROOT_ITEM_KEY: u8 = 132;
pub const BTRFS_ROOT_REF_KEY: u8 = 156;
pub const BTRFS_CHUNK_ITEM_KEY: u8 = 228;

/// File types in directory entries
pub const BTRFS_FT_UNKNOWN: u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR: u8 = 2;
pub const BTRFS_FT_CHRDEV: u8 = 3;
pub const BTRFS_FT_BLKDEV: u8 = 4;
pub const BTRFS_FT_FIFO: u8 = 5;
pub const BTRFS_FT_SOCK: u8 = 6;
pub const BTRFS_FT_SYMLINK: u8 = 7;

/// Btrfs inode item
#[derive(Debug, Clone, Default)]
struct InodeItem {
    generation: u64,
    transid: u64,
    size: u64,
    nbytes: u64,
    block_group: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u64,
    flags: u64,
}

/// Btrfs directory entry
#[derive(Debug, Clone)]
struct DirEntry {
    location_objectid: u64,
    location_type: u8,
    location_offset: u64,
    transid: u64,
    data_len: u16,
    name_len: u16,
    file_type: u8,
    name: String,
}

/// Chunk mapping entry for logical to physical address translation
#[derive(Debug, Clone)]
struct ChunkMapping {
    logical_start: u64,
    logical_size: u64,
    stripe_len: u64,
    stripe_type: u64,
    stripe_offset: u64,
    num_stripes: u16,
}

/// Node header for btrfs b-tree nodes
#[derive(Debug, Clone)]
struct NodeHeader {
    csum: [u8; 32],
    fs_uuid: [u8; 16],
    bytenr: u64,
    flags: u64,
    chunk_tree_uuid: [u8; 16],
    generation: u64,
    owner: u64,
    nritems: u32,
    level: u8,
}

/// Leaf item (key + data)
#[derive(Debug, Clone)]
struct LeafItem {
    key: BtrfsKey,
    data_offset: u32,
    data_size: u32,
}

/// Btrfs key
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct BtrfsKey {
    objectid: u64,
    item_type: u8,
    offset: u64,
}

/// Btrfs filesystem implementation
pub struct BtrfsFs<R: Read + Seek> {
    /// Filesystem label/name
    name: String,
    /// Reader for the underlying storage
    reader: RefCell<R>,
    /// Parsed superblock
    superblock: SuperBlock,
    /// Chunk mappings for address translation
    chunk_map: Vec<ChunkMapping>,
    /// Sector size
    sector_size: u64,
    /// Node size
    node_size: u64,
    /// Root tree root address
    root_tree_root: u64,
    /// Filesystem tree root address
    fs_tree_root: u64,
}

/// Check if data contains btrfs magic at the expected offset
pub fn is_btrfs(data: &[u8]) -> bool {
    // The magic is at offset 0x40 within the superblock
    if data.len() < 0x48 {
        return false;
    }
    &data[0x40..0x48] == BTRFS_MAGIC
}

/// Probe for btrfs at the standard superblock location
pub fn probe_btrfs<R: Read + Seek>(reader: &mut R) -> FsResult<bool> {
    let mut superblock_start = [0u8; 0x48];
    reader.seek(SeekFrom::Start(BTRFS_SUPERBLOCK_OFFSET))?;
    if reader.read(&mut superblock_start)? < superblock_start.len() {
        return Ok(false);
    }
    Ok(is_btrfs(&superblock_start))
}

impl<R: Read + Seek> BtrfsFs<R> {
    /// Create a new BtrfsFs from a reader
    pub fn new(mut reader: R, label: Option<String>) -> FsResult<Self> {
        // Read superblock
        let mut sb_data = [0u8; 4096];
        reader.seek(SeekFrom::Start(BTRFS_SUPERBLOCK_OFFSET))?;
        reader.read_exact(&mut sb_data).map_err(|e| {
            FsError::FilesystemError(format!("Failed to read btrfs superblock: {}", e))
        })?;

        if !is_btrfs(&sb_data) {
            return Err(FsError::FilesystemError("Invalid btrfs magic".to_string()));
        }

        // Parse superblock using btrfs-diskformat
        let superblock: SuperBlock =
            unsafe { std::ptr::read_unaligned(sb_data.as_ptr() as *const SuperBlock) };

        // Extract key values from superblock
        // Correct offsets based on btrfs superblock structure:
        // sectorsize is at offset 0x90, nodesize is at offset 0x94
        let sector_size =
            u32::from_le_bytes([sb_data[0x90], sb_data[0x91], sb_data[0x92], sb_data[0x93]]) as u64;
        let node_size =
            u32::from_le_bytes([sb_data[0x94], sb_data[0x95], sb_data[0x96], sb_data[0x97]]) as u64;
        let root_tree_root = u64::from_le_bytes([
            sb_data[0x50],
            sb_data[0x51],
            sb_data[0x52],
            sb_data[0x53],
            sb_data[0x54],
            sb_data[0x55],
            sb_data[0x56],
            sb_data[0x57],
        ]);

        // Get the label from superblock (offset 0x12B, 256 bytes max)
        let label_offset = 0x12B;
        let label_bytes = &sb_data[label_offset..label_offset + 256];
        let sb_label = {
            let end = label_bytes.iter().position(|&b| b == 0).unwrap_or(256);
            String::from_utf8_lossy(&label_bytes[..end]).to_string()
        };

        let name = label
            .or({
                if sb_label.is_empty() {
                    None
                } else {
                    Some(sb_label)
                }
            })
            .unwrap_or_else(|| "Btrfs Partition".to_string());

        // Parse system chunk array from superblock for initial chunk mappings
        let chunk_map = Self::parse_system_chunk_array(&sb_data)?;

        eprintln!(
            "Btrfs: sector_size={}, node_size={}, root_tree_root={:#x}, sys_chunks={}",
            sector_size,
            node_size,
            root_tree_root,
            chunk_map.len()
        );

        // Get chunk_root address to read chunk tree for complete mappings
        let chunk_root = u64::from_le_bytes([
            sb_data[0x58],
            sb_data[0x59],
            sb_data[0x5A],
            sb_data[0x5B],
            sb_data[0x5C],
            sb_data[0x5D],
            sb_data[0x5E],
            sb_data[0x5F],
        ]);

        eprintln!("Btrfs: chunk_root={:#x}", chunk_root);

        // We need to find the fs tree root by reading the root tree
        // For now, use a placeholder - we'll resolve it when needed
        let fs_tree_root = 0;

        let mut btrfs = Self {
            name,
            reader: RefCell::new(reader),
            superblock,
            chunk_map,
            sector_size,
            node_size,
            root_tree_root,
            fs_tree_root,
        };

        // Now read the chunk tree to get all chunk mappings
        if let Err(e) = btrfs.load_chunk_tree(chunk_root) {
            eprintln!("Btrfs: Warning: Failed to load chunk tree: {}", e);
            // Continue anyway - we might have enough from sys_chunk_array
        }

        eprintln!(
            "Btrfs: After chunk tree load, chunk_map entries={}",
            btrfs.chunk_map.len()
        );

        // Dump chunk map for diagnostics
        for (i, chunk) in btrfs.chunk_map.iter().enumerate() {
            eprintln!(
                "Btrfs: chunk_map[{}]: logical={:#x}..{:#x}, phys_offset={:#x}, stripes={}, type={:#x}",
                i,
                chunk.logical_start,
                chunk.logical_start + chunk.logical_size,
                chunk.stripe_offset,
                chunk.num_stripes,
                chunk.stripe_type,
            );
        }

        // Eagerly resolve FS tree root now that chunk map is complete
        match btrfs.find_fs_tree_root() {
            Ok(addr) => {
                eprintln!("Btrfs: Resolved fs_tree_root={:#x}", addr);
                btrfs.fs_tree_root = addr;
            }
            Err(e) => {
                eprintln!("Btrfs: Warning: Could not resolve fs_tree_root: {}", e);
                // Continue — will retry lazily when needed
            }
        }

        Ok(btrfs)
    }

    /// Load all chunk mappings from the chunk tree
    fn load_chunk_tree(&mut self, chunk_root: u64) -> FsResult<()> {
        // Read the chunk tree root node
        let node_data = self.read_node(chunk_root)?;
        let header = self.parse_node_header(&node_data)?;

        eprintln!(
            "Btrfs: chunk tree root: level={}, nritems={}, owner={}, bytenr={:#x}",
            header.level, header.nritems, header.owner, header.bytenr
        );

        let before = self.chunk_map.len();

        // Parse chunk items from this node (recursively if needed)
        self.parse_chunk_tree_node(&node_data, &header)?;

        eprintln!(
            "Btrfs: chunk tree loaded {} new mappings (total {})",
            self.chunk_map.len() - before,
            self.chunk_map.len()
        );

        Ok(())
    }

    /// Parse a chunk tree node for chunk items
    fn parse_chunk_tree_node(&mut self, node_data: &[u8], header: &NodeHeader) -> FsResult<()> {
        if header.level == 0 {
            // Leaf node - parse chunk items
            let items = self.parse_leaf_items(node_data, header.nritems)?;

            for item in items {
                if item.key.item_type == BTRFS_CHUNK_ITEM_KEY {
                    // data_offset is relative to end of header (101 bytes)
                    let header_size = 101usize;
                    let data_start = header_size + item.data_offset as usize;
                    let data_end = data_start + item.data_size as usize;

                    if data_start >= header_size
                        && data_end <= node_data.len()
                        && item.data_size >= 48
                    {
                        let chunk_data = &node_data[data_start..data_end];

                        if let Some(mapping) = self.parse_chunk_item(item.key.offset, chunk_data) {
                            // Skip invalid chunks (size=0 or unreasonably large)
                            if mapping.logical_size == 0
                                || mapping.logical_size > 0x100000000000
                                || mapping.stripe_offset > 0x100000000000
                            {
                                continue;
                            }
                            // Check if we already have this chunk
                            let exists = self
                                .chunk_map
                                .iter()
                                .any(|c| c.logical_start == mapping.logical_start);
                            if !exists {
                                self.chunk_map.push(mapping);
                            }
                        }
                    }
                }
            }
        } else {
            // Internal node - recurse into children
            let ptr_size = 33; // Key (17) + blockptr (8) + generation (8)

            for i in 0..header.nritems {
                let ptr_offset = 101 + (i as usize * ptr_size);
                if ptr_offset + ptr_size > node_data.len() {
                    break;
                }

                let child_addr = u64::from_le_bytes([
                    node_data[ptr_offset + 17],
                    node_data[ptr_offset + 18],
                    node_data[ptr_offset + 19],
                    node_data[ptr_offset + 20],
                    node_data[ptr_offset + 21],
                    node_data[ptr_offset + 22],
                    node_data[ptr_offset + 23],
                    node_data[ptr_offset + 24],
                ]);

                if let Ok(child_data) = self.read_node(child_addr) {
                    if let Ok(child_header) = self.parse_node_header(&child_data) {
                        let _ = self.parse_chunk_tree_node(&child_data, &child_header);
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a chunk item into a ChunkMapping
    fn parse_chunk_item(&self, logical_start: u64, data: &[u8]) -> Option<ChunkMapping> {
        if data.len() < 48 {
            return None;
        }

        let logical_size = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let stripe_len = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        let stripe_type = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);

        let num_stripes = u16::from_le_bytes([data[44], data[45]]);

        // Read first stripe offset (each stripe is 32 bytes, starts after chunk header at offset 48)
        let stripe_offset = if data.len() >= 48 + 16 {
            // Stripe structure: devid (8 bytes) + offset (8 bytes) + dev_uuid (16 bytes)
            u64::from_le_bytes([
                data[48 + 8],
                data[48 + 9],
                data[48 + 10],
                data[48 + 11],
                data[48 + 12],
                data[48 + 13],
                data[48 + 14],
                data[48 + 15],
            ])
        } else {
            logical_start // Fallback
        };

        Some(ChunkMapping {
            logical_start,
            logical_size,
            stripe_len,
            stripe_type,
            stripe_offset,
            num_stripes,
        })
    }

    /// Parse the system chunk array from the superblock
    fn parse_system_chunk_array(sb_data: &[u8]) -> FsResult<Vec<ChunkMapping>> {
        let mut chunks = Vec::new();

        // System chunk array size is at offset 0xA0 (after sectorsize, nodesize, leafsize, stripesize)
        // System chunk array data starts at offset 0x32B
        let sys_chunk_array_size =
            u32::from_le_bytes([sb_data[0xA0], sb_data[0xA1], sb_data[0xA2], sb_data[0xA3]])
                as usize;

        eprintln!(
            "Btrfs: sys_chunk_array_size={} (at offset 0xA0)",
            sys_chunk_array_size
        );

        if sys_chunk_array_size == 0 || sys_chunk_array_size > 2048 {
            // No system chunks or invalid
            eprintln!("Btrfs: sys_chunk_array_size invalid or zero, skipping chunk parsing");
            return Ok(chunks);
        }

        let array_start = 0x32B;
        let mut offset = 0;

        while offset < sys_chunk_array_size && array_start + offset + 48 <= sb_data.len() {
            let base = array_start + offset;

            // Read chunk key (17 bytes): objectid (8) + type (1) + offset (8)
            // The offset field in the key IS the logical address for chunk items
            let _key_objectid = u64::from_le_bytes([
                sb_data[base],
                sb_data[base + 1],
                sb_data[base + 2],
                sb_data[base + 3],
                sb_data[base + 4],
                sb_data[base + 5],
                sb_data[base + 6],
                sb_data[base + 7],
            ]);
            let _key_type = sb_data[base + 8];
            let logical_start = u64::from_le_bytes([
                sb_data[base + 9],
                sb_data[base + 10],
                sb_data[base + 11],
                sb_data[base + 12],
                sb_data[base + 13],
                sb_data[base + 14],
                sb_data[base + 15],
                sb_data[base + 16],
            ]);

            // Skip over key (17 bytes)
            let chunk_base = base + 17;
            if chunk_base + 48 > sb_data.len() {
                break;
            }

            // Parse chunk item
            let logical_size = u64::from_le_bytes([
                sb_data[chunk_base],
                sb_data[chunk_base + 1],
                sb_data[chunk_base + 2],
                sb_data[chunk_base + 3],
                sb_data[chunk_base + 4],
                sb_data[chunk_base + 5],
                sb_data[chunk_base + 6],
                sb_data[chunk_base + 7],
            ]);

            let stripe_len = u64::from_le_bytes([
                sb_data[chunk_base + 16],
                sb_data[chunk_base + 17],
                sb_data[chunk_base + 18],
                sb_data[chunk_base + 19],
                sb_data[chunk_base + 20],
                sb_data[chunk_base + 21],
                sb_data[chunk_base + 22],
                sb_data[chunk_base + 23],
            ]);

            let stripe_type = u64::from_le_bytes([
                sb_data[chunk_base + 24],
                sb_data[chunk_base + 25],
                sb_data[chunk_base + 26],
                sb_data[chunk_base + 27],
                sb_data[chunk_base + 28],
                sb_data[chunk_base + 29],
                sb_data[chunk_base + 30],
                sb_data[chunk_base + 31],
            ]);

            let num_stripes =
                u16::from_le_bytes([sb_data[chunk_base + 44], sb_data[chunk_base + 45]]);

            // Read first stripe offset (each stripe is 32 bytes, starts after chunk header)
            let stripe_base = chunk_base + 48;
            let stripe_offset = if stripe_base + 16 <= sb_data.len() {
                // Stripe offset is at bytes 8-15 of the stripe structure
                u64::from_le_bytes([
                    sb_data[stripe_base + 8],
                    sb_data[stripe_base + 9],
                    sb_data[stripe_base + 10],
                    sb_data[stripe_base + 11],
                    sb_data[stripe_base + 12],
                    sb_data[stripe_base + 13],
                    sb_data[stripe_base + 14],
                    sb_data[stripe_base + 15],
                ])
            } else {
                logical_start // Fallback
            };

            chunks.push(ChunkMapping {
                logical_start,
                logical_size,
                stripe_len,
                stripe_type,
                stripe_offset,
                num_stripes,
            });

            // Move to next entry (17 byte key + 48 byte chunk header + 32 * num_stripes)
            offset += 17 + 48 + (num_stripes as usize * 32);
        }

        Ok(chunks)
    }

    /// Translate a logical address to a physical address
    fn logical_to_physical(&self, logical: u64) -> FsResult<u64> {
        for chunk in &self.chunk_map {
            if logical >= chunk.logical_start && logical < chunk.logical_start + chunk.logical_size
            {
                let offset_in_chunk = logical - chunk.logical_start;
                let physical = chunk.stripe_offset + offset_in_chunk;
                return Ok(physical);
            }
        }

        // No mapping found — this likely means the chunk map is incomplete
        eprintln!(
            "Btrfs: WARNING: No chunk mapping for logical address {:#x} (chunk_map has {} entries)",
            logical,
            self.chunk_map.len()
        );
        Err(FsError::FilesystemError(format!(
            "No chunk mapping found for logical address {:#x}",
            logical
        )))
    }

    /// Read a tree node from disk
    fn read_node(&self, logical_addr: u64) -> FsResult<Vec<u8>> {
        let physical_addr = self.logical_to_physical(logical_addr)?;

        let mut reader = self.reader.borrow_mut();
        reader.seek(SeekFrom::Start(physical_addr)).map_err(|e| {
            FsError::FilesystemError(format!(
                "Failed to seek to btrfs node at {:#x}: {}",
                physical_addr, e
            ))
        })?;

        let mut node_data = vec![0u8; self.node_size as usize];
        reader.read_exact(&mut node_data).map_err(|e| {
            FsError::FilesystemError(format!(
                "Failed to read btrfs node at {:#x}: {}",
                physical_addr, e
            ))
        })?;

        Ok(node_data)
    }

    /// Parse a node header
    fn parse_node_header(&self, data: &[u8]) -> FsResult<NodeHeader> {
        if data.len() < 101 {
            return Err(FsError::FilesystemError(
                "Node data too small for header".to_string(),
            ));
        }

        let mut csum = [0u8; 32];
        csum.copy_from_slice(&data[0..32]);

        let mut fs_uuid = [0u8; 16];
        fs_uuid.copy_from_slice(&data[32..48]);

        let bytenr = u64::from_le_bytes([
            data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
        ]);

        let flags = u64::from_le_bytes([
            data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
        ]);

        let mut chunk_tree_uuid = [0u8; 16];
        chunk_tree_uuid.copy_from_slice(&data[64..80]);

        let generation = u64::from_le_bytes([
            data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
        ]);

        let owner = u64::from_le_bytes([
            data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
        ]);

        let nritems = u32::from_le_bytes([data[96], data[97], data[98], data[99]]);
        let level = data[100];

        Ok(NodeHeader {
            csum,
            fs_uuid,
            bytenr,
            flags,
            chunk_tree_uuid,
            generation,
            owner,
            nritems,
            level,
        })
    }

    /// Parse a btrfs key from bytes
    fn parse_key(&self, data: &[u8]) -> BtrfsKey {
        BtrfsKey {
            objectid: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            item_type: data[8],
            offset: u64::from_le_bytes([
                data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            ]),
        }
    }

    /// Parse leaf items from a node
    fn parse_leaf_items(&self, data: &[u8], nritems: u32) -> FsResult<Vec<LeafItem>> {
        let mut items = Vec::with_capacity(nritems as usize);
        let header_size = 101; // Node header size

        for i in 0..nritems {
            let item_offset = header_size + (i as usize * 25);
            if item_offset + 25 > data.len() {
                break;
            }

            let key = self.parse_key(&data[item_offset..]);
            // data_offset is u32 at bytes 17..21 (offset 0x11), relative to end of header (101)
            // data_size is u32 at bytes 21..25 (offset 0x15)
            let data_offset = u32::from_le_bytes([
                data[item_offset + 17],
                data[item_offset + 18],
                data[item_offset + 19],
                data[item_offset + 20],
            ]);
            let data_size = u32::from_le_bytes([
                data[item_offset + 21],
                data[item_offset + 22],
                data[item_offset + 23],
                data[item_offset + 24],
            ]);

            items.push(LeafItem {
                key,
                data_offset,
                data_size,
            });
        }

        Ok(items)
    }

    /// Parse a directory entry from leaf data
    fn parse_dir_entry(&self, data: &[u8]) -> FsResult<DirEntry> {
        if data.len() < 30 {
            return Err(FsError::FilesystemError(
                "Dir entry data too small".to_string(),
            ));
        }

        let location_objectid = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let location_type = data[8];
        let location_offset = u64::from_le_bytes([
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        ]);
        let transid = u64::from_le_bytes([
            data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24],
        ]);
        let data_len = u16::from_le_bytes([data[25], data[26]]);
        let name_len = u16::from_le_bytes([data[27], data[28]]);
        let file_type = data[29];

        let name_start = 30;
        let name_end = name_start + name_len as usize;
        let name = if name_end <= data.len() {
            String::from_utf8_lossy(&data[name_start..name_end]).to_string()
        } else {
            String::new()
        };

        Ok(DirEntry {
            location_objectid,
            location_type,
            location_offset,
            transid,
            data_len,
            name_len,
            file_type,
            name,
        })
    }

    /// Parse an inode item from leaf data
    fn parse_inode_item(&self, data: &[u8]) -> FsResult<InodeItem> {
        if data.len() < 160 {
            return Err(FsError::FilesystemError(
                "Inode item data too small".to_string(),
            ));
        }

        Ok(InodeItem {
            generation: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            transid: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            size: u64::from_le_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            nbytes: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            block_group: u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            nlink: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            uid: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            gid: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            mode: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            rdev: u64::from_le_bytes([
                data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
            ]),
            flags: u64::from_le_bytes([
                data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
            ]),
        })
    }

    /// Parse key pointers from an internal node, returning (key, child_block_addr) pairs
    fn parse_internal_key_ptrs(&self, data: &[u8], nritems: u32) -> Vec<(BtrfsKey, u64)> {
        let header_size = 101;
        let ptr_size = 33; // Key (17) + blockptr (8) + generation (8)
        let mut ptrs = Vec::with_capacity(nritems as usize);

        for i in 0..nritems as usize {
            let ptr_offset = header_size + i * ptr_size;
            if ptr_offset + ptr_size > data.len() {
                break;
            }

            let key = self.parse_key(&data[ptr_offset..]);
            let child_addr = u64::from_le_bytes([
                data[ptr_offset + 17],
                data[ptr_offset + 18],
                data[ptr_offset + 19],
                data[ptr_offset + 20],
                data[ptr_offset + 21],
                data[ptr_offset + 22],
                data[ptr_offset + 23],
                data[ptr_offset + 24],
            ]);

            ptrs.push((key, child_addr));
        }

        ptrs
    }

    /// Search a B-tree for items matching criteria.
    ///
    /// Uses key-based pruning on internal nodes to avoid visiting children
    /// that cannot contain the target objectid, and stops early in leaf nodes
    /// once items have moved past the target.
    fn search_tree(
        &self,
        tree_root: u64,
        target_objectid: u64,
        target_type: Option<u8>,
    ) -> FsResult<Vec<(BtrfsKey, Vec<u8>)>> {
        let mut results = Vec::new();

        // Read the root node
        let node_data = self.read_node(tree_root)?;
        let header = self.parse_node_header(&node_data)?;

        if header.level == 0 {
            // Leaf node - items are sorted by key, so we can skip and stop early
            let items = self.parse_leaf_items(&node_data, header.nritems)?;
            let header_size = 101usize;

            for item in items.iter() {
                // Items are sorted; if we've passed the target objectid, stop
                if item.key.objectid > target_objectid {
                    break;
                }

                if item.key.objectid != target_objectid {
                    continue;
                }

                // Objectid matches — check type filter
                if let Some(t) = target_type {
                    if item.key.item_type != t {
                        // If the item type is already past what we want, we can stop
                        // (types are sorted within the same objectid)
                        if item.key.item_type > t {
                            break;
                        }
                        continue;
                    }
                }

                // Extract item data - data_offset is relative to end of header (101 bytes)
                let data_start = header_size + item.data_offset as usize;
                let data_end = data_start + item.data_size as usize;

                if data_end <= node_data.len() {
                    results.push((item.key, node_data[data_start..data_end].to_vec()));
                }
            }
        } else {
            // Internal node — each key pointer [i] is the *lowest* key in child [i].
            // Child [i] contains keys from ptr[i].key (inclusive) up to ptr[i+1].key (exclusive).
            // We only need to recurse into children whose key range overlaps the target.
            let ptrs = self.parse_internal_key_ptrs(&node_data, header.nritems);

            for (i, (key, child_addr)) in ptrs.iter().enumerate() {
                // Skip: this child's entire range is before the target objectid.
                // The next pointer's key is the lower bound of the next child,
                // so all items in this child have objectid < next_oid.
                if let Some((next_key, _)) = ptrs.get(i + 1) {
                    if next_key.objectid < target_objectid {
                        continue;
                    }
                }

                // Stop: this child and all subsequent ones start past the target
                if key.objectid > target_objectid {
                    break;
                }

                if let Ok(child_results) =
                    self.search_tree(*child_addr, target_objectid, target_type)
                {
                    results.extend(child_results);
                }
            }
        }

        Ok(results)
    }

    /// Find the filesystem tree root
    fn find_fs_tree_root(&self) -> FsResult<u64> {
        eprintln!(
            "Btrfs: Searching for FS_TREE (objectid={}) in root tree at {:#x}",
            BTRFS_FS_TREE_OBJECTID, self.root_tree_root
        );

        // Search the root tree for the FS tree root item
        let results = self.search_tree(
            self.root_tree_root,
            BTRFS_FS_TREE_OBJECTID,
            Some(BTRFS_ROOT_ITEM_KEY),
        )?;

        eprintln!("Btrfs: search_tree returned {} results", results.len());

        for (key, data) in &results {
            eprintln!(
                "Btrfs: Found item: objectid={:#x}, type={}, offset={:#x}, data_len={}",
                key.objectid,
                key.item_type,
                key.offset,
                data.len()
            );

            // btrfs_root_item layout:
            //   0..160   btrfs_inode_item (160 bytes)
            //   160..168 generation (u64)
            //   168..176 root_dirid (u64)
            //   176..184 bytenr (u64) — the root node logical address
            if data.len() >= 184 {
                let root_addr = u64::from_le_bytes([
                    data[176], data[177], data[178], data[179], data[180], data[181], data[182],
                    data[183],
                ]);
                eprintln!("Btrfs: Found FS_TREE root at {:#x}", root_addr);
                return Ok(root_addr);
            } else {
                eprintln!(
                    "Btrfs: ROOT_ITEM data too small ({} bytes, need >= 184)",
                    data.len()
                );
            }
        }

        eprintln!("Btrfs: Could not find filesystem tree root");
        Err(FsError::FilesystemError(
            "Could not find filesystem tree root".to_string(),
        ))
    }

    /// Convert btrfs file type to our entry type
    fn file_type_to_entry_type(ft: u8) -> EntryType {
        match ft {
            BTRFS_FT_REG_FILE => EntryType::File,
            BTRFS_FT_DIR => EntryType::Directory,
            BTRFS_FT_SYMLINK => EntryType::Symlink,
            _ => EntryType::Other,
        }
    }

    /// Get the display name of this filesystem
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the root path(s) of this filesystem
    pub fn roots(&self) -> FsResult<Vec<String>> {
        Ok(vec!["/".to_string()])
    }

    /// Resolve a path to an inode number
    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        let fs_root = if self.fs_tree_root != 0 {
            self.fs_tree_root
        } else {
            self.find_fs_tree_root()?
        };

        let normalized = if path.is_empty() || path == "/" {
            return Ok(BTRFS_FIRST_FREE_OBJECTID); // Root directory inode
        } else {
            path.trim_start_matches('/')
        };

        let mut current_inode = BTRFS_FIRST_FREE_OBJECTID;

        for component in normalized.split('/') {
            if component.is_empty() {
                continue;
            }

            // Search for directory entries in current inode
            let entries = self.search_tree(fs_root, current_inode, Some(BTRFS_DIR_ITEM_KEY))?;

            let mut found = false;
            for (_, data) in entries {
                if let Ok(dir_entry) = self.parse_dir_entry(&data) {
                    if dir_entry.name == component {
                        current_inode = dir_entry.location_objectid;
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return Err(FsError::NotFound(format!("Path not found: {}", path)));
            }
        }

        Ok(current_inode)
    }

    /// List entries in a directory
    pub fn list_dir(&self, path: &str) -> FsResult<Vec<FsEntry>> {
        let fs_root = if self.fs_tree_root != 0 {
            self.fs_tree_root
        } else {
            self.find_fs_tree_root()?
        };

        let dir_inode = self.resolve_path(path)?;

        // Get directory entries
        let entries = self.search_tree(fs_root, dir_inode, Some(BTRFS_DIR_INDEX_KEY))?;

        let mut result = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for (_, data) in entries {
            if let Ok(dir_entry) = self.parse_dir_entry(&data) {
                // Skip . and ..
                if dir_entry.name == "." || dir_entry.name == ".." {
                    continue;
                }

                // Skip duplicates
                if seen_names.contains(&dir_entry.name) {
                    continue;
                }
                seen_names.insert(dir_entry.name.clone());

                let entry_path = if path == "/" || path.is_empty() {
                    format!("/{}", dir_entry.name)
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), dir_entry.name)
                };

                let entry_type = Self::file_type_to_entry_type(dir_entry.file_type);

                // Try to get inode info for size
                let mut size = 0u64;
                let mut mode = 0u32;

                if let Ok(inode_results) = self.search_tree(
                    fs_root,
                    dir_entry.location_objectid,
                    Some(BTRFS_INODE_ITEM_KEY),
                ) {
                    for (_, inode_data) in inode_results {
                        if let Ok(inode) = self.parse_inode_item(&inode_data) {
                            size = inode.size;
                            mode = inode.mode;
                            break;
                        }
                    }
                }

                let metadata = EntryMetadata {
                    name: dir_entry.name.clone(),
                    entry_type,
                    size,
                    modified: None,
                    created: None,
                    accessed: None,
                    readonly: (mode & 0o222) == 0,
                    hidden: dir_entry.name.starts_with('.'),
                };

                result.push(FsEntry {
                    path: entry_path,
                    metadata,
                });
            }
        }

        // Sort entries
        result.sort_by(|a, b| match (a.metadata.is_dir(), b.metadata.is_dir()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .metadata
                .name
                .to_lowercase()
                .cmp(&b.metadata.name.to_lowercase()),
        });

        Ok(result)
    }

    /// Get metadata for a path
    pub fn metadata(&self, path: &str) -> FsResult<EntryMetadata> {
        let fs_root = if self.fs_tree_root != 0 {
            self.fs_tree_root
        } else {
            self.find_fs_tree_root()?
        };

        let inode = self.resolve_path(path)?;

        // Get inode item
        let results = self.search_tree(fs_root, inode, Some(BTRFS_INODE_ITEM_KEY))?;

        for (_, data) in results {
            if let Ok(inode_item) = self.parse_inode_item(&data) {
                let entry_type = if (inode_item.mode & 0o170000) == 0o040000 {
                    EntryType::Directory
                } else if (inode_item.mode & 0o170000) == 0o120000 {
                    EntryType::Symlink
                } else if (inode_item.mode & 0o170000) == 0o100000 {
                    EntryType::File
                } else {
                    EntryType::Other
                };

                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                let name = if name.is_empty() {
                    "/".to_string()
                } else {
                    name
                };

                return Ok(EntryMetadata {
                    name: name.clone(),
                    entry_type,
                    size: inode_item.size,
                    modified: None,
                    created: None,
                    accessed: None,
                    readonly: (inode_item.mode & 0o222) == 0,
                    hidden: name.starts_with('.'),
                });
            }
        }

        Err(FsError::NotFound(format!(
            "Could not get metadata for: {}",
            path
        )))
    }

    /// Read file contents (simplified - doesn't handle all extent types)
    pub fn read_file(&self, path: &str) -> FsResult<Vec<u8>> {
        let fs_root = if self.fs_tree_root != 0 {
            self.fs_tree_root
        } else {
            self.find_fs_tree_root()?
        };

        let inode = self.resolve_path(path)?;

        // Get file size first
        let meta = self.metadata(path)?;
        if meta.entry_type != EntryType::File {
            return Err(FsError::NotAFile(path.to_string()));
        }

        if meta.size == 0 {
            return Ok(Vec::new());
        }

        // Get extent data items
        let results = self.search_tree(fs_root, inode, Some(BTRFS_EXTENT_DATA_KEY))?;

        let mut file_data = vec![0u8; meta.size as usize];

        for (key, data) in results {
            if data.len() < 21 {
                continue;
            }

            let file_offset = key.offset;
            let compression = data[16];
            let extent_type = data[20];

            if extent_type == 0 {
                // Inline extent
                let inline_data_start = 21;
                let inline_data = &data[inline_data_start..];
                let copy_len =
                    std::cmp::min(inline_data.len(), file_data.len() - file_offset as usize);
                if file_offset as usize + copy_len <= file_data.len() {
                    file_data[file_offset as usize..file_offset as usize + copy_len]
                        .copy_from_slice(&inline_data[..copy_len]);
                }
            } else if extent_type == 1 && compression == 0 {
                // Regular extent (uncompressed)
                if data.len() < 53 {
                    continue;
                }

                let disk_bytenr = u64::from_le_bytes([
                    data[21], data[22], data[23], data[24], data[25], data[26], data[27], data[28],
                ]);
                let _disk_num_bytes = u64::from_le_bytes([
                    data[29], data[30], data[31], data[32], data[33], data[34], data[35], data[36],
                ]);
                let extent_offset = u64::from_le_bytes([
                    data[37], data[38], data[39], data[40], data[41], data[42], data[43], data[44],
                ]);
                let num_bytes = u64::from_le_bytes([
                    data[45], data[46], data[47], data[48], data[49], data[50], data[51], data[52],
                ]);

                if disk_bytenr == 0 {
                    // Sparse extent (hole)
                    continue;
                }

                // Read the extent data
                let phys_addr = self.logical_to_physical(disk_bytenr + extent_offset)?;
                let mut reader = self.reader.borrow_mut();
                reader.seek(SeekFrom::Start(phys_addr))?;

                let read_len =
                    std::cmp::min(num_bytes as usize, file_data.len() - file_offset as usize);
                let mut extent_data = vec![0u8; read_len];
                reader.read_exact(&mut extent_data)?;

                let dest_start = file_offset as usize;
                let dest_end = dest_start + read_len;
                if dest_end <= file_data.len() {
                    file_data[dest_start..dest_end].copy_from_slice(&extent_data);
                }
            }
            // Note: Compressed and prealloc extents not fully supported
        }

        Ok(file_data)
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        self.resolve_path(path).is_ok()
    }

    /// Check if path is a directory
    pub fn is_dir(&self, path: &str) -> bool {
        match self.metadata(path) {
            Ok(meta) => meta.entry_type == EntryType::Directory,
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
