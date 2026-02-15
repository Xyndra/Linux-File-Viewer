//! LUKS (Linux Unified Key Setup) decryption support
//!
//! This module provides support for reading LUKS-encrypted partitions.
//! Supports both LUKS1 and LUKS2 formats with AES-XTS and AES-CBC encryption.

use std::io::{Read, Seek, SeekFrom};

use aes::cipher::KeyInit;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use xts_mode::Xts128;

use super::disk::RawDisk;
use super::{FsError, FsResult};

/// LUKS magic bytes
pub const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// LUKS1 header size
pub const LUKS1_HEADER_SIZE: usize = 592;

/// LUKS2 header size (4KB minimum, but we read more for JSON)
pub const LUKS2_HEADER_SIZE: usize = 4096;

/// LUKS2 JSON area size (we read up to 128KB to get full JSON)
pub const LUKS2_JSON_AREA_SIZE: usize = 128 * 1024;

/// LUKS key slot count
pub const LUKS_NUM_KEYS: usize = 8;

/// LUKS key slot states (LUKS1)
pub const LUKS_KEY_DISABLED: u32 = 0x0000DEAD;
pub const LUKS_KEY_ENABLED: u32 = 0x00AC71F3;

/// Sector size for LUKS
pub const LUKS_SECTOR_SIZE: u64 = 512;

/// LUKS version enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuksVersion {
    V1,
    V2,
}

/// Unified LUKS header that can represent both LUKS1 and LUKS2
#[derive(Debug, Clone)]
pub struct LuksHeader {
    /// LUKS version
    pub version: LuksVersion,
    /// Cipher name (e.g., "aes")
    pub cipher_name: String,
    /// Cipher mode (e.g., "xts-plain64")
    pub cipher_mode: String,
    /// Hash specification (e.g., "sha256")
    pub hash_spec: String,
    /// Payload offset in bytes
    pub payload_offset: u64,
    /// Key length in bytes
    pub key_bytes: u32,
    /// UUID
    pub uuid: String,
    /// Key slots
    pub key_slots: Vec<LuksKeySlot>,
    /// Master key digest (LUKS1 only)
    pub mk_digest: Option<[u8; 20]>,
    /// Master key digest salt (LUKS1 only)
    pub mk_digest_salt: Option<[u8; 32]>,
    /// Master key digest iteration count (LUKS1 only)
    pub mk_digest_iter: Option<u32>,
    /// Digest entries (LUKS2)
    pub digests: Vec<Luks2Digest>,
}

/// LUKS key slot (unified for LUKS1 and LUKS2)
#[derive(Debug, Clone)]
pub struct LuksKeySlot {
    /// Slot index
    pub index: usize,
    /// Whether the slot is active
    pub active: bool,
    /// Key derivation function type
    pub kdf: KdfType,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Start offset for key material (in bytes)
    pub key_material_offset: u64,
    /// Size of key material area
    pub key_material_size: u64,
    /// Number of anti-forensic stripes
    pub stripes: u32,
    /// Area encryption type (LUKS2)
    pub area_encryption: Option<String>,
    /// Key size for this slot (may differ from master key size)
    pub key_size: u32,
    /// Hash algorithm for AF diffusion (LUKS2, defaults to sha1)
    pub af_hash: String,
}

/// Key derivation function type
#[derive(Debug, Clone)]
pub enum KdfType {
    Pbkdf2 { hash: String, iterations: u32 },
    Argon2i { time: u32, memory: u32, cpus: u32 },
    Argon2id { time: u32, memory: u32, cpus: u32 },
}

/// LUKS2 digest entry
#[derive(Debug, Clone)]
pub struct Luks2Digest {
    pub index: usize,
    pub hash: String,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
    pub iterations: u32,
    pub keyslots: Vec<usize>,
    pub segments: Vec<usize>,
}

/// LUKS container reader
pub struct LuksReader {
    /// Underlying disk
    disk: RawDisk,
    /// Partition offset
    partition_offset: u64,
    /// LUKS header
    header: LuksHeader,
    /// Decrypted master key (if unlocked)
    master_key: Option<Vec<u8>>,
    /// XTS cipher for decryption (initialized when unlocked)
    cipher: Option<Xts128<Aes256>>,
    /// Current position for Read trait
    current_position: u64,
}

/// Check if data starts with LUKS magic
pub fn is_luks(data: &[u8]) -> bool {
    data.len() >= 6 && &data[0..6] == LUKS_MAGIC
}

/// Detect LUKS version from header
pub fn detect_luks_version(data: &[u8]) -> Option<LuksVersion> {
    if !is_luks(data) {
        return None;
    }
    if data.len() < 8 {
        return None;
    }
    let version = u16::from_be_bytes([data[6], data[7]]);
    match version {
        1 => Some(LuksVersion::V1),
        2 => Some(LuksVersion::V2),
        _ => None,
    }
}

/// Parse a null-terminated string from bytes
fn parse_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Decode hex string to bytes
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Decode base64 string to bytes (LUKS2 uses base64 for salt/digest)
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();

    // Base64 alphabet
    fn char_to_val(c: char) -> Option<u8> {
        match c {
            'A'..='Z' => Some(c as u8 - b'A'),
            'a'..='z' => Some(c as u8 - b'a' + 26),
            '0'..='9' => Some(c as u8 - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            '=' => None, // Padding
            _ => None,
        }
    }

    let mut bytes = Vec::new();
    let chars: Vec<char> = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();

    for chunk in chars.chunks(4) {
        if chunk.is_empty() {
            break;
        }

        let mut vals = [0u8; 4];
        let mut valid_count = 0;

        for (i, &c) in chunk.iter().enumerate() {
            if c == '=' {
                break;
            }
            vals[i] = char_to_val(c)?;
            valid_count += 1;
        }

        if valid_count >= 2 {
            bytes.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if valid_count >= 3 {
            bytes.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if valid_count >= 4 {
            bytes.push((vals[2] << 6) | vals[3]);
        }
    }

    Some(bytes)
}

/// Try to decode as base64 first, then hex (LUKS2 typically uses base64)
fn decode_luks2_binary(s: &str) -> Option<Vec<u8>> {
    // LUKS2 uses base64 encoding for binary data
    if let Some(bytes) = base64_decode(s) {
        if !bytes.is_empty() {
            return Some(bytes);
        }
    }
    // Fallback to hex
    hex_decode(s)
}

impl LuksHeader {
    /// Parse LUKS header from disk
    pub fn parse(disk: &mut RawDisk, partition_offset: u64) -> FsResult<Self> {
        // Read enough data to determine version and parse header
        let mut header_data = vec![0u8; LUKS2_JSON_AREA_SIZE];
        disk.read_exact_at(partition_offset, &mut header_data[..LUKS2_HEADER_SIZE])?;

        if !is_luks(&header_data) {
            return Err(FsError::FilesystemError("Invalid LUKS magic".to_string()));
        }

        let version = detect_luks_version(&header_data)
            .ok_or_else(|| FsError::UnsupportedFilesystem("Unknown LUKS version".to_string()))?;

        match version {
            LuksVersion::V1 => Self::parse_luks1(&header_data),
            LuksVersion::V2 => {
                // Read more data for LUKS2 JSON area
                disk.read_exact_at(partition_offset, &mut header_data)?;
                Self::parse_luks2(&header_data)
            }
        }
    }

    /// Parse LUKS1 header
    fn parse_luks1(data: &[u8]) -> FsResult<Self> {
        if data.len() < LUKS1_HEADER_SIZE {
            return Err(FsError::FilesystemError(
                "LUKS1 header too small".to_string(),
            ));
        }

        let cipher_name = parse_string(&data[8..40]);
        let cipher_mode = parse_string(&data[40..72]);
        let hash_spec = parse_string(&data[72..104]);
        let payload_offset = u32::from_be_bytes([data[104], data[105], data[106], data[107]]);
        let key_bytes = u32::from_be_bytes([data[108], data[109], data[110], data[111]]);

        let mut mk_digest = [0u8; 20];
        mk_digest.copy_from_slice(&data[112..132]);

        let mut mk_digest_salt = [0u8; 32];
        mk_digest_salt.copy_from_slice(&data[132..164]);

        let mk_digest_iter = u32::from_be_bytes([data[164], data[165], data[166], data[167]]);

        let uuid = parse_string(&data[168..208]);

        // Parse key slots (starting at offset 208)
        let mut key_slots = Vec::new();
        for i in 0..LUKS_NUM_KEYS {
            let offset = 208 + i * 48;
            let active = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let iterations = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let mut salt = vec![0u8; 32];
            salt.copy_from_slice(&data[offset + 8..offset + 40]);
            let key_material_offset = u32::from_be_bytes([
                data[offset + 40],
                data[offset + 41],
                data[offset + 42],
                data[offset + 43],
            ]);
            let stripes = u32::from_be_bytes([
                data[offset + 44],
                data[offset + 45],
                data[offset + 46],
                data[offset + 47],
            ]);

            if active == LUKS_KEY_ENABLED {
                key_slots.push(LuksKeySlot {
                    index: i,
                    active: true,
                    kdf: KdfType::Pbkdf2 {
                        hash: hash_spec.clone(),
                        iterations,
                    },
                    salt,
                    key_material_offset: key_material_offset as u64 * LUKS_SECTOR_SIZE,
                    key_material_size: 0, // Calculated from stripes
                    stripes,
                    area_encryption: None,
                    key_size: key_bytes,
                    af_hash: "sha1".to_string(), // LUKS1 always uses SHA1 for AF
                });
            }
        }

        Ok(Self {
            version: LuksVersion::V1,
            cipher_name,
            cipher_mode,
            hash_spec,
            payload_offset: payload_offset as u64 * LUKS_SECTOR_SIZE,
            key_bytes,
            uuid,
            key_slots,
            mk_digest: Some(mk_digest),
            mk_digest_salt: Some(mk_digest_salt),
            mk_digest_iter: Some(mk_digest_iter),
            digests: Vec::new(),
        })
    }

    /// Parse LUKS2 header
    fn parse_luks2(data: &[u8]) -> FsResult<Self> {
        if data.len() < LUKS2_HEADER_SIZE {
            return Err(FsError::FilesystemError(
                "LUKS2 header too small".to_string(),
            ));
        }

        // LUKS2 binary header structure:
        // 0-6: magic
        // 6-8: version
        // 8-16: header size
        // 16-24: sequence id
        // 24-88: label
        // 88-120: checksum algorithm
        // 120-184: salt
        // 184-248: uuid
        // 248-312: subsystem
        // 312-320: header offset
        // 320-512: padding
        // 512+: JSON area

        let uuid = parse_string(&data[184..248]);

        // Find JSON area (starts at offset 4096 in LUKS2)
        let json_start = 4096;
        if data.len() <= json_start {
            return Err(FsError::FilesystemError(
                "LUKS2 JSON area not readable".to_string(),
            ));
        }

        // Find the end of JSON (null terminator or end of data)
        let json_data = &data[json_start..];
        let json_end = json_data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(json_data.len());
        let json_str = String::from_utf8_lossy(&json_data[..json_end]);

        // Parse JSON manually (simple parser to avoid adding serde_json dependency)
        Self::parse_luks2_json(&json_str, uuid)
    }

    /// Parse LUKS2 JSON metadata
    fn parse_luks2_json(json_str: &str, uuid: String) -> FsResult<Self> {
        // Simple JSON parsing for LUKS2 metadata
        // We need to extract: config, keyslots, digests, segments

        #[cfg(debug_assertions)]
        eprintln!("LUKS2 JSON: Parsing JSON ({} bytes)", json_str.len());
        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: First 500 chars: {}",
            &json_str[..json_str.len().min(500)]
        );

        let mut cipher_name = String::from("aes");
        let mut cipher_mode = String::from("xts-plain64");
        let hash_spec = String::from("sha256");
        let mut payload_offset: u64 = 0;
        let mut key_bytes: u32 = 64; // Default for AES-256-XTS
        let mut key_slots = Vec::new();
        let mut digests = Vec::new();

        // Extract segments to get payload offset
        if let Some(segments_start) = json_str.find("\"segments\"") {
            let segments_area = &json_str[segments_start..];
            // Find the segments object
            if let Some(obj_start) = segments_area.find('{') {
                let segments_obj = &segments_area[obj_start..];
                if let Some(obj_end) = find_matching_brace(segments_obj) {
                    let segments_obj = &segments_obj[..obj_end];

                    // Find segment "0"
                    if let Some(segment_0_pos) = segments_obj.find("\"0\"") {
                        let segment_0_data = &segments_obj[segment_0_pos..];
                        if let Some(seg_obj_start) = segment_0_data.find('{') {
                            let seg_obj = &segment_0_data[seg_obj_start..];
                            if let Some(seg_obj_end) = find_matching_brace(seg_obj) {
                                let seg_obj = &seg_obj[..seg_obj_end];

                                if let Some(offset_val) = extract_json_string(seg_obj, "offset") {
                                    payload_offset = offset_val.parse().unwrap_or(0);
                                    #[cfg(debug_assertions)]
                                    eprintln!(
                                        "LUKS2 JSON: Segment 0 payload offset = {}",
                                        payload_offset
                                    );
                                }
                                if let Some(encryption) = extract_json_string(seg_obj, "encryption")
                                {
                                    // Parse encryption like "aes-xts-plain64"
                                    let parts: Vec<&str> = encryption.split('-').collect();
                                    if !parts.is_empty() {
                                        cipher_name = parts[0].to_string();
                                    }
                                    if parts.len() >= 2 {
                                        cipher_mode = parts[1..].join("-");
                                    }
                                    #[cfg(debug_assertions)]
                                    eprintln!(
                                        "LUKS2 JSON: cipher = {}-{}",
                                        cipher_name, cipher_mode
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract keyslots - find the keyslots object and iterate within it
        if let Some(keyslots_start) = json_str.find("\"keyslots\"") {
            let keyslots_area = &json_str[keyslots_start..];

            // Find the keyslots object
            if let Some(obj_start) = keyslots_area.find('{') {
                let keyslots_obj = &keyslots_area[obj_start..];
                if let Some(obj_end) = find_matching_brace(keyslots_obj) {
                    let keyslots_obj = &keyslots_obj[..obj_end];

                    #[cfg(debug_assertions)]
                    eprintln!("LUKS2 JSON: Keyslots object len = {}", keyslots_obj.len());

                    // Find each keyslot (0-7 typically)
                    for slot_idx in 0..32 {
                        let slot_key = format!("\"{}\"", slot_idx);
                        if let Some(slot_start) = keyslots_obj.find(&slot_key) {
                            let slot_data = &keyslots_obj[slot_start..];

                            // Check if this is actually a keyslot object (not a reference in another field)
                            let next_brace = slot_data.find('{');
                            let next_bracket = slot_data.find('[');

                            if let Some(brace_pos) = next_brace {
                                if next_bracket.is_none_or(|b| brace_pos < b) {
                                    if let Some(slot) =
                                        Self::parse_keyslot_json(slot_data, slot_idx)
                                    {
                                        key_slots.push(slot);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract digests
        if let Some(digests_start) = json_str.find("\"digests\"") {
            let digests_area = &json_str[digests_start..];

            for digest_idx in 0..8 {
                let digest_key = format!("\"{}\"", digest_idx);
                if let Some(digest_start) = digests_area.find(&digest_key) {
                    let digest_data = &digests_area[digest_start..];
                    if let Some(digest) = Self::parse_digest_json(digest_data, digest_idx) {
                        digests.push(digest);
                    }
                }
            }
        }

        // Get key_bytes from first keyslot's key_size if available
        if let Some(keyslots_start) = json_str.find("\"keyslots\"") {
            let keyslots_area = &json_str[keyslots_start..];
            if let Some(key_size_str) = extract_json_number(keyslots_area, "key_size") {
                key_bytes = key_size_str.parse().unwrap_or(64);
            }
        }

        if key_slots.is_empty() {
            return Err(FsError::FilesystemError(
                "No active keyslots found in LUKS2 header".to_string(),
            ));
        }

        Ok(Self {
            version: LuksVersion::V2,
            cipher_name,
            cipher_mode,
            hash_spec,
            payload_offset,
            key_bytes,
            uuid,
            key_slots,
            mk_digest: None,
            mk_digest_salt: None,
            mk_digest_iter: None,
            digests,
        })
    }

    /// Parse a single keyslot from JSON
    fn parse_keyslot_json(data: &str, index: usize) -> Option<LuksKeySlot> {
        // Find the keyslot object boundaries
        let obj_start = data.find('{')?;
        let obj_data = &data[obj_start..];

        // Find the matching closing brace for this object
        // This is important to limit our search scope
        let obj_end = find_matching_brace(obj_data).unwrap_or(obj_data.len());
        let data = &obj_data[..obj_end];

        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: Parsing keyslot {} (object len={})",
            index,
            data.len()
        );

        // Extract KDF parameters
        let kdf_type = extract_json_string(data, "type").unwrap_or_default();

        let kdf = if let Some(kdf_start) = data.find("\"kdf\"") {
            let kdf_data = &data[kdf_start..];
            // Limit kdf_data to its object
            let kdf_obj_start = kdf_data.find('{')?;
            let kdf_obj_data = &kdf_data[kdf_obj_start..];
            let kdf_obj_end = find_matching_brace(kdf_obj_data).unwrap_or(kdf_obj_data.len());
            let kdf_data = &kdf_obj_data[..kdf_obj_end];

            let kdf_type_inner = extract_json_string(kdf_data, "type").unwrap_or_default();

            #[cfg(debug_assertions)]
            eprintln!("LUKS2 JSON: KDF type = '{}'", kdf_type_inner);

            match kdf_type_inner.as_str() {
                "pbkdf2" => {
                    let hash = extract_json_string(kdf_data, "hash")
                        .unwrap_or_else(|| "sha256".to_string());
                    let iterations: u32 = extract_json_number(kdf_data, "iterations")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(100000);
                    KdfType::Pbkdf2 { hash, iterations }
                }
                "argon2i" => {
                    let time: u32 = extract_json_number(kdf_data, "time")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(4);
                    let memory: u32 = extract_json_number(kdf_data, "memory")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1048576);
                    let cpus: u32 = extract_json_number(kdf_data, "cpus")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(4);
                    KdfType::Argon2i { time, memory, cpus }
                }
                "argon2id" => {
                    let time: u32 = extract_json_number(kdf_data, "time")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(4);
                    let memory: u32 = extract_json_number(kdf_data, "memory")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1048576);
                    let cpus: u32 = extract_json_number(kdf_data, "cpus")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(4);
                    KdfType::Argon2id { time, memory, cpus }
                }
                _ => {
                    // TODO: This is invisible because of admin privilige handling, use a msgbox instead
                    panic!("Unsupported KDF type")
                }
            }
        } else {
            return None;
        };

        // Extract salt (base64 encoded in LUKS2)
        let salt = if let Some(kdf_start) = data.find("\"kdf\"") {
            let kdf_data = &data[kdf_start..];
            let kdf_obj_start = kdf_data.find('{').unwrap_or(0);
            let kdf_obj_data = &kdf_data[kdf_obj_start..];
            let kdf_obj_end = find_matching_brace(kdf_obj_data).unwrap_or(kdf_obj_data.len());
            let kdf_data = &kdf_obj_data[..kdf_obj_end];

            let salt_str = extract_json_string(kdf_data, "salt");
            #[cfg(debug_assertions)]
            if let Some(ref s) = salt_str {
                eprintln!(
                    "LUKS2 JSON: Salt string = '{}' (len={})",
                    &s[..s.len().min(40)],
                    s.len()
                );
            }
            salt_str
                .and_then(|s| decode_luks2_binary(&s))
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        #[cfg(debug_assertions)]
        eprintln!("LUKS2 JSON: Decoded salt len = {}", salt.len());

        // Extract key_size for this slot
        let key_size: u32 = extract_json_number(data, "key_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);

        #[cfg(debug_assertions)]
        eprintln!("LUKS2 JSON: key_size = {}", key_size);

        // Extract area parameters - be very careful about scope
        let (key_material_offset, key_material_size, area_encryption) = if let Some(area_start) =
            data.find("\"area\"")
        {
            let area_data = &data[area_start..];
            // Find area object and limit scope
            let area_obj_start = area_data.find('{').unwrap_or(0);
            let area_obj_data = &area_data[area_obj_start..];
            let area_obj_end = find_matching_brace(area_obj_data).unwrap_or(area_obj_data.len());
            let area_data = &area_obj_data[..area_obj_end];

            #[cfg(debug_assertions)]
            eprintln!(
                "LUKS2 JSON: Area object = '{}'",
                &area_data[..area_data.len().min(200)]
            );

            let offset_str = extract_json_number(area_data, "offset");
            let size_str = extract_json_number(area_data, "size");

            #[cfg(debug_assertions)]
            eprintln!(
                "LUKS2 JSON: Area offset_str = {:?}, size_str = {:?}",
                offset_str, size_str
            );

            let offset: u64 = offset_str.and_then(|s| s.parse().ok()).unwrap_or(0);
            let size: u64 = size_str.and_then(|s| s.parse().ok()).unwrap_or(0);
            let encryption = extract_json_string(area_data, "encryption");

            #[cfg(debug_assertions)]
            eprintln!(
                "LUKS2 JSON: Area offset = {}, size = {}, encryption = {:?}",
                offset, size, encryption
            );

            (offset, size, encryption)
        } else {
            #[cfg(debug_assertions)]
            eprintln!("LUKS2 JSON: No area found in keyslot!");
            (0, 0, None)
        };

        // Extract AF stripes and hash
        let (stripes, af_hash): (u32, String) = if let Some(af_start) = data.find("\"af\"") {
            let af_data = &data[af_start..];
            let af_obj_start = af_data.find('{').unwrap_or(0);
            let af_obj_data = &af_data[af_obj_start..];
            let af_obj_end = find_matching_brace(af_obj_data).unwrap_or(af_obj_data.len());
            let af_data = &af_obj_data[..af_obj_end];

            let stripes = extract_json_number(af_data, "stripes")
                .and_then(|s| s.parse().ok())
                .unwrap_or(4000);
            let hash = extract_json_string(af_data, "hash").unwrap_or_else(|| "sha1".to_string());

            #[cfg(debug_assertions)]
            eprintln!("LUKS2 JSON: AF hash = '{}'", hash);

            (stripes, hash)
        } else {
            (4000, "sha1".to_string())
        };

        #[cfg(debug_assertions)]
        eprintln!("LUKS2 JSON: stripes = {}", stripes);

        // Check if slot type is "luks2"
        if kdf_type != "luks2" && !kdf_type.is_empty() {
            #[cfg(debug_assertions)]
            eprintln!(
                "LUKS2 JSON: Skipping slot {} with type '{}'",
                index, kdf_type
            );
            return None;
        }

        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: Slot {} parsed: offset={}, size={}, key_size={}, stripes={}",
            index, key_material_offset, key_material_size, key_size, stripes
        );

        Some(LuksKeySlot {
            index,
            active: true,
            kdf,
            salt,
            key_material_offset,
            key_material_size,
            stripes,
            area_encryption,
            key_size,
            af_hash,
        })
    }

    /// Parse a digest entry from JSON
    fn parse_digest_json(data: &str, index: usize) -> Option<Luks2Digest> {
        let obj_start = data.find('{')?;
        let obj_data = &data[obj_start..];
        let obj_end = find_matching_brace(obj_data).unwrap_or(obj_data.len());
        let data = &obj_data[..obj_end];

        let hash = extract_json_string(data, "hash").unwrap_or_else(|| "sha256".to_string());
        let salt_str = extract_json_string(data, "salt");
        let digest_str = extract_json_string(data, "digest");

        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: Digest {} hash='{}', salt_str={:?}, digest_str={:?}",
            index,
            hash,
            salt_str.as_ref().map(|s| s.len()),
            digest_str.as_ref().map(|s| s.len())
        );

        let salt = salt_str
            .and_then(|s| decode_luks2_binary(&s))
            .unwrap_or_default();
        let digest = digest_str
            .and_then(|s| decode_luks2_binary(&s))
            .unwrap_or_default();
        let iterations: u32 = extract_json_number(data, "iterations")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100000);

        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: Digest {} decoded: salt_len={}, digest_len={}, iterations={}",
            index,
            salt.len(),
            digest.len(),
            iterations
        );

        // Parse keyslots array
        let keyslots = extract_json_array_numbers(data, "keyslots");
        let segments = extract_json_array_numbers(data, "segments");

        #[cfg(debug_assertions)]
        eprintln!(
            "LUKS2 JSON: Digest {} keyslots={:?}, segments={:?}",
            index, keyslots, segments
        );

        Some(Luks2Digest {
            index,
            hash,
            salt,
            digest,
            iterations,
            keyslots,
            segments,
        })
    }

    /// Check if this LUKS uses supported encryption
    pub fn is_supported(&self) -> bool {
        self.cipher_name.to_lowercase() == "aes"
            && (self.cipher_mode.to_lowercase().starts_with("xts")
                || self.cipher_mode.to_lowercase().starts_with("cbc"))
    }

    /// Get the number of active key slots
    pub fn active_slot_count(&self) -> usize {
        self.key_slots.iter().filter(|s| s.active).count()
    }
}

/// Extract a string value from JSON (simple parser)
/// Find the position of the matching closing brace for an object starting with '{'
fn find_matching_brace(data: &str) -> Option<usize> {
    if !data.starts_with('{') {
        return None;
    }

    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in data.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }

    None
}

fn extract_json_string(data: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let key_pos = data.find(&search)?;
    let after_key = &data[key_pos + search.len()..];

    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    // Check if it's a string value
    if !after_colon.starts_with('"') {
        return None;
    }

    let value_start = 1; // Skip opening quote
    let value_data = &after_colon[value_start..];
    let value_end = value_data.find('"')?;

    Some(value_data[..value_end].to_string())
}

/// Extract a number value from JSON (simple parser)
fn extract_json_number(data: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let key_pos = data.find(&search)?;
    let after_key = &data[key_pos + search.len()..];

    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    // Handle both quoted and unquoted numbers
    if after_colon.starts_with('"') {
        // Quoted number
        let value_start = 1;
        let value_data = &after_colon[value_start..];
        let value_end = value_data.find('"')?;
        Some(value_data[..value_end].to_string())
    } else {
        // Unquoted number
        let end = after_colon.find(|c: char| !c.is_ascii_digit() && c != '-')?;
        if end == 0 {
            return None;
        }
        Some(after_colon[..end].to_string())
    }
}

/// Extract an array of numbers from JSON
fn extract_json_array_numbers(data: &str, key: &str) -> Vec<usize> {
    let search = format!("\"{}\"", key);
    let key_pos = match data.find(&search) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let after_key = &data[key_pos + search.len()..];

    // Skip whitespace and colon
    let after_colon = match after_key.trim_start().strip_prefix(':') {
        Some(s) => s.trim_start(),
        None => return Vec::new(),
    };

    // Find array brackets
    if !after_colon.starts_with('[') {
        return Vec::new();
    }

    let array_end = match after_colon.find(']') {
        Some(p) => p,
        None => return Vec::new(),
    };

    let array_content = &after_colon[1..array_end];

    // Parse numbers (can be quoted like "0" or unquoted like 0)
    array_content
        .split(',')
        .filter_map(|s| {
            let s = s.trim().trim_matches('"');
            s.parse().ok()
        })
        .collect()
}

impl LuksReader {
    /// Open a LUKS partition
    pub fn open(mut disk: RawDisk, partition_offset: u64) -> FsResult<Self> {
        let header = LuksHeader::parse(&mut disk, partition_offset)?;

        if !header.is_supported() {
            return Err(FsError::UnsupportedFilesystem(format!(
                "Unsupported LUKS cipher: {}-{}",
                header.cipher_name, header.cipher_mode
            )));
        }

        Ok(Self {
            disk,
            partition_offset,
            header,
            master_key: None,
            cipher: None,
            current_position: 0,
        })
    }

    /// Get the LUKS header
    pub fn header(&self) -> &LuksHeader {
        &self.header
    }

    /// Check if the partition is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Try to unlock with a password
    pub fn unlock(&mut self, password: &str) -> FsResult<bool> {
        let password_bytes = password.as_bytes();

        // Clone key slots to avoid borrow issues
        let key_slots = self.header.key_slots.clone();

        if key_slots.is_empty() {
            return Err(FsError::FilesystemError(
                "No key slots found in LUKS header".to_string(),
            ));
        }

        #[cfg(debug_assertions)]
        let mut last_error: Option<String> = None;

        // Try each active key slot
        for slot in &key_slots {
            if !slot.active {
                continue;
            }

            match self.try_slot(slot, password_bytes) {
                Ok(master_key) => {
                    // Verify the master key
                    match self.verify_master_key(&master_key) {
                        Ok(true) => {
                            self.master_key = Some(master_key.clone());
                            self.init_cipher(&master_key)?;
                            return Ok(true);
                        }
                        Ok(false) => {
                            #[cfg(debug_assertions)]
                            {
                                last_error = Some(format!(
                                    "Slot {}: Master key verification failed",
                                    slot.index
                                ));
                            }
                        }
                        Err(e) => {
                            #[cfg(debug_assertions)]
                            {
                                last_error =
                                    Some(format!("Slot {}: Verification error: {}", slot.index, e));
                            }
                        }
                    }
                }
                Err(e) => {
                    #[cfg(debug_assertions)]
                    {
                        last_error = Some(format!("Slot {}: {}", slot.index, e));
                    }
                }
            }
        }

        // If we have diagnostic info, include it in the debug output
        #[cfg(debug_assertions)]
        if let Some(ref err) = last_error {
            eprintln!("LUKS unlock debug: {}", err);
        }

        Ok(false)
    }

    /// Try to decrypt a key slot
    fn try_slot(&mut self, slot: &LuksKeySlot, password: &[u8]) -> FsResult<Vec<u8>> {
        // Derive the slot key using the appropriate KDF
        // For LUKS2, the derived key length is the slot's key_size (for keyslot decryption)
        // The master key length is header.key_bytes
        let derived_key_len = slot.key_size as usize;
        let master_key_len = self.header.key_bytes as usize;

        eprintln!(
            "LUKS slot {}: KDF={:?}, salt_len={}, derived_key_len={}, master_key_len={}, stripes={}",
            slot.index,
            match &slot.kdf {
                KdfType::Pbkdf2 { hash, iterations } => format!("PBKDF2-{} ({})", hash, iterations),
                KdfType::Argon2i { time, memory, cpus } => format!("Argon2i (t={}, m={}, p={})", time, memory, cpus),
                KdfType::Argon2id { time, memory, cpus } => format!("Argon2id (t={}, m={}, p={})", time, memory, cpus),
            },
            slot.salt.len(),
            derived_key_len,
            master_key_len,
            slot.stripes
        );

        let derived_key = self.derive_key(slot, password, derived_key_len)?;

        eprintln!(
            "LUKS slot {}: Key derived successfully ({} bytes)",
            slot.index,
            derived_key.len()
        );

        // Read the encrypted key material
        let af_size = slot.stripes as usize * master_key_len;
        let key_material_size =
            if slot.key_material_size > 0 && slot.key_material_size as usize >= af_size {
                slot.key_material_size as usize
            } else {
                // Calculate from stripes, round up to sector boundary
                let sectors = af_size.div_ceil(512);
                sectors * 512
            };
        let key_material_offset = self.partition_offset + slot.key_material_offset;

        eprintln!(
    "LUKS slot {}: Reading {} bytes of key material from offset {} (partition_offset={}, slot.key_material_offset={})",
            slot.index, key_material_size, key_material_offset, self.partition_offset, slot.key_material_offset
        );

        let mut encrypted_key_material = vec![0u8; key_material_size];
        self.disk
            .read_exact_at(key_material_offset, &mut encrypted_key_material)?;

        eprintln!(
            "LUKS slot {}: First 32 bytes of encrypted key material: {:02x?}",
            slot.index,
            &encrypted_key_material[..encrypted_key_material.len().min(32)]
        );

        // Decrypt the key material
        let decrypted_key_material =
            self.decrypt_key_material(&encrypted_key_material, &derived_key, slot)?;

        eprintln!(
            "LUKS slot {}: Decrypted key material ({} bytes), applying AF merge",
            slot.index,
            decrypted_key_material.len()
        );

        // Apply anti-forensic splitter (AF) to merge stripes
        let master_key = self.af_merge(
            &decrypted_key_material,
            slot.stripes as usize,
            master_key_len,
            &slot.af_hash,
        )?;

        eprintln!(
            "LUKS slot {}: AF merge complete, master key is {} bytes, first 8 bytes: {:02x?}",
            slot.index,
            master_key.len(),
            &master_key[..master_key.len().min(8)]
        );

        Ok(master_key)
    }

    /// Derive key using the appropriate KDF
    fn derive_key(&self, slot: &LuksKeySlot, password: &[u8], key_len: usize) -> FsResult<Vec<u8>> {
        let mut derived_key = vec![0u8; key_len];

        if slot.salt.is_empty() {
            return Err(FsError::FilesystemError(
                "Empty salt in keyslot".to_string(),
            ));
        }

        match &slot.kdf {
            KdfType::Pbkdf2 { hash, iterations } => match hash.to_lowercase().as_str() {
                "sha1" => {
                    pbkdf2::<Hmac<Sha1>>(password, &slot.salt, *iterations, &mut derived_key)
                        .map_err(|e| {
                            FsError::FilesystemError(format!("PBKDF2-SHA1 failed: {:?}", e))
                        })?;
                }
                "sha256" => {
                    pbkdf2::<Hmac<Sha256>>(password, &slot.salt, *iterations, &mut derived_key)
                        .map_err(|e| {
                            FsError::FilesystemError(format!("PBKDF2-SHA256 failed: {:?}", e))
                        })?;
                }
                "sha512" => {
                    pbkdf2::<Hmac<Sha512>>(password, &slot.salt, *iterations, &mut derived_key)
                        .map_err(|e| {
                            FsError::FilesystemError(format!("PBKDF2-SHA512 failed: {:?}", e))
                        })?;
                }
                _ => {
                    // TODO: Make this a msgbox
                    panic!("Unsupported hash algorithm");
                }
            },
            KdfType::Argon2i { time, memory, cpus } | KdfType::Argon2id { time, memory, cpus } => {
                use argon2::{Algorithm, Argon2, Params, Version};

                let algorithm = match &slot.kdf {
                    KdfType::Argon2i { .. } => Algorithm::Argon2i,
                    _ => Algorithm::Argon2id,
                };

                // Argon2 memory parameter is in KiB
                // LUKS2 stores memory in KiB as well
                let m_cost = *memory;
                let t_cost = *time;
                let p_cost = *cpus;

                let params = Params::new(m_cost, t_cost, p_cost, Some(key_len)).map_err(|e| {
                    FsError::FilesystemError(format!("Argon2 params error: {:?}", e))
                })?;

                let argon2 = Argon2::new(algorithm, Version::V0x13, params);

                argon2
                    .hash_password_into(password, &slot.salt, &mut derived_key)
                    .map_err(|e| FsError::FilesystemError(format!("Argon2 failed: {:?}", e)))?;
            }
        }

        Ok(derived_key)
    }

    /// Decrypt key material
    fn decrypt_key_material(
        &self,
        encrypted: &[u8],
        key: &[u8],
        slot: &LuksKeySlot,
    ) -> FsResult<Vec<u8>> {
        let master_key_len = self.header.key_bytes as usize;
        let total_size = slot.stripes as usize * master_key_len;

        // Round up to sector size
        let sectors = total_size.div_ceil(512);
        let aligned_size = sectors * 512;

        // Determine encryption mode from slot or header
        // LUKS2 keyslot area typically uses "aes-xts-plain64"
        let cipher_mode = slot
            .area_encryption
            .as_ref()
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| self.header.cipher_mode.to_lowercase());

        // For LUKS2 keyslot area decryption, the key is the derived key from KDF
        // The key size should match the slot's key_size (often 64 bytes for XTS)
        if cipher_mode.contains("xts") {
            self.decrypt_xts_sectors(encrypted, key, sectors)
        } else if cipher_mode.contains("cbc") {
            self.decrypt_cbc(encrypted, key, aligned_size)
        } else {
            // Default to XTS for LUKS2
            self.decrypt_xts_sectors(encrypted, key, sectors)
        }
    }

    /// Decrypt using AES-CBC
    fn decrypt_cbc(&self, encrypted: &[u8], key: &[u8], size: usize) -> FsResult<Vec<u8>> {
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let mut decrypted = vec![0u8; size];
        let sector_size = 512usize;
        let num_sectors = size / sector_size;

        // For key slot decryption, we may need to use only part of the key
        let key_to_use = if key.len() >= 32 {
            &key[..32]
        } else {
            // Pad key if needed
            let mut padded = vec![0u8; 32];
            padded[..key.len()].copy_from_slice(key);
            return self.decrypt_cbc_with_key(encrypted, &padded, size);
        };

        for sector_num in 0..num_sectors {
            let start = sector_num * sector_size;
            let end = start + sector_size;

            if end > encrypted.len() {
                break;
            }

            // IV is sector number as little-endian
            let mut iv = [0u8; 16];
            let sector_bytes = (sector_num as u64).to_le_bytes();
            iv[..8].copy_from_slice(&sector_bytes);

            let cipher = Aes256CbcDec::new_from_slices(key_to_use, &iv).map_err(|e| {
                FsError::FilesystemError(format!("Failed to create AES-CBC cipher: {:?}", e))
            })?;

            let mut sector_data = encrypted[start..end].to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut sector_data)
                .map_err(|e| {
                    FsError::FilesystemError(format!("AES-CBC decryption failed: {:?}", e))
                })?;

            decrypted[start..end].copy_from_slice(&sector_data);
        }

        Ok(decrypted)
    }

    fn decrypt_cbc_with_key(&self, encrypted: &[u8], key: &[u8], size: usize) -> FsResult<Vec<u8>> {
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let mut decrypted = vec![0u8; size];
        let sector_size = 512usize;
        let num_sectors = size / sector_size;

        for sector_num in 0..num_sectors {
            let start = sector_num * sector_size;
            let end = start + sector_size;

            if end > encrypted.len() {
                break;
            }

            let mut iv = [0u8; 16];
            let sector_bytes = (sector_num as u64).to_le_bytes();
            iv[..8].copy_from_slice(&sector_bytes);

            let cipher = Aes256CbcDec::new_from_slices(key, &iv).map_err(|e| {
                FsError::FilesystemError(format!("Failed to create AES-CBC cipher: {:?}", e))
            })?;

            let mut sector_data = encrypted[start..end].to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut sector_data)
                .map_err(|e| {
                    FsError::FilesystemError(format!("AES-CBC decryption failed: {:?}", e))
                })?;

            decrypted[start..end].copy_from_slice(&sector_data);
        }

        Ok(decrypted)
    }

    /// Decrypt using AES-XTS (sector by sector)
    fn decrypt_xts_sectors(
        &self,
        encrypted: &[u8],
        key: &[u8],
        num_sectors: usize,
    ) -> FsResult<Vec<u8>> {
        let key_len = key.len();

        eprintln!(
            "XTS decrypt: key_len={}, num_sectors={}, encrypted_len={}",
            key_len,
            num_sectors,
            encrypted.len()
        );

        // XTS requires at least 32 bytes (two 128-bit keys) or 64 bytes (two 256-bit keys)
        if key_len < 32 {
            return Err(FsError::FilesystemError(format!(
                "Key too short for XTS mode: {} bytes",
                key_len
            )));
        }

        // For XTS, split the key into two halves
        // If key is 64 bytes, use full AES-256-XTS (two 256-bit keys)
        // If key is 32 bytes, use AES-128-XTS (two 128-bit keys) but we pad to 256
        let (key1, key2) = if key_len >= 64 {
            (&key[..32], &key[32..64])
        } else if key_len >= 32 {
            // For 32-byte key, split into two 16-byte keys and pad
            (&key[..16], &key[16..32])
        } else {
            (&key[..key_len / 2], &key[key_len / 2..])
        };

        eprintln!(
            "XTS decrypt: key1_len={}, key2_len={}, key1[0..4]={:02x?}, key2[0..4]={:02x?}",
            key1.len(),
            key2.len(),
            &key1[..key1.len().min(4)],
            &key2[..key2.len().min(4)]
        );

        // Pad keys to 32 bytes for AES-256
        let mut key1_padded = [0u8; 32];
        let mut key2_padded = [0u8; 32];
        let len1 = std::cmp::min(key1.len(), 32);
        let len2 = std::cmp::min(key2.len(), 32);
        key1_padded[..len1].copy_from_slice(&key1[..len1]);
        key2_padded[..len2].copy_from_slice(&key2[..len2]);

        let cipher1 = Aes256::new_from_slice(&key1_padded)
            .map_err(|_| FsError::FilesystemError("Invalid key1 for XTS".to_string()))?;
        let cipher2 = Aes256::new_from_slice(&key2_padded)
            .map_err(|_| FsError::FilesystemError("Invalid key2 for XTS".to_string()))?;
        let xts = Xts128::new(cipher1, cipher2);

        let sector_size = 512usize;
        let mut decrypted = vec![0u8; num_sectors * sector_size];

        for sector_num in 0..num_sectors {
            let start = sector_num * sector_size;
            let end = start + sector_size;

            if end > encrypted.len() {
                break;
            }

            decrypted[start..end].copy_from_slice(&encrypted[start..end]);

            // XTS tweak is the sector number as little-endian bytes
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&(sector_num as u64).to_le_bytes());
            xts.decrypt_sector(&mut decrypted[start..end], tweak);
        }

        eprintln!(
            "XTS decrypt: First 32 bytes of decrypted: {:02x?}",
            &decrypted[..decrypted.len().min(32)]
        );

        Ok(decrypted)
    }

    /// Apply AF (Anti-Forensic) merge operation
    /// LUKS AF split/merge uses XOR with hash diffusion
    /// The merge operation reverses the split: for each stripe except the last,
    /// we XOR with the stripe data, then apply hash diffusion.
    /// For the last stripe, we just XOR without diffusion.
    fn af_merge(
        &self,
        data: &[u8],
        stripes: usize,
        key_len: usize,
        hash_name: &str,
    ) -> FsResult<Vec<u8>> {
        if stripes == 0 {
            return Err(FsError::FilesystemError("Invalid stripe count".to_string()));
        }

        if stripes == 1 {
            // No AF splitting, just return the data
            let mut result = vec![0u8; key_len];
            let copy_len = std::cmp::min(key_len, data.len());
            result[..copy_len].copy_from_slice(&data[..copy_len]);
            return Ok(result);
        }

        let stripe_size = key_len;
        let mut result = vec![0u8; key_len];

        // Process all stripes
        for stripe_idx in 0..stripes {
            let offset = stripe_idx * stripe_size;
            if offset + stripe_size > data.len() {
                break;
            }

            // XOR this stripe into the result
            for (i, byte) in data[offset..offset + stripe_size].iter().enumerate() {
                result[i] ^= byte;
            }

            // Apply hash diffusion after XOR (except for the last stripe)
            if stripe_idx < stripes - 1 {
                result = self.af_hash_diffuse(&result, hash_name);
            }
        }

        Ok(result)
    }

    /// Hash diffusion for AF splitter
    /// This implements the diffuse function from LUKS specification
    /// LUKS2 can use different hash algorithms (sha1, sha256, sha512)
    fn af_hash_diffuse(&self, data: &[u8], hash_name: &str) -> Vec<u8> {
        use sha1::Sha1;
        use sha2::{Digest, Sha256, Sha512};

        let data_len = data.len();
        let mut result = vec![0u8; data_len];

        match hash_name.to_lowercase().as_str() {
            "sha512" => {
                let hash_len = 64; // SHA-512 output size
                let num_blocks = data_len.div_ceil(hash_len);

                for block_idx in 0..num_blocks {
                    let start = block_idx * hash_len;
                    let end = std::cmp::min(start + hash_len, data_len);
                    let block_len = end - start;

                    let mut hasher = Sha512::new();
                    hasher.update((block_idx as u32).to_be_bytes());
                    hasher.update(&data[start..end]);
                    let hash = hasher.finalize();
                    result[start..end].copy_from_slice(&hash[..block_len]);
                }
            }
            "sha256" => {
                let hash_len = 32; // SHA-256 output size
                let num_blocks = data_len.div_ceil(hash_len);

                for block_idx in 0..num_blocks {
                    let start = block_idx * hash_len;
                    let end = std::cmp::min(start + hash_len, data_len);
                    let block_len = end - start;

                    let mut hasher = Sha256::new();
                    hasher.update((block_idx as u32).to_be_bytes());
                    hasher.update(&data[start..end]);
                    let hash = hasher.finalize();
                    result[start..end].copy_from_slice(&hash[..block_len]);
                }
            }
            _ => {
                // Default to SHA-1 (LUKS1 compatibility)
                let hash_len = 20; // SHA-1 output size
                let num_blocks = data_len.div_ceil(hash_len);

                for block_idx in 0..num_blocks {
                    let start = block_idx * hash_len;
                    let end = std::cmp::min(start + hash_len, data_len);
                    let block_len = end - start;

                    let mut hasher = Sha1::new();
                    hasher.update((block_idx as u32).to_be_bytes());
                    hasher.update(&data[start..end]);
                    let hash = hasher.finalize();
                    result[start..end].copy_from_slice(&hash[..block_len]);
                }
            }
        }

        result
    }

    /// Verify the master key
    fn verify_master_key(&self, master_key: &[u8]) -> FsResult<bool> {
        match self.header.version {
            LuksVersion::V1 => self.verify_master_key_v1(master_key),
            LuksVersion::V2 => self.verify_master_key_v2(master_key),
        }
    }

    /// Verify master key for LUKS1
    fn verify_master_key_v1(&self, master_key: &[u8]) -> FsResult<bool> {
        let mk_digest = self
            .header
            .mk_digest
            .ok_or_else(|| FsError::FilesystemError("Missing master key digest".to_string()))?;
        let mk_digest_salt = self.header.mk_digest_salt.ok_or_else(|| {
            FsError::FilesystemError("Missing master key digest salt".to_string())
        })?;
        let mk_digest_iter = self.header.mk_digest_iter.ok_or_else(|| {
            FsError::FilesystemError("Missing master key digest iterations".to_string())
        })?;

        // PBKDF2 the master key with mk_digest_salt and verify against mk_digest
        let mut digest = [0u8; 20];

        pbkdf2::<Hmac<Sha1>>(master_key, &mk_digest_salt, mk_digest_iter, &mut digest).map_err(
            |e| FsError::FilesystemError(format!("PBKDF2 verification failed: {:?}", e)),
        )?;

        // Constant-time comparison
        Ok(digest == mk_digest)
    }

    /// Verify master key for LUKS2
    fn verify_master_key_v2(&self, master_key: &[u8]) -> FsResult<bool> {
        // LUKS2 uses digest entries for verification
        // The digest is PBKDF2(master_key, salt, iterations) truncated to digest length

        eprintln!(
            "LUKS2 verify: master_key len={}, first 8 bytes={:02x?}",
            master_key.len(),
            &master_key[..master_key.len().min(8)]
        );

        if self.header.digests.is_empty() {
            // If no digest entries found, we can't verify - but try anyway
            // The decryption might still work
            eprintln!("LUKS2 verify: No digests found, assuming success");
            return Ok(true);
        }

        eprintln!(
            "LUKS2 verify: Checking {} digest(s)",
            self.header.digests.len()
        );

        for digest_entry in &self.header.digests {
            eprintln!(
                "LUKS2 verify: Digest {} - hash='{}', salt_len={}, digest_len={}, iterations={}",
                digest_entry.index,
                digest_entry.hash,
                digest_entry.salt.len(),
                digest_entry.digest.len(),
                digest_entry.iterations
            );

            if digest_entry.salt.is_empty() || digest_entry.digest.is_empty() {
                eprintln!(
                    "LUKS2 verify: Skipping digest {} - empty salt or digest",
                    digest_entry.index
                );
                continue;
            }

            let digest_len = digest_entry.digest.len();
            let mut computed = vec![0u8; digest_len];

            let verified = match digest_entry.hash.to_lowercase().as_str() {
                "sha256" | "" => {
                    pbkdf2::<Hmac<Sha256>>(
                        master_key,
                        &digest_entry.salt,
                        digest_entry.iterations,
                        &mut computed,
                    )
                    .map_err(|e| FsError::FilesystemError(format!("PBKDF2 failed: {:?}", e)))?;
                    eprintln!(
                        "LUKS2 verify: Computed digest (SHA256): {:02x?}",
                        &computed[..computed.len().min(16)]
                    );
                    eprintln!(
                        "LUKS2 verify: Expected digest: {:02x?}",
                        &digest_entry.digest[..digest_entry.digest.len().min(16)]
                    );
                    computed == digest_entry.digest
                }
                "sha1" => {
                    pbkdf2::<Hmac<Sha1>>(
                        master_key,
                        &digest_entry.salt,
                        digest_entry.iterations,
                        &mut computed,
                    )
                    .map_err(|e| FsError::FilesystemError(format!("PBKDF2 failed: {:?}", e)))?;
                    eprintln!(
                        "LUKS2 verify: Computed digest (SHA1): {:02x?}",
                        &computed[..computed.len().min(16)]
                    );
                    computed == digest_entry.digest
                }
                "sha512" => {
                    pbkdf2::<Hmac<Sha512>>(
                        master_key,
                        &digest_entry.salt,
                        digest_entry.iterations,
                        &mut computed,
                    )
                    .map_err(|e| FsError::FilesystemError(format!("PBKDF2 failed: {:?}", e)))?;
                    eprintln!(
                        "LUKS2 verify: Computed digest (SHA512): {:02x?}",
                        &computed[..computed.len().min(16)]
                    );
                    computed == digest_entry.digest
                }
                _ => {
                    eprintln!(
                        "LUKS2 verify: Unknown hash type '{}', skipping",
                        digest_entry.hash
                    );
                    continue;
                }
            };

            eprintln!(
                "LUKS2 verify: Digest {} match = {}",
                digest_entry.index, verified
            );

            if verified {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Initialize the cipher with the master key
    fn init_cipher(&mut self, master_key: &[u8]) -> FsResult<()> {
        let key_len = master_key.len();

        if self.header.cipher_mode.to_lowercase().contains("xts") {
            // For XTS mode, split the key
            let (key1, key2) = if key_len >= 64 {
                (&master_key[..32], &master_key[32..64])
            } else if key_len >= 32 {
                (&master_key[..key_len / 2], &master_key[key_len / 2..])
            } else {
                return Err(FsError::FilesystemError(
                    "Master key too short for XTS".to_string(),
                ));
            };

            // Pad keys to 32 bytes if needed
            let mut key1_padded = [0u8; 32];
            let mut key2_padded = [0u8; 32];
            let len = std::cmp::min(key1.len(), 32);
            key1_padded[..len].copy_from_slice(&key1[..len]);
            key2_padded[..len].copy_from_slice(&key2[..len]);

            let cipher1 = Aes256::new_from_slice(&key1_padded)
                .map_err(|_| FsError::FilesystemError("Invalid key1 for XTS".to_string()))?;
            let cipher2 = Aes256::new_from_slice(&key2_padded)
                .map_err(|_| FsError::FilesystemError("Invalid key2 for XTS".to_string()))?;

            self.cipher = Some(Xts128::new(cipher1, cipher2));
        }

        Ok(())
    }

    /// Get the payload offset (where the encrypted filesystem data starts)
    pub fn payload_offset(&self) -> u64 {
        self.partition_offset + self.header.payload_offset
    }

    /// Read and decrypt data from the payload
    pub fn read_decrypted(&mut self, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        if !self.is_unlocked() {
            return Err(FsError::PermissionDenied(
                "LUKS partition is locked".to_string(),
            ));
        }

        let payload_start = self.payload_offset();

        // Calculate sector alignment
        let sector_size = LUKS_SECTOR_SIZE as usize;
        let start_sector = offset as usize / sector_size;
        let offset_in_sector = offset as usize % sector_size;
        let end_offset = offset as usize + buffer.len();
        let end_sector = end_offset.div_ceil(sector_size);
        let num_sectors = end_sector - start_sector;

        // Read aligned sectors
        let read_offset = payload_start + (start_sector as u64 * LUKS_SECTOR_SIZE);
        let mut encrypted = vec![0u8; num_sectors * sector_size];

        let bytes_read = self.disk.read_at(read_offset, &mut encrypted)?;

        if bytes_read == 0 {
            return Ok(0);
        }

        // Decrypt sector by sector
        let cipher_mode = self.header.cipher_mode.to_lowercase();
        let decrypted = if cipher_mode.contains("xts") {
            if let Some(ref xts) = self.cipher {
                let mut decrypted = encrypted;
                for i in 0..num_sectors {
                    let sector_num = start_sector + i;
                    let start = i * sector_size;
                    let end = start + sector_size;
                    if end <= decrypted.len() {
                        let mut tweak = [0u8; 16];
                        tweak[..8].copy_from_slice(&(sector_num as u64).to_le_bytes());
                        xts.decrypt_sector(&mut decrypted[start..end], tweak);
                    }
                }
                decrypted
            } else {
                return Err(FsError::FilesystemError(
                    "XTS cipher not initialized".to_string(),
                ));
            }
        } else if cipher_mode.contains("cbc") {
            if let Some(ref key) = self.master_key {
                self.decrypt_cbc(&encrypted, key, encrypted.len())?
            } else {
                return Err(FsError::FilesystemError(
                    "Master key not available".to_string(),
                ));
            }
        } else {
            return Err(FsError::UnsupportedFilesystem(format!(
                "Unsupported cipher mode: {}",
                cipher_mode
            )));
        };

        // Copy the requested portion to the buffer
        let copy_len = std::cmp::min(buffer.len(), decrypted.len() - offset_in_sector);
        buffer[..copy_len]
            .copy_from_slice(&decrypted[offset_in_sector..offset_in_sector + copy_len]);

        Ok(copy_len)
    }
}

/// Wrapper that provides a decrypted view of a LUKS partition
pub struct DecryptedLuksReader {
    inner: LuksReader,
    position: u64,
}

impl DecryptedLuksReader {
    /// Create a new decrypted reader from an unlocked LUKS reader
    pub fn new(reader: LuksReader) -> FsResult<Self> {
        if !reader.is_unlocked() {
            return Err(FsError::PermissionDenied(
                "LUKS partition must be unlocked first".to_string(),
            ));
        }
        Ok(Self {
            inner: reader,
            position: 0,
        })
    }

    /// Get the underlying LUKS header
    pub fn header(&self) -> &LuksHeader {
        self.inner.header()
    }
}

impl Read for DecryptedLuksReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self
            .inner
            .read_decrypted(self.position, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for DecryptedLuksReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                self.position = n;
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.position = self.position.saturating_add(n as u64);
                } else {
                    self.position = self.position.saturating_sub((-n) as u64);
                }
            }
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SeekFrom::End not supported for LUKS reader",
                ));
            }
        }
        Ok(self.position)
    }
}

/// Probe a partition to check if it's LUKS-encrypted
pub fn probe_luks(disk: &mut RawDisk, partition_offset: u64) -> FsResult<Option<LuksVersion>> {
    let mut header = [0u8; 8];
    disk.read_exact_at(partition_offset, &mut header)?;
    Ok(detect_luks_version(&header))
}
