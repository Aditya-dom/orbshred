#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ShredType {
    Data,
    Code,
}

impl std::fmt::Display for ShredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShredType::Data => write!(f, "data"),
            ShredType::Code => write!(f, "code"),
        }
    }
}

/// Minimal Solana shred header layout:
///   [0..64]  signature (Ed25519, 64 bytes)
///   [64]     ShredVariant byte
///   [65..73] slot (u64 LE)
///   [73..77] index (u32 LE)
///   [77..79] version (u16 LE)
///   [79..83] fec_set_index (u32 LE)
const MIN_SHRED_SIZE: usize = 83;

/// Determine shred type from variant byte.
/// Bit 7 (MSB) == 1 → Data, Bit 7 == 0 → Code.
/// Special cases: 0xA5 = legacy data, 0x5A = legacy code.
pub fn shred_type(variant: u8) -> ShredType {
    match variant {
        0xA5 => ShredType::Data,
        0x5A => ShredType::Code,
        v => {
            if v & 0x80 != 0 {
                ShredType::Data
            } else {
                ShredType::Code
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShredKey {
    pub slot: u64,
    pub index: u32,
    pub shred_type: ShredType,
}

/// Parse a raw UDP shred buffer into its identifying key.
/// Returns None if the buffer is too short or slot is 0.
pub fn parse_shred_key(buf: &[u8]) -> Option<ShredKey> {
    if buf.len() < MIN_SHRED_SIZE {
        return None;
    }
    let variant = buf[64];
    let slot = u64::from_le_bytes(buf[65..73].try_into().ok()?);
    let index = u32::from_le_bytes(buf[73..77].try_into().ok()?);
    if slot == 0 {
        return None;
    }
    Some(ShredKey {
        slot,
        index,
        shred_type: shred_type(variant),
    })
}
