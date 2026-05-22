use crate::error::{LocalPassError, Result};

pub const MAGIC: &[u8; 4] = b"LPAS";
pub const VERSION: u16 = 1;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 4 + 2 + SALT_LEN + NONCE_LEN + TAG_LEN;

pub struct VaultFile {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(LocalPassError::InvalidVaultFile);
        }
        if &bytes[0..4] != MAGIC {
            return Err(LocalPassError::InvalidVaultFile);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(LocalPassError::InvalidVaultFile);
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[6..38]);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[38..50]);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[50..66]);

        Ok(Self {
            salt,
            nonce,
            tag,
            ciphertext: bytes[66..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_vault_file() {
        let file = VaultFile {
            salt: [1; SALT_LEN],
            nonce: [2; NONCE_LEN],
            tag: [3; TAG_LEN],
            ciphertext: b"ciphertext".to_vec(),
        };

        let bytes = file.to_bytes();
        let parsed = VaultFile::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.salt, [1; SALT_LEN]);
        assert_eq!(parsed.nonce, [2; NONCE_LEN]);
        assert_eq!(parsed.tag, [3; TAG_LEN]);
        assert_eq!(parsed.ciphertext, b"ciphertext");
    }

    #[test]
    fn rejects_invalid_magic() {
        let bytes = vec![0; HEADER_LEN];

        assert!(matches!(
            VaultFile::from_bytes(&bytes),
            Err(LocalPassError::InvalidVaultFile)
        ));
    }
}
