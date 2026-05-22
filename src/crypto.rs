use crate::error::{LocalPassError, Result};
use crate::vault_file::{NONCE_LEN, SALT_LEN, TAG_LEN};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

pub struct EncryptedPayload {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(master_password: &[u8], plaintext: &[u8]) -> Result<EncryptedPayload> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key_bytes = derive_key(master_password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut ciphertext)
        .map_err(|_| LocalPassError::UnlockFailed)?;

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());
    key_bytes.zeroize();

    Ok(EncryptedPayload {
        salt,
        nonce,
        tag: tag_bytes,
        ciphertext,
    })
}

pub fn decrypt(master_password: &[u8], payload: &EncryptedPayload) -> Result<Vec<u8>> {
    let mut key_bytes = derive_key(master_password, &payload.salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut plaintext = payload.ciphertext.clone();
    let result = cipher.decrypt_in_place_detached(
        Nonce::from_slice(&payload.nonce),
        b"",
        &mut plaintext,
        Tag::from_slice(&payload.tag),
    );
    key_bytes.zeroize();

    result.map_err(|_| LocalPassError::UnlockFailed)?;
    Ok(plaintext)
}

fn derive_key(master_password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let params = Params::new(65_536, 3, 4, Some(32))
        .map_err(|error| LocalPassError::Message(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(master_password, salt, &mut key)
        .map_err(|error| LocalPassError::Message(error.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let encrypted = encrypt(b"master password", b"[]").unwrap();
        let decrypted = decrypt(b"master password", &encrypted).unwrap();

        assert_eq!(decrypted, b"[]");
    }

    #[test]
    fn wrong_password_fails_to_decrypt() {
        let encrypted = encrypt(b"master password", b"[]").unwrap();

        assert!(matches!(
            decrypt(b"wrong password", &encrypted),
            Err(LocalPassError::UnlockFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let mut encrypted = encrypt(b"master password", b"[]").unwrap();
        encrypted.ciphertext[0] ^= 0x01;

        assert!(matches!(
            decrypt(b"master password", &encrypted),
            Err(LocalPassError::UnlockFailed)
        ));
    }
}
