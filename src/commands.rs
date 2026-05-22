use crate::crypto::{EncryptedPayload, decrypt, encrypt};
use crate::error::{LocalPassError, Result};
use crate::generator::{GeneratorOptions, generate_password};
use crate::vault::Vault;
use crate::vault_file::VaultFile;
use std::fs;
use std::path::{Path, PathBuf};

const MIN_MASTER_PASSWORD_LEN: usize = 12;

pub fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home)
        .join(".localpass")
        .join("localpass.vault")
}

pub fn init_vault_with_password(path: &Path, master_password: &str) -> Result<()> {
    validate_master_password(master_password)?;

    if path.exists() {
        return Err(LocalPassError::VaultAlreadyExists);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let vault = Vault::default();
    let encrypted = encrypt(master_password.as_bytes(), &vault.to_json_bytes()?)?;
    let file = VaultFile {
        salt: encrypted.salt,
        nonce: encrypted.nonce,
        tag: encrypted.tag,
        ciphertext: encrypted.ciphertext,
    };
    fs::write(path, file.to_bytes())?;
    Ok(())
}

pub fn add_entry_with_values(
    path: &Path,
    master_password: &str,
    site: &str,
    username: &str,
    password: &str,
    notes: &str,
) -> Result<()> {
    let mut vault = unlock_vault(path, master_password)?;
    vault.add(site, username, password, notes)?;
    save_vault(path, master_password, &vault)
}

pub fn update_entry_with_values(
    path: &Path,
    master_password: &str,
    site: &str,
    username: &str,
    password: &str,
    notes: &str,
) -> Result<()> {
    let mut vault = unlock_vault(path, master_password)?;
    vault.update(site, username, password, notes)?;
    save_vault(path, master_password, &vault)
}

pub fn generate_and_save_entry_with_values(
    path: &Path,
    master_password: &str,
    site: &str,
    username: &str,
    notes: &str,
    options: &GeneratorOptions,
) -> Result<()> {
    let password = generate_password(options)?;
    add_entry_with_values(path, master_password, site, username, &password, notes)
}

pub fn list_entries_with_password(
    path: &Path,
    master_password: &str,
) -> Result<Vec<(String, String)>> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault
        .list()
        .iter()
        .map(|entry| (entry.site.clone(), entry.username.clone()))
        .collect())
}

pub fn search_entries_with_password(
    path: &Path,
    master_password: &str,
    query: &str,
) -> Result<Vec<(String, String)>> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault
        .search(query)
        .iter()
        .map(|entry| (entry.site.clone(), entry.username.clone()))
        .collect())
}

pub fn stats_with_password(path: &Path, master_password: &str) -> Result<usize> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault.entry_count())
}

pub fn read_password_with_password(
    path: &Path,
    master_password: &str,
    site: &str,
) -> Result<String> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault.find(site)?.password.clone())
}

pub fn delete_entry_with_password(path: &Path, master_password: &str, site: &str) -> Result<()> {
    let mut vault = unlock_vault(path, master_password)?;
    vault.delete(site)?;
    save_vault(path, master_password, &vault)
}

pub fn rekey_vault_with_passwords(
    path: &Path,
    current_master_password: &str,
    new_master_password: &str,
) -> Result<()> {
    validate_master_password(new_master_password)?;

    let vault = unlock_vault(path, current_master_password)?;
    save_vault(path, new_master_password, &vault)
}

fn validate_master_password(master_password: &str) -> Result<()> {
    if master_password.trim().chars().count() < MIN_MASTER_PASSWORD_LEN {
        return Err(LocalPassError::InvalidMasterPassword);
    }
    Ok(())
}

fn unlock_vault(path: &Path, master_password: &str) -> Result<Vault> {
    if !path.exists() {
        return Err(LocalPassError::VaultNotFound);
    }
    let bytes = fs::read(path)?;
    let file = VaultFile::from_bytes(&bytes)?;
    let payload = EncryptedPayload {
        salt: file.salt,
        nonce: file.nonce,
        tag: file.tag,
        ciphertext: file.ciphertext,
    };
    let plaintext = decrypt(master_password.as_bytes(), &payload)?;
    Vault::from_json_bytes(&plaintext)
}

fn save_vault(path: &Path, master_password: &str, vault: &Vault) -> Result<()> {
    let encrypted = encrypt(master_password.as_bytes(), &vault.to_json_bytes()?)?;
    let file = VaultFile {
        salt: encrypted.salt,
        nonce: encrypted.nonce,
        tag: encrypted.tag,
        ciphertext: encrypted.ciphertext,
    };
    fs::write(path, file.to_bytes())?;
    Ok(())
}
