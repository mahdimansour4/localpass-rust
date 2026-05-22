# LocalPass Rust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working offline Rust CLI password manager with encrypted local vault storage, basic CRUD commands, password generation, and focused tests.

**Architecture:** The app is split into small modules: CLI parsing, command orchestration, crypto, binary vault-file encoding, vault CRUD, password generation, clipboard behavior, and errors. The vault stores one encrypted JSON array in a binary file with a fixed header. Tests are written before implementation for each behavior.

**Tech Stack:** Rust 1.95, Cargo, `clap`, `argon2`, `aes-gcm`, `rand`, `serde`, `serde_json`, `uuid`, `chrono`, `zeroize`, `secrecy`, `rpassword`, `arboard`, `thiserror`, `tempfile`.

---

## File Structure

- Create `Cargo.toml`: package metadata and dependencies.
- Create `src/main.rs`: app entry point and top-level error reporting.
- Create `src/lib.rs`: module exports for unit and integration tests.
- Create `src/cli.rs`: CLI arguments and subcommands.
- Create `src/error.rs`: shared `LocalPassError` and `Result` alias.
- Create `src/entry.rs`: vault entry data type.
- Create `src/vault.rs`: in-memory vault CRUD and JSON serialization.
- Create `src/vault_file.rs`: binary vault file format parsing/writing.
- Create `src/crypto.rs`: Argon2id key derivation and AES-256-GCM encryption/decryption.
- Create `src/generator.rs`: password generation.
- Create `src/clipboard.rs`: clipboard copy and best-effort clearing.
- Create `src/commands.rs`: command handlers that connect CLI, vault, crypto, and storage.
- Create `tests/cli_flow.rs`: integration tests using temporary vault paths.
- Create `README.md`: setup, usage, security model, and resume talking points.

## Task 1: Cargo Project And CLI Shape

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `src/cli.rs`
- Create: `src/error.rs`

- [ ] **Step 1: Create the Cargo package skeleton**

Run:

```bash
cargo init --bin --name localpass .
```

Expected: `Cargo.toml` and `src/main.rs` are created.

- [ ] **Step 2: Add dependencies**

Update `Cargo.toml`:

```toml
[package]
name = "localpass"
version = "0.1.0"
edition = "2024"

[dependencies]
aes-gcm = "0.10"
arboard = "3"
argon2 = "0.5"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
rand = "0.8"
rpassword = "7"
secrecy = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
uuid = { version = "1", features = ["v4", "serde"] }
zeroize = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

- [ ] **Step 3: Write failing CLI parser tests**

Create `src/cli.rs` with tests first:

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "localpass")]
pub struct Cli {
    #[arg(long, global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Add { site: String },
    List,
    Get { site: String, #[arg(long)] show: bool },
    Delete { site: String },
    Generate {
        #[arg(long, default_value_t = 16)]
        length: usize,
        #[arg(long)]
        symbols: bool,
        #[arg(long = "no-upper")]
        no_upper: bool,
        #[arg(long = "no-digits")]
        no_digits: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vault_override_and_get_show() {
        let cli = Cli::parse_from([
            "localpass",
            "--vault",
            "./demo.vault",
            "get",
            "github",
            "--show",
        ]);

        assert_eq!(cli.vault, Some(PathBuf::from("./demo.vault")));
        match cli.command {
            Command::Get { site, show } => {
                assert_eq!(site, "github");
                assert!(show);
            }
            _ => panic!("expected get command"),
        }
    }

    #[test]
    fn generate_defaults_to_length_16() {
        let cli = Cli::parse_from(["localpass", "generate"]);

        match cli.command {
            Command::Generate {
                length,
                symbols,
                no_upper,
                no_digits,
            } => {
                assert_eq!(length, 16);
                assert!(!symbols);
                assert!(!no_upper);
                assert!(!no_digits);
            }
            _ => panic!("expected generate command"),
        }
    }
}
```

- [ ] **Step 4: Run tests and verify they fail because the project does not compile fully yet**

Run:

```bash
cargo test cli::tests
```

Expected: tests compile once `lib.rs` exports `cli`; before that, Cargo reports missing module wiring.

- [ ] **Step 5: Add module wiring and top-level error type**

Create `src/lib.rs`:

```rust
pub mod cli;
pub mod error;
```

Create `src/error.rs`:

```rust
pub type Result<T> = std::result::Result<T, LocalPassError>;

#[derive(Debug, thiserror::Error)]
pub enum LocalPassError {
    #[error("vault already exists")]
    VaultAlreadyExists,

    #[error("vault not found")]
    VaultNotFound,

    #[error("invalid vault file")]
    InvalidVaultFile,

    #[error("failed to unlock vault")]
    UnlockFailed,

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("invalid password generator options")]
    InvalidGeneratorOptions,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Message(String),
}
```

Update `src/main.rs`:

```rust
use clap::Parser;
use localpass::cli::Cli;

fn main() {
    let _cli = Cli::parse();
}
```

- [ ] **Step 6: Run tests and verify pass**

Run:

```bash
cargo test cli::tests
```

Expected: both CLI parser tests pass.

Explanation checkpoint: explain `Cargo.toml`, `src/main.rs`, `src/lib.rs`, and how `clap` turns terminal arguments into typed Rust enums.

## Task 2: Entry Model And In-Memory Vault

**Files:**
- Create: `src/entry.rs`
- Create: `src/vault.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing vault CRUD tests**

Create `src/vault.rs`:

```rust
use crate::entry::Entry;
use crate::error::{LocalPassError, Result};

#[derive(Debug, Clone, Default)]
pub struct Vault {
    entries: Vec<Entry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find_entry_by_site() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "").unwrap();

        let entry = vault.find("github").unwrap();

        assert_eq!(entry.site, "github");
        assert_eq!(entry.username, "mahdi@example.com");
        assert_eq!(entry.password, "secret");
    }

    #[test]
    fn delete_removes_entry() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "").unwrap();

        vault.delete("github").unwrap();

        assert!(matches!(
            vault.find("github"),
            Err(LocalPassError::EntryNotFound(site)) if site == "github"
        ));
    }

    #[test]
    fn serializes_and_deserializes_json_payload() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "main account").unwrap();

        let json = vault.to_json_bytes().unwrap();
        let parsed = Vault::from_json_bytes(&json).unwrap();

        assert_eq!(parsed.find("github").unwrap().notes, "main account");
    }
}
```

- [ ] **Step 2: Run tests and verify fail because `Entry` and methods are missing**

Run:

```bash
cargo test vault::tests
```

Expected: compile errors for missing `entry` module and missing methods.

- [ ] **Step 3: Implement entry and vault minimally**

Create `src/entry.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: Uuid,
    pub site: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Entry {
    pub fn new(site: &str, username: &str, password: &str, notes: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            site: site.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            notes: notes.to_owned(),
            created_at: now,
            updated_at: now,
        }
    }
}
```

Update `src/vault.rs`:

```rust
use crate::entry::Entry;
use crate::error::{LocalPassError, Result};

#[derive(Debug, Clone, Default)]
pub struct Vault {
    entries: Vec<Entry>,
}

impl Vault {
    pub fn add(&mut self, site: &str, username: &str, password: &str, notes: &str) -> Result<()> {
        self.entries.push(Entry::new(site, username, password, notes));
        Ok(())
    }

    pub fn find(&self, site: &str) -> Result<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.site == site)
            .ok_or_else(|| LocalPassError::EntryNotFound(site.to_owned()))
    }

    pub fn delete(&mut self, site: &str) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.site != site);
        if self.entries.len() == before {
            return Err(LocalPassError::EntryNotFound(site.to_owned()));
        }
        Ok(())
    }

    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.entries)?)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        let entries = serde_json::from_slice(bytes)?;
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find_entry_by_site() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "").unwrap();

        let entry = vault.find("github").unwrap();

        assert_eq!(entry.site, "github");
        assert_eq!(entry.username, "mahdi@example.com");
        assert_eq!(entry.password, "secret");
    }

    #[test]
    fn delete_removes_entry() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "").unwrap();

        vault.delete("github").unwrap();

        assert!(matches!(
            vault.find("github"),
            Err(LocalPassError::EntryNotFound(site)) if site == "github"
        ));
    }

    #[test]
    fn serializes_and_deserializes_json_payload() {
        let mut vault = Vault::default();
        vault.add("github", "mahdi@example.com", "secret", "main account").unwrap();

        let json = vault.to_json_bytes().unwrap();
        let parsed = Vault::from_json_bytes(&json).unwrap();

        assert_eq!(parsed.find("github").unwrap().notes, "main account");
    }
}
```

Update `src/lib.rs`:

```rust
pub mod cli;
pub mod entry;
pub mod error;
pub mod vault;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test vault::tests
```

Expected: vault tests pass.

Explanation checkpoint: explain `Entry`, `Vault`, JSON serialization, and why the password is only plain text inside the decrypted in-memory vault.

## Task 3: Password Generator

**Files:**
- Create: `src/generator.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing generator tests**

Create `src/generator.rs`:

```rust
use crate::error::{LocalPassError, Result};

pub struct GeneratorOptions {
    pub length: usize,
    pub symbols: bool,
    pub no_upper: bool,
    pub no_digits: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let password = generate_password(&GeneratorOptions {
            length: 24,
            symbols: true,
            no_upper: false,
            no_digits: false,
        })
        .unwrap();

        assert_eq!(password.len(), 24);
    }

    #[test]
    fn rejects_empty_character_set() {
        let result = generate_password(&GeneratorOptions {
            length: 8,
            symbols: false,
            no_upper: true,
            no_digits: true,
        });

        assert!(matches!(result, Err(LocalPassError::InvalidGeneratorOptions)));
    }
}
```

- [ ] **Step 2: Run tests and verify fail because `generate_password` is missing**

Run:

```bash
cargo test generator::tests
```

Expected: compile error for missing `generate_password`.

- [ ] **Step 3: Implement generator**

Update `src/generator.rs`:

```rust
use crate::error::{LocalPassError, Result};
use rand::{rngs::OsRng, RngCore};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub struct GeneratorOptions {
    pub length: usize,
    pub symbols: bool,
    pub no_upper: bool,
    pub no_digits: bool,
}

pub fn generate_password(options: &GeneratorOptions) -> Result<String> {
    if options.length == 0 {
        return Err(LocalPassError::InvalidGeneratorOptions);
    }

    let mut alphabet = Vec::new();
    alphabet.extend_from_slice(LOWER);
    if !options.no_upper {
        alphabet.extend_from_slice(UPPER);
    }
    if !options.no_digits {
        alphabet.extend_from_slice(DIGITS);
    }
    if options.symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    if alphabet.len() == LOWER.len() && options.no_upper && options.no_digits && !options.symbols {
        return Err(LocalPassError::InvalidGeneratorOptions);
    }

    let mut output = String::with_capacity(options.length);
    for _ in 0..options.length {
        let index = (OsRng.next_u32() as usize) % alphabet.len();
        output.push(alphabet[index] as char);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let password = generate_password(&GeneratorOptions {
            length: 24,
            symbols: true,
            no_upper: false,
            no_digits: false,
        })
        .unwrap();

        assert_eq!(password.len(), 24);
    }

    #[test]
    fn rejects_empty_character_set() {
        let result = generate_password(&GeneratorOptions {
            length: 8,
            symbols: false,
            no_upper: true,
            no_digits: true,
        });

        assert!(matches!(result, Err(LocalPassError::InvalidGeneratorOptions)));
    }
}
```

Update `src/lib.rs`:

```rust
pub mod cli;
pub mod entry;
pub mod error;
pub mod generator;
pub mod vault;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test generator::tests
```

Expected: generator tests pass.

Explanation checkpoint: explain CSPRNG randomness and why modulo selection is acceptable for this first version but can be improved with rejection sampling later.

## Task 4: Vault File Format

**Files:**
- Create: `src/vault_file.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing vault file tests**

Create `src/vault_file.rs`:

```rust
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
```

- [ ] **Step 2: Run tests and verify fail because methods are missing**

Run:

```bash
cargo test vault_file::tests
```

Expected: compile errors for missing `to_bytes` and `from_bytes`.

- [ ] **Step 3: Implement binary encoding**

Update `src/vault_file.rs`:

```rust
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
```

Update `src/lib.rs`:

```rust
pub mod cli;
pub mod entry;
pub mod error;
pub mod generator;
pub mod vault;
pub mod vault_file;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test vault_file::tests
```

Expected: vault file tests pass.

Explanation checkpoint: explain the binary header byte by byte and why the ciphertext is opaque.

## Task 5: Crypto Layer

**Files:**
- Create: `src/crypto.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing crypto tests**

Create `src/crypto.rs`:

```rust
use crate::error::{LocalPassError, Result};
use crate::vault_file::{NONCE_LEN, SALT_LEN, TAG_LEN};

pub struct EncryptedPayload {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
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
```

- [ ] **Step 2: Run tests and verify fail because crypto functions are missing**

Run:

```bash
cargo test crypto::tests
```

Expected: compile errors for missing `encrypt` and `decrypt`.

- [ ] **Step 3: Implement key derivation and AES-GCM**

Update `src/crypto.rs`:

```rust
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use argon2::{Algorithm, Argon2, Params, Version};
use crate::error::{LocalPassError, Result};
use crate::vault_file::{NONCE_LEN, SALT_LEN, TAG_LEN};
use rand::{rngs::OsRng, RngCore};
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
```

Update `src/lib.rs`:

```rust
pub mod cli;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod generator;
pub mod vault;
pub mod vault_file;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test crypto::tests
```

Expected: crypto tests pass. These tests may take a few seconds because Argon2id intentionally uses memory and CPU.

Explanation checkpoint: explain salt, Argon2id, AES-GCM nonce, ciphertext, authentication tag, and why wrong passwords and tampering both fail.

## Task 6: Command Handlers And CLI Flows

**Files:**
- Create: `src/commands.rs`
- Create: `src/clipboard.rs`
- Modify: `src/main.rs`
- Modify: `src/lib.rs`
- Create: `tests/cli_flow.rs`

- [ ] **Step 1: Write failing integration tests for non-interactive command helpers**

Create `tests/cli_flow.rs`:

```rust
use localpass::commands::{
    add_entry_with_values, delete_entry_with_password, init_vault_with_password,
    list_entries_with_password, read_password_with_password,
};
use tempfile::tempdir;

#[test]
fn init_add_list_get_delete_flow() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();

    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert_eq!(entries, vec![("github".to_owned(), "mahdi@example.com".to_owned())]);

    let password = read_password_with_password(&vault_path, "master password", "github").unwrap();
    assert_eq!(password, "secret-password");

    delete_entry_with_password(&vault_path, "master password", "github").unwrap();
    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert!(entries.is_empty());
}
```

- [ ] **Step 2: Run tests and verify fail because command helpers are missing**

Run:

```bash
cargo test --test cli_flow
```

Expected: compile errors for missing `commands` module and helpers.

- [ ] **Step 3: Implement storage-backed helper functions**

Create `src/commands.rs`:

```rust
use crate::crypto::{decrypt, encrypt, EncryptedPayload};
use crate::error::{LocalPassError, Result};
use crate::vault::Vault;
use crate::vault_file::VaultFile;
use std::fs;
use std::path::{Path, PathBuf};

pub fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".localpass").join("localpass.vault")
}

pub fn init_vault_with_password(path: &Path, master_password: &str) -> Result<()> {
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

pub fn list_entries_with_password(path: &Path, master_password: &str) -> Result<Vec<(String, String)>> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault
        .list()
        .iter()
        .map(|entry| (entry.site.clone(), entry.username.clone()))
        .collect())
}

pub fn read_password_with_password(path: &Path, master_password: &str, site: &str) -> Result<String> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault.find(site)?.password.clone())
}

pub fn delete_entry_with_password(path: &Path, master_password: &str, site: &str) -> Result<()> {
    let mut vault = unlock_vault(path, master_password)?;
    vault.delete(site)?;
    save_vault(path, master_password, &vault)
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
```

Create `src/clipboard.rs`:

```rust
use crate::error::{LocalPassError, Result};
use std::thread;
use std::time::Duration;

pub fn copy_and_clear_after(password: String, seconds: u64) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| LocalPassError::Message(error.to_string()))?;
    clipboard
        .set_text(password.clone())
        .map_err(|error| LocalPassError::Message(error.to_string()))?;

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text(String::new());
        }
    });

    Ok(())
}
```

Update `src/lib.rs`:

```rust
pub mod cli;
pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod generator;
pub mod vault;
pub mod vault_file;
```

- [ ] **Step 4: Run integration tests and verify pass**

Run:

```bash
cargo test --test cli_flow
```

Expected: integration flow test passes.

- [ ] **Step 5: Wire interactive CLI in `main.rs`**

Update `src/main.rs`:

```rust
use clap::Parser;
use localpass::cli::{Cli, Command};
use localpass::commands::{
    add_entry_with_values, default_vault_path, delete_entry_with_password,
    init_vault_with_password, list_entries_with_password, read_password_with_password,
};
use localpass::error::Result;
use localpass::generator::{generate_password, GeneratorOptions};
use std::io::{self, Write};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(default_vault_path);

    match cli.command {
        Command::Init => {
            let password = prompt_password_confirmed()?;
            init_vault_with_password(&vault_path, &password)?;
            println!("vault initialized at {}", vault_path.display());
        }
        Command::Add { site } => {
            let master = rpassword::prompt_password("Master password: ")?;
            let username = prompt("Username: ")?;
            let password = rpassword::prompt_password("Password: ")?;
            let notes = prompt("Notes: ")?;
            add_entry_with_values(&vault_path, &master, &site, &username, &password, &notes)?;
            println!("added {site}");
        }
        Command::List => {
            let master = rpassword::prompt_password("Master password: ")?;
            for (site, username) in list_entries_with_password(&vault_path, &master)? {
                println!("{site}\t{username}");
            }
        }
        Command::Get { site, show } => {
            let master = rpassword::prompt_password("Master password: ")?;
            let password = read_password_with_password(&vault_path, &master, &site)?;
            if show {
                println!("{password}");
            } else {
                localpass::clipboard::copy_and_clear_after(password, 30)?;
                println!("password copied to clipboard");
            }
        }
        Command::Delete { site } => {
            let master = rpassword::prompt_password("Master password: ")?;
            delete_entry_with_password(&vault_path, &master, &site)?;
            println!("deleted {site}");
        }
        Command::Generate {
            length,
            symbols,
            no_upper,
            no_digits,
        } => {
            let password = generate_password(&GeneratorOptions {
                length,
                symbols,
                no_upper,
                no_digits,
            })?;
            println!("{password}");
        }
    }

    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end().to_owned())
}

fn prompt_password_confirmed() -> Result<String> {
    let password = rpassword::prompt_password("Master password: ")?;
    let confirm = rpassword::prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err(localpass::error::LocalPassError::Message(
            "master passwords do not match".to_owned(),
        ));
    }
    Ok(password)
}
```

- [ ] **Step 6: Run full test suite**

Run:

```bash
cargo test
```

Expected: all unit and integration tests pass.

Explanation checkpoint: explain why integration tests use helper functions instead of trying to type into password prompts.

## Task 7: README And Manual Demo

**Files:**
- Create: `README.md`
- Optional modify: `.gitignore`

- [ ] **Step 1: Add `.gitignore`**

Create `.gitignore`:

```gitignore
/target/
*.vault
```

- [ ] **Step 2: Write README**

Create `README.md`:

```markdown
# LocalPass

LocalPass is a fully offline command-line password manager written in Rust. It stores credentials in one encrypted vault file and never sends data over a network.

## Features

- Offline encrypted vault
- Master password based unlocking
- Argon2id key derivation
- AES-256-GCM authenticated encryption
- Add, list, get, and delete credentials
- Strong password generation
- Default vault path: `~/.localpass/localpass.vault`
- Test/demo vault override with `--vault <path>`

## Install And Run

```bash
cargo build
cargo run -- init
cargo run -- add github
cargo run -- list
cargo run -- get github
cargo run -- get github --show
cargo run -- generate --length 24 --symbols
```

For a demo vault:

```bash
cargo run -- --vault ./demo.vault init
cargo run -- --vault ./demo.vault add github
cargo run -- --vault ./demo.vault get github --show
```

## Security Model

LocalPass protects a stolen vault file. The vault is encrypted with AES-256-GCM, and the encryption key is derived from the master password using Argon2id. The master password is never stored.

LocalPass does not protect against a compromised operating system, keyloggers, malware, or an attacker watching while the vault is unlocked.

## Resume Talking Points

- Designed a local encrypted vault file format with authenticated encryption.
- Used Argon2id to derive encryption keys from a master password.
- Built a Rust CLI with typed command parsing and integration tests.
- Separated crypto, storage, vault logic, CLI parsing, and command orchestration into focused modules.
```

- [ ] **Step 3: Run formatting and tests**

Run:

```bash
cargo fmt
cargo test
```

Expected: formatting succeeds and all tests pass.

- [ ] **Step 4: Manual demo**

Run:

```bash
cargo run -- --vault ./demo.vault init
cargo run -- --vault ./demo.vault add github
cargo run -- --vault ./demo.vault list
cargo run -- --vault ./demo.vault get github --show
cargo run -- --vault ./demo.vault delete github
```

Expected: the demo vault can be initialized, populated, listed, read with `--show`, and cleaned up.

Explanation checkpoint: explain how to demo the project and how to describe its security boundaries honestly.

## Self-Review

Spec coverage:

- Rust stack is covered by Task 1 dependencies.
- Default vault path and `--vault` override are covered by Tasks 1 and 6.
- `init`, `add`, `list`, `get --show`, `delete`, and `generate` are covered.
- Vault file format is covered by Task 4.
- Argon2id and AES-GCM are covered by Task 5.
- Tests are covered across Tasks 1 through 7.
- README and resume explanation are covered by Task 7.

Intentional v1 gaps:

- Clipboard clearing is best effort because platform clipboard systems differ.
- `generate --save`, rekey, TOTP, GUI/TUI, browser integration, fuzzy search, and imports remain deferred by the approved design.

Placeholder scan: no TBD/TODO placeholders are required for implementation.

Type consistency: command names, module names, and helper function names are consistent across tasks.
