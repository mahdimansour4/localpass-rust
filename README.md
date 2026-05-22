# LocalPass

LocalPass is a fully offline command-line password manager written in Rust. It stores credentials in a single encrypted vault file and never sends data over a network.

This project was built as a security-focused systems project for a resume portfolio. The main goal is to demonstrate practical cryptography usage, careful data handling, command-line application design, and test coverage around sensitive workflows.

## Highlights

- Offline encrypted vault stored as one local file
- Master password unlock without storing the master password
- Argon2id key derivation
- AES-256-GCM authenticated encryption
- Binary vault file header with magic bytes, version, salt, nonce, tag, and ciphertext
- Add, list, search, get, update, and delete credential entries
- Duplicate-site prevention so `get <site>` stays unambiguous
- Password generation with configurable length and symbols
- Generate-and-save workflow for new credentials
- Master password rotation with `rekey`
- Safe vault stats that do not expose usernames, passwords, or notes
- Unit and integration tests for crypto, vault format, CRUD, search, rekey, and CLI flows

## Tech Stack

- Rust 2024 edition
- `clap` for typed CLI parsing
- `argon2` for Argon2id key derivation
- `aes-gcm` for AES-256-GCM encryption
- `serde` and `serde_json` for encrypted vault payload serialization
- `uuid` and `chrono` for entry IDs and timestamps
- `rand` for OS-backed randomness
- `rpassword` for hidden password prompts
- `arboard` for clipboard access
- `thiserror` for typed errors

## Architecture

```text
src/
  main.rs        interactive command handling and prompts
  cli.rs         typed CLI definitions
  commands.rs    storage-backed command helpers
  crypto.rs      Argon2id and AES-GCM
  vault_file.rs  binary vault file encoding
  vault.rs       in-memory vault operations
  entry.rs       credential entry model
  generator.rs   password generation
  clipboard.rs   clipboard copy and best-effort clearing
  error.rs       application error types
```

The app separates user interaction from testable command helpers. Integration tests call helper functions directly, which avoids brittle terminal automation while still testing encrypted vault behavior end to end.

## Vault Format

The vault file is a flat binary file:

```text
LPAS | version | salt | nonce | tag | ciphertext
```

The ciphertext is an AES-256-GCM encrypted JSON array of credential entries. Without the master password, vault contents are not readable through the LocalPass file format. If a wrong password is used, or if the vault is tampered with, AES-GCM authentication fails and LocalPass reports an unlock failure.

## Security Model

LocalPass is designed to protect a stolen vault file. An attacker who copies the vault should not be able to read or modify credentials without the master password.

Security properties:

- The master password is never stored.
- A 256-bit encryption key is derived at unlock time with Argon2id.
- Each save uses fresh encryption metadata.
- AES-GCM detects wrong passwords and file tampering.
- `get <site>` copies to the clipboard by default instead of printing passwords.
- `get <site> --show` exists only for explicit demos and testing.
- `list`, `search`, and `stats` never print passwords.

Out of scope:

- Compromised operating systems
- Keyloggers
- Malware with access to the running process
- Physical access while the vault is unlocked
- Cloud sync and browser autofill

## Commands

Default vault path:

```text
~/.localpass/localpass.vault
```

Use `--vault <path>` for demos and tests:

```bash
cargo run -- --vault ./demo.vault <command>
```

Command reference:

```bash
cargo run -- init
cargo run -- add github
cargo run -- list
cargo run -- search git
cargo run -- stats
cargo run -- get github
cargo run -- get github --show
cargo run -- update github
cargo run -- delete github
cargo run -- rekey
cargo run -- generate --length 24 --symbols
cargo run -- generate --length 24 --symbols --save gitlab
```

`add` and `generate --save` create new entries. If a site already exists, use `update <site>`.

## Demo Flow

```bash
cargo run -- --vault ./demo.vault init
cargo run -- --vault ./demo.vault add github
cargo run -- --vault ./demo.vault generate --length 24 --symbols --save gitlab
cargo run -- --vault ./demo.vault list
cargo run -- --vault ./demo.vault search git
cargo run -- --vault ./demo.vault stats
cargo run -- --vault ./demo.vault get gitlab --show
cargo run -- --vault ./demo.vault update github
cargo run -- --vault ./demo.vault rekey
```

After `rekey`, use the new master password. The old master password should no longer unlock the vault.

## Build And Test

```bash
cargo build
cargo test
```

The integration tests use temporary vault files and cover encrypted end-to-end workflows.

## Resume Talking Points

- Built an offline password manager in Rust with a documented encrypted vault format.
- Used Argon2id and AES-256-GCM to protect vault contents.
- Designed clear module boundaries between CLI parsing, crypto, storage, and vault operations.
- Implemented master password rotation without changing the vault format.
- Added integration tests for encrypted workflows including add, update, delete, search, generate-save, and rekey.
- Documented the project threat model and avoided overclaiming security guarantees.
