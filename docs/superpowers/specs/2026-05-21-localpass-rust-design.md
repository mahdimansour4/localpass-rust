# LocalPass Rust Design

Date: 2026-05-21
Status: Approved for implementation planning

## Purpose

LocalPass is a fully offline command-line password manager for a resume project. It stores credentials in a single encrypted vault file on disk. The master password is never stored; it is used at unlock time to derive an encryption key.

The project should be understandable step by step. Each module should have a clear responsibility so the implementation can be explained in the README and in interviews.

## Technology Choices

LocalPass will be implemented in Rust instead of the original C++17 design.

Rust is the better default for this project because memory safety matters in a password manager. It also gives a strong resume story: the project uses systems-level tooling while reducing classes of memory bugs that are common in C and C++.

Core dependencies:

- `clap`: command-line parsing
- `argon2`: Argon2id key derivation from the master password
- `aes-gcm`: AES-256-GCM authenticated encryption
- `rand`: cryptographically secure randomness
- `serde` and `serde_json`: JSON vault payload serialization
- `uuid`: entry IDs
- `chrono`: UTC timestamps
- `zeroize` and `secrecy`: reduce accidental exposure of sensitive strings in memory
- `rpassword`: master password prompts without terminal echo
- `arboard`: clipboard integration
- `thiserror`: typed application errors
- `tempfile`: integration tests

## Vault Location

The default vault path is:

```text
~/.localpass/localpass.vault
```

All commands should use that path unless the user passes an override:

```bash
localpass --vault ./demo.vault init
localpass --vault ./demo.vault add github
```

This avoids accidentally creating vaults in random working directories and reduces the risk of committing a vault file to Git.

## Commands

### `localpass init`

Creates a new encrypted vault.

Behavior:

- Creates `~/.localpass/` if needed
- Refuses to overwrite an existing vault unless a future `--force` option is added
- Prompts for a master password and confirmation
- Generates a random salt
- Derives an encryption key with Argon2id
- Encrypts an empty JSON array
- Writes the vault file

### `localpass add <site>`

Adds a credential entry.

Behavior:

- Prompts for the master password
- Decrypts the vault
- Prompts for username, password, and optional notes
- Rejects the command if the site already exists
- Generates a UUID v4 entry ID
- Sets `created_at` and `updated_at`
- Re-encrypts and saves the vault

### `localpass list`

Lists non-secret entry metadata.

Behavior:

- Prompts for the master password
- Decrypts the vault
- Prints site and username
- Never prints passwords

### `localpass search <query>`

Searches non-secret entry metadata.

Behavior:

- Prompts for the master password
- Decrypts the vault
- Matches the query case-insensitively against site and username
- Prints site and username only
- Never prints passwords

### `localpass stats`

Shows safe vault metadata.

Behavior:

- Prompts for the master password
- Decrypts the vault to verify access
- Prints the number of entries
- Prints the vault path chosen by the CLI
- Never prints usernames, passwords, or notes

### `localpass get <site>`

Retrieves one password.

Default behavior:

- Prompts for the master password
- Decrypts the vault
- Finds the entry by exact site name
- Copies the password to the clipboard
- Attempts to clear the clipboard after 30 seconds
- Does not print the password

Demo and test behavior:

```bash
localpass get github --show
```

`--show` explicitly prints the password to stdout. This is included for demos and tests. The default remains safer clipboard-only behavior.

### `localpass delete <site>`

Deletes one entry.

Behavior:

- Prompts for the master password
- Decrypts the vault
- Removes the exact site match
- Re-encrypts and saves the vault

### `localpass update <site>`

Updates one existing credential entry.

Behavior:

- Prompts for the master password
- Decrypts the vault
- Prompts for replacement username, password, and notes
- Updates `updated_at`
- Re-encrypts and saves the vault

### `localpass rekey`

Changes the master password for the vault.

Behavior:

- Prompts for the current master password
- Decrypts the vault with the current master password
- Prompts for a new master password and confirmation
- Re-encrypts the same entries with the new master password
- Uses fresh encryption metadata during save
- Makes the old master password unable to unlock the vault

### `localpass generate`

Generates a strong random password.

Initial options:

- `--length <N>`, default 16
- `--symbols`, include symbol characters
- `--no-upper`, exclude uppercase letters
- `--no-digits`, exclude digits
- `--save <site>`, save the generated password directly into the vault

When `--save <site>` is used, LocalPass prompts for the master password, username, and notes. It stores the generated password without printing it to stdout.

## Vault File Format

The vault file is a flat binary file:

| Offset | Length | Content |
| --- | ---: | --- |
| 0 | 4 bytes | Magic bytes: `LPAS` |
| 4 | 2 bytes | Format version, little-endian `u16` |
| 6 | 32 bytes | Argon2id salt |
| 38 | 12 bytes | AES-GCM nonce |
| 50 | 16 bytes | AES-GCM authentication tag |
| 66 | variable | AES-GCM ciphertext |

The ciphertext is an encrypted JSON array of entries.

## Data Model

Each decrypted vault entry has:

- `id`: UUID v4 string
- `site`: service name
- `username`: login username or email
- `password`: credential secret
- `notes`: optional notes
- `created_at`: UTC timestamp
- `updated_at`: UTC timestamp

The encrypted JSON payload is a flat array of these objects.

## Module Boundaries

Proposed source layout:

```text
src/
  main.rs
  cli.rs
  commands.rs
  crypto.rs
  vault_file.rs
  vault.rs
  entry.rs
  generator.rs
  clipboard.rs
  error.rs
```

Responsibilities:

- `main.rs`: starts the app and reports errors
- `cli.rs`: defines CLI arguments and subcommands
- `commands.rs`: maps CLI commands to vault operations
- `crypto.rs`: Argon2id key derivation and AES-GCM encryption/decryption
- `vault_file.rs`: binary vault header parsing and writing
- `vault.rs`: CRUD operations and JSON serialization
- `entry.rs`: credential entry data type
- `generator.rs`: password generation
- `clipboard.rs`: clipboard copy and best-effort clearing
- `error.rs`: application error types

## Error Handling

Errors should be clear but should not leak secrets.

Examples:

- Wrong master password or tampered file: `failed to unlock vault`
- Existing vault on init: `vault already exists`
- Duplicate site on add or generate-save: `entry already exists: <site>`
- Missing entry: `entry not found: <site>`
- Invalid vault header: `invalid vault file`

Internally, wrong passwords and tampering are both detected through AES-GCM authentication failure.

## Testing Strategy

Unit tests:

- Password generation length and character set behavior
- AES-GCM encrypt/decrypt round trip
- AES-GCM tamper detection
- Vault file header round trip
- Vault CRUD behavior in memory

Integration tests:

- `init -> add -> list -> get --show` using a temporary vault path
- Wrong master password fails
- Deleted entries no longer appear
- Two initialized vaults use different salts

## Deferred Features

These are useful but out of scope for the first working version:

- Master password change / rekey
- Import from other password managers
- Browser integration
- Cloud sync
- TOTP support
- TUI interface
- Fuzzy site matching

## Explanation Plan

The implementation should be explained in this order:

1. Cargo project structure
2. CLI command parsing
3. Vault data model
4. Vault file format
5. Master password to encryption key with Argon2id
6. AES-GCM encryption and authentication
7. CRUD commands
8. Password generator
9. Clipboard behavior
10. Tests and README polish
