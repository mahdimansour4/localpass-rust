# Changelog

All notable changes to LocalPass will be documented in this file.

## 0.1.0 - 2026-05-22

### Added

- Offline encrypted vault stored as a single local file.
- Argon2id master password key derivation.
- AES-256-GCM authenticated encryption.
- Binary vault file format with magic bytes, version, salt, nonce, tag, and ciphertext.
- Credential commands: `init`, `add`, `list`, `search`, `stats`, `get`, `update`, `delete`, and `rekey`.
- Strong password generation with optional symbol support.
- `generate --save <site>` for creating and storing generated credentials.
- Duplicate-site prevention.
- Master password validation.
- Integration tests for encrypted vault workflows.
- GitHub Actions CI for audit, dependency policy, formatting, Clippy, and tests.
