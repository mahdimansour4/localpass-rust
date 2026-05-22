# Security Policy

LocalPass is a portfolio project for an offline password manager. Security is a core design goal, but this project has not received an independent security audit.

## Supported Versions

The `main` branch is the only supported version.

## Threat Model

LocalPass is designed to protect a stolen vault file. The vault contents are encrypted locally, and the master password is used only at unlock time to derive an encryption key.

LocalPass does not protect against:

- A compromised operating system
- Malware or keyloggers
- A malicious terminal, shell, or clipboard manager
- Physical access while the vault is unlocked
- Memory inspection by a privileged attacker
- Weak or reused master passwords

## Cryptography

- Argon2id is used to derive a key from the master password.
- AES-256-GCM is used for authenticated encryption.
- Each save generates fresh encryption metadata.
- Wrong passwords and tampered vault files fail during authentication.

## Reporting Security Issues

Do not open a public GitHub issue for sensitive security reports.

Instead, contact the maintainer directly through the contact information listed on the GitHub profile:

https://github.com/mahdimansour4

Please include:

- A clear description of the issue
- Steps to reproduce
- Any affected command or file
- Whether the issue exposes secrets, corrupts vault data, or bypasses authentication

## Safe Usage Notes

- Use a long, unique master password.
- Do not store real production credentials in demo vaults.
- Avoid `get --show` except for demos and tests.
- Treat terminal history, screenshots, and chat logs as public if they include shown passwords.
