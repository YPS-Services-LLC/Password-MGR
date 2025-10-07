<h1 align="center">🔐 Password-MGR v2.1 — YPS Services LLC</h1>
<p align="center">
  <b>YPS Services LLC — B20250292295</b><br>
  AUS: +61 3 8907 8593 | USA: +1 (213) 528-8185<br>
  ✉ <a href="mailto:contact@yps.services">contact@yps.services</a><br>
  <a href="https://github.com/YPS-Services-LLC/Password-MGR">github.com/YPS-Services-LLC/Password-MGR</a>
</p>
<p align="center">
  <img src="assets/watermark-505953-angled.svg" width="120" height="80"><br>
  <img src="https://img.shields.io/badge/version-v2.1-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/status-Stable-orange?style=for-the-badge">
</p>

## Overview
**Password‑MGR** is an offline, encrypted password vault for Linux systems. It stores credentials locally with **AES‑256** encryption, **Argon2** key derivation, optional **TOTP/2FA** helpers, and a clipboard watchdog. No cloud services, no telemetry.

## Features
- 🔐 AES‑256 vault with Argon2 KDF (memory‑hard)
- 🔑 TOTP helper (generate one‑time codes for saved entries)
- 🧹 Clipboard auto‑clear with configurable timeout
- 🔎 Fast search by name, tag, or domain
- 🔁 Import/Export JSON (migrate from v1.x)
- 🧰 Designed for terminal workflows; minimal dependencies

## What’s new in v2.1
- Argon2id KDF (replaces PBKDF2) for stronger resistance to GPU cracking
- TOTP helper module and `pmgr otp` command
- Unified CLI (`pmgr <command> [options]`), better errors & help texts
- Safer clipboard handling with timeout + process check

## Install
```bash
# Fedora 42+
sudo dnf install -y python3-cryptography xclip
# Ubuntu 24.04+
sudo apt install -y python3-cryptography xclip

git clone https://github.com/YPS-Services-LLC/Password-MGR.git
cd Password-MGR
```

## Quick start
```bash
[yps@localhost]$ pmgr init --vault ~/.vaults/main.yps
[yps@localhost]$ pmgr add "GitHub" --user admin@yps.services --tags dev
[yps@localhost]$ pmgr list --tags dev
[yps@localhost]$ pmgr show "GitHub" --fields user,pass --copy pass --timeout 15
[yps@localhost]$ pmgr export --vault ~/.vaults/main.yps --out ~/exports/vault.json
```

### Example output
```text
Vault: ~/.vaults/main.yps
Entries (1)
[dev] GitHub  → user: admin@yps.services  (password copied for 15s)
Export complete: /home/yps/exports/vault.json (1 entry)
```

## CLI reference (selected)
```bash
pmgr init --vault <path>                # create vault
pmgr add "<name>" --user <u> [--tags t] # add entry
pmgr list [--tags t] [--search q]       # list entries
pmgr show "<name>" [--fields f1,f2]     # print selected fields
pmgr otp "<name>"                       # generate TOTP for entry
pmgr export --out <file.json>           # export JSON
pmgr import --in <file.json>            # import JSON
```

## Integration
- **Sys‑Snapshots**: include vault file path in baseline to detect tampering or unexpected modification times.
- **Opsec Hardener**: runs environment checks (xclip presence, clipboard timeout) and suggests hardening tips for vault usage.

## Security notes
- Vault encryption is only as strong as the master passphrase; use long passphrases.
- Clipboard content is a leak vector; prefer `--copy pass --timeout N` and avoid terminals that keep scrollback.
- Keep regular encrypted exports and store them offline.

## Troubleshooting
- *xclip not found*: install `xclip` or use `--no-clipboard`.
- *Unsigned commits*: ensure SSH commit signing is enabled and configured (see project docs).
- *Vault corrupted*: recover from latest JSON export; consider file system snapshot tools.

## License
MIT License · © 2025 YPS Services LLC

<hr>
<p align="center">
  <sub>© 2025 YPS Services LLC — B20250292295 · All Rights Reserved</sub><br>
  <sub>
    <a href="https://github.com/YPS-Services-LLC/OPSEC-Hardener">⚙️ Opsec Hardener v3.1</a> ·
    <a href="https://github.com/YPS-Services-LLC/Sys-Snapshots">🧠 Sys-Snapshots v2.0</a> ·
    <a href="https://github.com/YPS-Services-LLC/Password-MGR">🔐 Password-MGR v2.1</a>
  </sub>
</p>
