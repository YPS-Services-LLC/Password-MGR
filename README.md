<h1 align="center">🔐 Password-MGR v3.1r — YPS Services LLC</h1>
<p align="center">
  <b>YPS Services LLC — B20250292295</b><br>
  AUS: +61 3 8907 8593 | USA: +1 (213) 528-8185<br>
  ✉ <a href="mailto:contact@yps.services">contact@yps.services</a><br>
  <a href="https://github.com/YPS-Services-LLC/Password-MGR">github.com/YPS-Services-LLC/Password-MGR</a>
</p>
<p align="center">
  <img src="assets/watermark-505953-angled.svg" width="120" height="80" alt="YPS watermark"><br>
  <img src="https://img.shields.io/badge/version-v3.1r-blue?style=for-the-badge" alt="version badge">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-green?style=for-the-badge" alt="platform badge">
  <img src="https://img.shields.io/badge/status-Stable-orange?style=for-the-badge" alt="status badge">
</p>

## Overview
**Password-MGR** is a local-first, offline password manager with device-bound encryption, automatic backups, and integrated TOTP. It tracks **recently viewed** credentials and provides a one-step **restore** from a rolling backup.

## Features
- 🔒 PBKDF2-HMAC-SHA256 + Fernet (AES-256) device-bound vault  
- 🛟 Automatic `.bak` on each save + single-command **restore**  
- 🕒 **recent** view sorted by `last_viewed` timestamp  
- 🔢 Built-in generator (charset masks: `U L D S`)  
- ⏱️ TOTP import from Google Authenticator migration URIs  
- ⌨️ Wayland clipboard + optional autotype (ydotool)  
- 🧾 Config view/reset from CLI  
- ✅ License banner with unique instance hash  

## What’s new in v3.1r
- Fixed **recent** ordering with timestamp normalization  
- Added **restore** command with validation and safe replace  
- Sticky header with instance verification and hash  
- Config reset flow and inline help reference  
- Cross-platform clipboard fallback improvements  

## Install
```bash
# Fedora 42+
sudo dnf install -y python3 python3-cryptography python3-psutil

# Ubuntu 24.04+
sudo apt install -y python3 python3-cryptography python3-psutil

# Clone
git clone https://github.com/YPS-Services-LLC/Password-MGR.git
cd Password-MGR
```

## Usage
```bash
python3 passmgr.py
```

## Commands
```text
add, get, type, gen, update, show, list, search,
delete, recent, restore, verify, about, help, config, quit
```

### Examples
```bash
get linkedin.com user
get 4 pw
get site 2fa
recent
config reset
```

### First run creates
```text
vault.dat        # encrypted data store
vault.dat.bak    # rolling backup
vault.salt       # KDF salt
device.key       # device secret (binds vault to device)
config.json      # defaults (length/charset/modes)
```

## Backup and restore
Backups are automatic on each save. To roll back:
```text
restore
```
The command validates the backup, then safely replaces `vault.dat`.

## 2FA import
Supports Google Authenticator migration:
```text
import-2fa
# paste the otpauth-migration:// URL
```
Map a TOTP secret between entries:
```text
map-2fa 2 7
```

## Config
Shown via `help` and editable in `config.json`.
```jsonc
{
  "default_length": 16,        // generator length
  "default_charset": "ULDS",   // U/L/D/S sets
  "default_get_mode": "both",  // user|pw|up|2fa|both
  "default_type_mode": "hotkey"// user|pw|up|hotkey
}
```
Reset to defaults:
```text
config reset
```

## Integration
- **Sys-Snapshots v2.0**: baseline vault attributes for drift detection  
- **Opsec Hardener v3.1**: process lockdown and clipboard hygiene  

## Troubleshooting
- Keep `vault.salt` and `device.key` with the vault when migrating  
- Do not commit `vault.dat` or `.bak` to Git  
- Wayland users: install `wl-clipboard`; for autotype install `ydotool`  

## License
Commercial License · © 2025 YPS Services LLC

<hr>
<p align="center">
  <sub>© 2025 YPS Services LLC — B20250292295 · All Rights Reserved</sub><br>
  <sub>
    <a href="https://github.com/YPS-Services-LLC/OPSEC-Hardener">⚙️ Opsec Hardener v3.1</a> ·
    <a href="https://github.com/YPS-Services-LLC/Sys-Snapshots">🧠 Sys-Snapshots v2.0</a> ·
    <a href="https://github.com/YPS-Services-LLC/Password-MGR">🔐 Password-MGR v3.1r</a>
  </sub>
</p>
