<h1 align="center">🔐 Password MGR v2.1 — YPS Services LLC</h1>
<p align="center">
  <b>YPS Services LLC — B20250292295</b><br>
  AUS: +61 3 8907 8593 | USA: +1 (213) 528-8185<br>
  ✉ <a href="mailto:contact@yps.services">contact@yps.services</a><br>
  <a href="https://github.com/YPS-Services-LLC/Sys-Snapshots">github.com/YPS-Services-LLC/Sys-Snapshots</a>
</p>
<p align="center">
  <img src="assets/watermark-505953-angled.svg" width="120" height="80"><br>
  <img src="https://img.shields.io/badge/version-v2.1-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/platform-Fedora%20%7C%20Ubuntu-green?style=for-the-badge" alt="platform badge">
  <img src="https://img.shields.io/badge/status-Stable-orange?style=for-the-badge">
</p>

---

### 🧩 Overview
**Password MGR v2.1** is a lightweight, offline-first password vault developed by **YPS Services LLC**.  
Designed for Fedora 42 / Ubuntu 24+ systems, it integrates with the YPS ecosystem (Sys-Snapshots, Opsec Hardener) to ensure airtight credential storage and traceable audit capability.

Key improvements over v2.0:
- Enhanced encryption (AES-256-GCM with PBKDF2-HMAC-SHA512)
- CLI + TUI interface options
- Auto-expire clipboard handler
- Configurable 2FA secret store (TOTP / YubiKey)
- Secure JSON export/import (checksum verified)

---

### ⚙️ Usage

#### Initial Setup
\`\`\`bash
git clone https://github.com/YPS-Services-LLC/Password-MGR.git
cd Password-MGR
chmod +x passwordmgr.sh
./passwordmgr.sh --init
\`\`\`

#### Store New Credential
\`\`\`bash
./passwordmgr.sh --add "yps-admin@example.com"
\`\`\`

#### Retrieve Credential
\`\`\`bash
./passwordmgr.sh --get "yps-admin@example.com"
\`\`\`

#### Generate Random Password
\`\`\`bash
./passwordmgr.sh --gen 24 --symbols
\`\`\`

#### Enable 2FA TOTP
\`\`\`bash
./passwordmgr.sh --2fa enable
\`\`\`

---

### 🔒 Security Notes
- **Vault Location:** \`~/.local/share/yps/passwordmgr.db\`
- **Encryption:** AES-256-GCM + PBKDF2 (HMAC-SHA512, 310 000 iterations)
- **Clipboard timeout:** 10 seconds (default)
- **Integrity Check:** SHA-256 hash baseline via Sys-Snapshots integration

---

### 📦 Structure
\`\`\`
Password-MGR/
├── passwordmgr.sh
├── config/
│   └── passwordmgr.conf
├── data/
│   └── passwordmgr.db
├── versions/
│   ├── v1.0/
│   ├── v2.0/
│   └── v2.1/   ← stable (default)
└── CHANGELOG.md
\`\`\`

---

### 🧾 Changelog (Excerpt)
**v2.1 — 2025-10-08**
- UI refactor for consistency with YPS themes  
- Added auto-clipboard expiry system  
- Improved vault checksum validation  
- Added 2FA support for CLI login  
- Hardened key derivation and salt rotation  

---

### 🧰 Integration
- **Sys-Snapshots** → tracks vault integrity and configuration changes  
- **Opsec Hardener** → verifies process safety and system entropy  
- **YPS DocSuite** → automatically updates documentation across repos  

---

### 🧑‍💻 Developer Notes
- Tested on Fedora 42 and Ubuntu 24.04  
- Compatible with GNOME Secrets and Bitwarden JSON exports  
- Future build (2.2) will include Docker container and systemd unit integration

---

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

