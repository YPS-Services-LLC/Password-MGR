<h1 align="center">🔐 Password MGR v2.1 — YPS Services LLC</h1>
<p align="center">
  <b>Cross-platform local password manager built for security-first operations</b><br>
  <i>Offline vault • 2FA verification • Clipboard timeout • Encrypted exports</i>
</p>

<p align="center">
  <img src="https://github.com/YPS-Services-LLC/.assets/raw/main/yps-banner-dark.svg" width="420" alt="YPS Services Banner">
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

### 🏷️ License & Attribution
\`\`\`
© 2025 YPS Services LLC — B20250292295
California Registered Entity
https://yps.services    ✉ contact@yps.services
AUS +61 3 8907 8593  |  USA +1 (213) 528-8185
\`\`\`

---

<p align="center">
  <i>YPS Services LLC — Building Secure Automation Infrastructure</i><br>
  <sub>https://github.com/YPS-Services-LLC</sub>
</p>
