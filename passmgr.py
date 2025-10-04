#!/usr/bin/env python3
"""
==================================================
Passmgr v3.0.0 (Final, Fedora Wayland Edition)
Author: YPS Services LLC
==================================================
"""

import os, json, base64, getpass, time, secrets, string, sys, shutil, psutil, subprocess, threading
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

import pyotp
from urllib.parse import urlparse, parse_qs
from google.protobuf.internal import decoder

# --- Files ---
VAULT_FILE = "vault.dat"
BACKUP_FILE = "vault.dat.bak"
TEMP_FILE = "vault.dat.tmp"
DEVICE_FILE = "device.key"
SALT_FILE = "vault.salt"
CONFIG_FILE = "config.json"
LOCK_FILE = "vault.lock"
LICENCE_FILE = "licence.json"
PUBLIC_KEY_FILE = "public.pem"

sites_cache = []

# --- Licence check ---
def verify_licence():
    if not os.path.exists(LICENCE_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print("⚠ Licence missing — running as UNVERIFIED instance.")
        return False
    try:
        licence = json.load(open(LICENCE_FILE))
        pubkey = serialization.load_pem_public_key(open(PUBLIC_KEY_FILE, "rb").read())
        data = (licence["instance_id"] + licence["expiry"]).encode()
        signature = bytes.fromhex(licence["signature"])
        pubkey.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        print(f"[✔] Instance verified: {licence['instance_id']}")
        return True
    except Exception as e:
        print(f"⚠ Licence invalid — {e}")
        return False

# --- Clipboard ---
def copy_to_clipboard(text: str):
    try:
        subprocess.run(["wl-copy"], input=text.encode(), check=True)
        print("[*] Value copied securely (Wayland).")
    except Exception as e:
        print(f"[-] wl-copy failed: {e}")

def paste_from_clipboard() -> str:
    try:
        result = subprocess.run(["wl-paste"], capture_output=True, check=True)
        return result.stdout.decode().strip()
    except Exception:
        return ""

def queue_user_and_pass(user, password):
    copy_to_clipboard(user)
    print("[✔] Username copied. Paste it, then password will follow...")
    def watcher():
        last = user
        while True:
            time.sleep(0.2)
            current = paste_from_clipboard()
            if current and current != last:
                copy_to_clipboard(password)
                print("[✔] Password queued — ready for second paste.")
                break
    threading.Thread(target=watcher, daemon=True).start()

# --- Typing helpers ---
def ensure_ydotoold():
    socket_path = f"/run/user/{os.getuid()}/.ydotool_socket"
    if os.path.exists(socket_path): return
    try:
        subprocess.Popen(["/usr/bin/ydotoold", f"--socket-path={socket_path}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
    except Exception:
        pass

def type_with_ydotool(text):
    env = os.environ.copy()
    env["YDOTOOL_SOCKET"] = f"/run/user/{os.getuid()}/.ydotool_socket"
    subprocess.run(["ydotool", "type", text], check=True, env=env)

def type_user_and_pass(user, password, delay=1.0):
    ensure_ydotoold()
    print("[✔] Typing username, then password...")
    type_with_ydotool(user)
    time.sleep(delay)
    type_with_ydotool(password)

# --- Helpers ---
def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_device_secret(): return open(DEVICE_FILE, "rb").read() if os.path.exists(DEVICE_FILE) else None
def load_salt(): return open(SALT_FILE, "rb").read() if os.path.exists(SALT_FILE) else None

def derive_key(master_password: str, salt: bytes, device_secret: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt + device_secret, iterations=200_000,
                     backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_data(data: dict, key: bytes) -> bytes:
    return Fernet(key).encrypt(json.dumps(data).encode())
def decrypt_data(token: bytes, key: bytes) -> dict:
    return json.loads(Fernet(key).decrypt(token).decode())

# --- Vault load/save ---
def save_vault(vault: dict, key: bytes):
    if os.path.exists(VAULT_FILE): shutil.copy2(VAULT_FILE, BACKUP_FILE)
    with open(TEMP_FILE, "wb") as f: f.write(encrypt_data(vault, key))
    os.replace(TEMP_FILE, VAULT_FILE)

def load_vault(key: bytes):
    if not os.path.exists(VAULT_FILE): return None
    try: return decrypt_data(open(VAULT_FILE, "rb").read(), key)
    except InvalidToken:
        print("[!] Vault corrupted or wrong password. Trying backup…")
        if os.path.exists(BACKUP_FILE):
            try:
                data = decrypt_data(open(BACKUP_FILE, "rb").read(), key)
                shutil.copy2(BACKUP_FILE, VAULT_FILE)
                print("[+] Backup restored.")
                return data
            except InvalidToken:
                print("[-] Backup also invalid.")
        return None

# --- Config ---
def load_config():
    defaults = {"default_length": 16, "default_charset": "ULDS",
                "default_get_mode": "both", "default_type_mode": "hotkey"}
    if not os.path.exists(CONFIG_FILE):
        json.dump(defaults, open(CONFIG_FILE, "w"), indent=4)
        return defaults
    try: return json.load(open(CONFIG_FILE))
    except Exception:
        print("[!] Config corrupted. Regenerating defaults.")
        json.dump(defaults, open(CONFIG_FILE, "w"), indent=4)
        return defaults

# --- Password generator ---
def generate_password(length=16, charset="ULDS"):
    sets = {"U": string.ascii_uppercase, "L": string.ascii_lowercase,
            "D": string.digits, "S": string.punctuation}
    chosen = "".join(sets[c] for c in charset if c in sets)
    return "".join(secrets.choice(chosen) for _ in range(length))

# --- Lock ---
def acquire_lock():
    if os.path.exists(LOCK_FILE):
        try:
            pid = int(open(LOCK_FILE).read().strip())
            if psutil.pid_exists(pid):
                choice = input(f"Instance already running (PID {pid}). Kill it? (y/N): ").lower()
                if choice == "y":
                    psutil.Process(pid).terminate()
                    print(f"[+] Killed process {pid}.")
                else: sys.exit(1)
        except Exception: pass
        os.remove(LOCK_FILE)
    open(LOCK_FILE, "w").write(str(os.getpid()))
def release_lock():
    if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)

# --- Listing ---
def list_sites(vault):
    global sites_cache
    sites_cache = list(vault.keys())
    for i, site in enumerate(sites_cache, 1):
        entry = vault[site]
        print(f"[{i}] {site} | User: {entry['user']} | "
              f"Last Updated: {entry.get('last_updated')} | Last Viewed: {entry.get('last_viewed')}")

# --- Google Auth Migration decoding ---
def parse_parameters(raw):
    i, params = 0, {}
    while i < len(raw):
        tag, i = decoder._DecodeVarint(raw, i)
        field_num = tag >> 3
        if field_num == 1:  # secret
            size, i = decoder._DecodeVarint(raw, i)
            secret = raw[i:i+size]; i += size
            params['secret'] = base64.b32encode(secret).decode().rstrip('=')
        elif field_num == 2:  # name
            size, i = decoder._DecodeVarint(raw, i)
            params['name'] = raw[i:i+size].decode(); i += size
        elif field_num == 3:  # issuer
            size, i = decoder._DecodeVarint(raw, i)
            params['issuer'] = raw[i:i+size].decode(); i += size
        else:
            size, i = decoder._DecodeVarint(raw, i); i += size
    return params

def import_migration_uri(vault, key):
    uri = input("Paste otpauth-migration:// URI: ").strip()
    if not uri.startswith("otpauth-migration://"):
        print("[-] Invalid URI format"); return
    qs = parse_qs(urlparse(uri).query)
    raw = base64.b64decode(qs['data'][0])
    i, accounts = 0, []
    while i < len(raw):
        tag, i = decoder._DecodeVarint(raw, i)
        field_num = tag >> 3
        if field_num == 1:  # otp_parameters
            size, i = decoder._DecodeVarint(raw, i)
            block = raw[i:i+size]; i += size
            accounts.append(parse_parameters(block))
        else:
            size, i = decoder._DecodeVarint(raw, i); i += size
    print(f"[+] Found {len(accounts)} accounts in migration data.")
    for acc in accounts:
        name = acc.get("name","unknown")
        issuer = acc.get("issuer","unknown")
        secret = acc["secret"]
        site = f"{issuer}-{name}".replace(" ","_")
        if site in vault:
            print(f"[!] {site} already exists.")
            if input("Update TOTP secret? (y/N): ").lower() != "y":
                continue
        if site not in vault:
            vault[site] = {"user": name, "password": "UNKNOWN",
                           "last_updated": now(), "last_viewed": "never"}
        vault[site]["totp_secret"] = secret
        save_vault(vault, key)
        print(f"[✔] Added/Updated {site} with TOTP secret.")

# --- Main ---
def main():
    if "--help" in sys.argv:
        print("Usage: passmgr.py\nCommands: add, get, type, gen, update, show, list, search, delete, recent, quit, import-2fa, map-2fa")
        return

    acquire_lock()
    try:
        verify_licence()
        device_secret, salt = load_device_secret(), load_salt()
        if not all([os.path.exists(VAULT_FILE), device_secret, salt]):
            if input("[!] Vault missing. Create new? (y/N): ").lower() != "y":
                release_lock(); return
            for f in [VAULT_FILE, SALT_FILE, DEVICE_FILE, LOCK_FILE]:
                if os.path.exists(f): os.remove(f)
            device_secret, salt = os.urandom(32), os.urandom(16)
            open(DEVICE_FILE, "wb").write(device_secret)
            open(SALT_FILE, "wb").write(salt)
            key = derive_key(getpass.getpass("Set master password: "), salt, device_secret)
            save_vault({}, key)
            print("[+] New vault created. Restart script."); return
        key = derive_key(getpass.getpass("Enter master password: "), salt, device_secret)
        vault = load_vault(key)
        if vault is None: return
        print("Vault unlocked.")

        config = load_config()
        idle_timeout = int(input("Idle lock timeout (minutes) [5]: ") or 5)
        last_activity = time.time()

        while True:
            if time.time() - last_activity > idle_timeout * 60:
                print("Idle timeout reached. Vault locked."); break
            cmd = input("\nCommand (add, get, type, gen, update, show, list, search, delete, recent, quit, import-2fa, map-2fa): ").strip().lower()
            last_activity = time.time()

            if cmd == "add":
                site = input("Site: ").strip()
                user = input("Username: ").strip()
                pwd = getpass.getpass("Password (blank=auto): ")
                if not pwd:
                    pwd = generate_password(config["default_length"], config["default_charset"])
                    print(f"Generated password: {'*'*len(pwd)}")
                totp = input("TOTP secret (blank=none): ").strip() or None
                vault[site] = {"user": user, "password": pwd,
                               "totp_secret": totp,
                               "last_updated": now(), "last_viewed": "never"}
                save_vault(vault, key)
                print(f"[+] Entry saved for {site}")

            elif cmd == "list":
                list_sites(vault)

            elif cmd.startswith("get"):
                parts = cmd.split()
                if len(parts) < 2:
                    print("Usage: get <site|index> [user|pw|up|2fa]"); continue
                target, mode_arg = parts[1], config.get("default_get_mode", "both")
                site = None
                if target.isdigit():
                    idx = int(target) - 1
                    if 0 <= idx < len(sites_cache): site = sites_cache[idx]
                elif target in vault: site = target
                if not site: print("[-] No entry found."); continue
                entry = vault[site]; entry["last_viewed"] = now(); save_vault(vault, key)
                if len(parts) > 2: mode_arg = parts[2].lower()
                if mode_arg == "user": copy_to_clipboard(entry["user"])
                elif mode_arg in ["pw","pass"]: copy_to_clipboard(entry["password"])
                elif mode_arg in ["up","userpass"]: queue_user_and_pass(entry["user"], entry["password"])
                elif mode_arg == "2fa":
                    if entry.get("totp_secret"):
                        totp = pyotp.TOTP(entry["totp_secret"])
                        code = totp.now()
                        valid_for = 30 - (int(time.time()) % 30)
                        print(f"[2FA] {code} (valid {valid_for}s)")
                    else: print("[-] No TOTP secret stored.")
                else: copy_to_clipboard(entry["user"])

            elif cmd.startswith("map-2fa"):
                parts = cmd.split()
                if len(parts) != 3:
                    print("Usage: map-2fa <from_index> <to_index>"); continue
                try:
                    from_idx, to_idx = int(parts[1]) - 1, int(parts[2]) - 1
                    if not (0 <= from_idx < len(sites_cache) and 0 <= to_idx < len(sites_cache)):
                        print("[-] Invalid index."); continue
                    from_site, to_site = sites_cache[from_idx], sites_cache[to_idx]
                    from_entry, to_entry = vault[from_site], vault[to_site]
                    if "totp_secret" not in from_entry or not from_entry["totp_secret"]:
                        print(f"[-] {from_site} has no 2FA secret to map."); continue
                    vault[to_site]["totp_secret"] = from_entry["totp_secret"]
                    save_vault(vault, key)
                    print(f"[✔] Mapped 2FA from {from_site} → {to_site}")
                except Exception as e:
                    print(f"[-] Error: {e}")

            elif cmd == "update":
                site = input("Site to update: ").strip()
                if site not in vault: print("[-] No entry found."); continue
                if input("Change username? (y/n): ").lower()=="y":
                    vault[site]["user"] = input("New username: ").strip()
                if input("Change password? (y/n): ").lower()=="y":
                    pwd = getpass.getpass("New password (blank=auto): ")
                    if not pwd:
                        pwd = generate_password(config["default_length"], config["default_charset"])
                        print(f"Generated password: {'*'*len(pwd)}")
                    vault[site]["password"] = pwd
                vault[site]["last_updated"] = now(); save_vault(vault, key)
                print(f"[+] Entry updated for {site}")

            elif cmd == "delete":
                site = input("Site to delete: ").strip()
                if site in vault and input(f"Delete {site}? (y/n): ").lower()=="y":
                    del vault[site]; save_vault(vault, key); print("[+] Entry deleted.")
                else: print("[-] No entry found or cancelled.")

            elif cmd == "gen":
                pw = generate_password(config["default_length"], config["default_charset"])
                print(f"Generated password: {pw}")

            elif cmd == "search":
                keyword = input("Keyword: ").lower()
                for site, entry in vault.items():
                    if keyword in site.lower() or keyword in entry['user'].lower():
                        print(f"{site} | User: {entry['user']}")

            elif cmd == "recent":
                for site, entry in sorted(vault.items(),
                    key=lambda kv: kv[1].get("last_viewed","0"), reverse=True)[:5]:
                    print(f"{site} | User: {entry['user']} | Last Viewed: {entry['last_viewed']}")

            elif cmd == "show":
                site = input("Site to show: ").strip()
                if site in vault:
                    entry = vault[site]
                    print(f"{site} | User: {entry['user']} | Password: {entry['password']}")
                else: print("[-] No entry found.")

            elif cmd == "import-2fa":
                import_migration_uri(vault, key)

            elif cmd == "quit":
                break

            else:
                print("Unknown command.")
    finally:
        release_lock()

if __name__ == "__main__":
    main()

