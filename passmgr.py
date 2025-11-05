#!/usr/bin/env python3
"""
==================================================
Password Manager v3.1 (Cross-Platform)
Author: YPS Services LLC
==================================================
"""

import os, json, base64, getpass, time, secrets, string, sys, shutil, psutil, subprocess, threading, platform
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
VAULT_FILE="vault.dat"; BACKUP_FILE="vault.dat.bak"; TEMP_FILE="vault.dat.tmp"
DEVICE_FILE="device.key"; SALT_FILE="vault.salt"; CONFIG_FILE="config.json"
LOCK_FILE="vault.lock"; LICENCE_FILE="licence.json"; PUBLIC_KEY_FILE="public.pem"
sites_cache=[]

# --- Colours ---
class C:
    RESET="\033[0m"; RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"

# --- Header ---
def banner():
    print(f"{C.BOLD}YPS SERVICES LLC  |  Support : support@yps.services  |  Site : ypsservicesllc.com{C.RESET}")

# --- Licence ---
def verify_licence():
    if not os.path.exists(LICENCE_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print(f"{C.YELLOW}⚠ Unverified instance (licence missing).{C.RESET}")
        return "UNVERIFIED"
    try:
        lic=json.load(open(LICENCE_FILE))
        pub=serialization.load_pem_public_key(open(PUBLIC_KEY_FILE,"rb").read())
        data=(lic["instance_id"]+lic["expiry"]).encode()
        pub.verify(bytes.fromhex(lic["signature"]),data,padding.PKCS1v15(),hashes.SHA256())
        ident=f"{lic['instance_id']}@{platform.node()}"
        print(f"{C.GREEN}[✔]{C.RESET} Verified instance ({ident})")
        return ident
    except Exception as e:
        print(f"{C.RED}Licence invalid — {e}{C.RESET}")
        return "UNVERIFIED"

# --- Clipboard helpers (auto-detect) ---
def copy_to_clipboard(txt):
    try:
        if platform.system()=="Windows":
            subprocess.run("clip",input=txt.encode(),check=True)
        else:
            subprocess.run(["wl-copy"],input=txt.encode(),check=True)
        print(f"{C.CYAN}[*]{C.RESET} Copied securely.")
    except Exception as e:
        print(f"{C.RED}Clipboard failed {e}{C.RESET}")

def paste_from_clipboard():
    try:
        if platform.system()=="Windows":
            return subprocess.run("powershell Get-Clipboard",capture_output=True).stdout.decode().strip()
        return subprocess.run(["wl-paste"],capture_output=True).stdout.decode().strip()
    except Exception: return ""

def queue_user_and_pass(u,p):
    copy_to_clipboard(u)
    print(f"{C.GREEN}[✔]{C.RESET} Username copied; password queued after paste.")
    def watch():
        last=u
        while True:
            time.sleep(0.2)
            cur=paste_from_clipboard()
            if cur and cur!=last:
                copy_to_clipboard(p); break
    threading.Thread(target=watch,daemon=True).start()

# --- Helpers ---
def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def load_device_secret(): return open(DEVICE_FILE,"rb").read() if os.path.exists(DEVICE_FILE) else None
def load_salt(): return open(SALT_FILE,"rb").read() if os.path.exists(SALT_FILE) else None

def derive_key(pw,salt,dev):
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt+dev,iterations=200000,backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt_data(d,k): return Fernet(k).encrypt(json.dumps(d).encode())
def decrypt_data(t,k): return json.loads(Fernet(k).decrypt(t).decode())

# --- Vault I/O ---
def save_vault(v,k):
    if os.path.exists(VAULT_FILE): shutil.copy2(VAULT_FILE,BACKUP_FILE)
    with open(TEMP_FILE,"wb") as f: f.write(encrypt_data(v,k))
    os.replace(TEMP_FILE,VAULT_FILE)

def load_vault(k):
    if not os.path.exists(VAULT_FILE): return {}
    try: return decrypt_data(open(VAULT_FILE,"rb").read(),k)
    except InvalidToken:
        print(f"{C.YELLOW}[!] Primary vault failed; trying backup…{C.RESET}")
        if os.path.exists(BACKUP_FILE):
            try:
                data=decrypt_data(open(BACKUP_FILE,"rb").read(),k)
                shutil.copy2(BACKUP_FILE,VAULT_FILE)
                print(f"{C.GREEN}[+] Backup restored.{C.RESET}")
                return data
            except InvalidToken: print(f"{C.RED}Backup invalid.{C.RESET}")
        return {}

# --- Restore manual ---
def restore_vault():
    if not os.path.exists(BACKUP_FILE):
        print("[-] No backup found."); return
    shutil.copy2(BACKUP_FILE,VAULT_FILE)
    print(f"{C.GREEN}[+] Vault restored from backup.{C.RESET}")

# --- Config ---
def load_config():
    defaults={"default_length":16,"default_charset":"ULDS","default_get_mode":"both","default_type_mode":"hotkey"}
    if not os.path.exists(CONFIG_FILE):
        json.dump(defaults,open(CONFIG_FILE,"w"),indent=4); return defaults
    try: return json.load(open(CONFIG_FILE))
    except Exception:
        print("[!] Config corrupt → reset.")
        json.dump(defaults,open(CONFIG_FILE,"w"),indent=4); return defaults

def show_config(cfg):
    print("Current configuration:")
    for k,v in cfg.items(): print(f"  {k}: {v}")

def reset_config():
    if input("Reset config to defaults? (y/N): ").lower()!="y": return
    os.remove(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else None
    load_config(); print("[+] Config reset.")

# --- Password gen ---
def generate_password(length=16,charset="ULDS"):
    s={"U":string.ascii_uppercase,"L":string.ascii_lowercase,"D":string.digits,"S":string.punctuation}
    chars="".join(s[c] for c in charset if c in s)
    return "".join(secrets.choice(chars) for _ in range(length))

# --- Lock ---
def acquire_lock():
    if os.path.exists(LOCK_FILE):
        try:
            pid=int(open(LOCK_FILE).read().strip())
            if psutil.pid_exists(pid):
                if input(f"Instance running (PID {pid}). Kill? (y/N): ").lower()=="y":
                    psutil.Process(pid).terminate(); print(f"Killed {pid}")
                else: sys.exit(1)
        except Exception: pass
        os.remove(LOCK_FILE)
    open(LOCK_FILE,"w").write(str(os.getpid()))

def release_lock():
    if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)

# --- Listing ---
def list_sites(vault):
    global sites_cache
    sites_cache=list(vault.keys())
    for i,s in enumerate(sites_cache,1):
        e=vault[s]
        print(f"[{i}] {s} | User: {e['user']} | Updated: {e.get('last_updated')} | Viewed: {e.get('last_viewed')}")

# --- 2FA import ---
def parse_parameters(raw):
    i=0; params={}
    while i<len(raw):
        tag,i=decoder._DecodeVarint(raw,i)
        field=tag>>3
        if field==1:
            size,i=decoder._DecodeVarint(raw,i); sec=raw[i:i+size]; i+=size
            params["secret"]=base64.b32encode(sec).decode().rstrip("=")
        elif field==2:
            size,i=decoder._DecodeVarint(raw,i); params["name"]=raw[i:i+size].decode(); i+=size
        elif field==3:
            size,i=decoder._DecodeVarint(raw,i); params["issuer"]=raw[i:i+size].decode(); i+=size
        else:
            size,i=decoder._DecodeVarint(raw,i); i+=size
    return params

def import_migration_uri(vault,key):
    uri=input("Paste otpauth-migration:// URI: ").strip()
    if not uri.startswith("otpauth-migration://"): print("[-] Invalid URI"); return
    raw=base64.b64decode(parse_qs(urlparse(uri).query)["data"][0])
    i=0; accs=[]
    while i<len(raw):
        tag,i=decoder._DecodeVarint(raw,i)
        if tag>>3==1:
            size,i=decoder._DecodeVarint(raw,i); blk=raw[i:i+size]; i+=size
            accs.append(parse_parameters(blk))
        else:
            size,i=decoder._DecodeVarint(raw,i); i+=size
    print(f"[+] Imported {len(accs)} accounts.")
    for a in accs:
        n,i2,s=a.get("name","unknown"),a.get("issuer","unknown"),a["secret"]
        site=f"{i2}-{n}".replace(" ","_")
        vault.setdefault(site,{"user":n,"password":"UNKNOWN","last_updated":now(),"last_viewed":"never"})
        vault[site]["totp_secret"]=s; save_vault(vault,key)
        print(f"  • {site} added")

# --- HELP ---
def show_help():
    print("""
Available commands:
  add              Add new entry
  get <id|name>    Copy user/password/2FA
  type <id|name>   Auto-type credentials
  update           Modify existing entry
  delete           Delete an entry
  list             List all entries
  search           Find entries by keyword
  recent           Show 5 most recently viewed
  restore          Restore vault from backup (.bak)
  config           View or reset configuration
  import-2fa       Import Authenticator migration URI
  map-2fa a b      Copy 2FA secret from entry a → b
  help             Show this help
  quit             Exit
""")

# --- RECENT ---
def show_recent(vault):
    valid=[(s,e) for s,e in vault.items() if e.get("last_viewed") not in [None,"never"]]
    if not valid: print("[-] No entries viewed yet."); return
    for s,e in sorted(valid,key=lambda kv:kv[1]["last_viewed"],reverse=True)[:5]:
        print(f"{s} | User: {e['user']} | Viewed: {e['last_viewed']}")

# --- Main loop ---
def main():
    banner(); acquire_lock()
    try:
        instance=verify_licence()
        dev,salt=load_device_secret(),load_salt()
        if not all([os.path.exists(VAULT_FILE),dev,salt]):
            if input("Vault missing. Create new? (y/N): ").lower()!="y": release_lock(); return
            for f in [VAULT_FILE,SALT_FILE,DEVICE_FILE,LOCK_FILE]:
                if os.path.exists(f): os.remove(f)
            dev,salt=os.urandom(32),os.urandom(16)
            open(DEVICE_FILE,"wb").write(dev); open(SALT_FILE,"wb").write(salt)
            key=derive_key(getpass.getpass("Set master password: "),salt,dev)
            save_vault({},key); print("[+] New vault created."); return

        key=derive_key(getpass.getpass("Enter master password: "),salt,dev)
        vault=load_vault(key)
        print(f"Vault unlocked ({instance}).")

        cfg=load_config(); idle=int(input("Idle lock (minutes) [5]: ") or 5); last=time.time()

        while True:
            if time.time()-last>idle*60: print("Idle timeout. Locked."); break
            cmd=input("\nCommand (help=list): ").strip().lower(); last=time.time()

            if cmd=="add":
                site=input("Site: "); user=input("User: "); pw=getpass.getpass("Pass (blank=auto): ")
                if not pw: pw=generate_password(cfg["default_length"],cfg["default_charset"]); print("Generated password.")
                totp=input("TOTP secret (blank=none): ") or None
                vault[site]={"user":user,"password":pw,"totp_secret":totp,"last_updated":now(),"last_viewed":"never"}
                save_vault(vault,key); print(f"[+] Added {site}")

            elif cmd=="list": list_sites(vault)
            elif cmd=="show": show_help()
            elif cmd=="help": show_help()
            elif cmd=="recent": show_recent(vault)
            elif cmd=="restore": restore_vault()
            elif cmd=="config":
                show_config(cfg)
                if input("Reset config? (y/N): ").lower()=="y": reset_config()
            elif cmd=="import-2fa": import_migration_uri(vault,key)
            elif cmd=="quit": break
            else: handle_get_type_update_delete(cmd,vault,key,cfg)
    finally:
        release_lock()


# --- Command handlers ---
def handle_get_type_update_delete(cmd,vault,key,cfg):
    global sites_cache

    # GET
    if cmd.startswith("get"):
        p=cmd.split()
        if len(p)<2:
            print("Usage: get <id|name> [user|pw|up|2fa]"); return
        tgt,mode=p[1],cfg.get("default_get_mode","both")
        site=None
        if tgt.isdigit():
            i=int(tgt)-1
            if 0<=i<len(sites_cache): site=sites_cache[i]
        elif tgt in vault: site=tgt
        if not site: print("[-] No entry found."); return
        e=vault[site]; e["last_viewed"]=now(); save_vault(vault,key)
        if len(p)>2: mode=p[2].lower()

        if mode=="user": copy_to_clipboard(e["user"])
        elif mode in ["pw","pass"]: copy_to_clipboard(e["password"])
        elif mode in ["up","userpass"]: queue_user_and_pass(e["user"],e["password"])
        elif mode=="2fa":
            if e.get("totp_secret"):
                t=pyotp.TOTP(e["totp_secret"]); c=t.now(); v=30-(int(time.time())%30)
                print(f"[2FA] {c} (valid {v}s)")
            else: print("[-] No TOTP secret.")
        else: copy_to_clipboard(e["user"])
        return

    # TYPE
    if cmd.startswith("type"):
        p=cmd.split()
        if len(p)<2:
            print("Usage: type <id|name> [user|pw|up]"); return
        tgt,mode=p[1],cfg.get("default_type_mode","hotkey")
        site=None
        if tgt.isdigit():
            i=int(tgt)-1
            if 0<=i<len(sites_cache): site=sites_cache[i]
        elif tgt in vault: site=tgt
        if not site: print("[-] No entry found."); return
        e=vault[site]; e["last_viewed"]=now(); save_vault(vault,key)
        if len(p)>2: mode=p[2].lower()

        try:
            ensure_ydotoold()
            if mode=="user": type_with_ydotool(e["user"])
            elif mode in ["pw","pass"]: type_with_ydotool(e["password"])
            elif mode in ["up","userpass"]: type_user_and_pass(e["user"],e["password"])
            else: type_with_ydotool(e["user"])
        except Exception as ex: print(f"[!] Autotype failed: {ex}")
        return

    # UPDATE
    if cmd=="update":
        s=input("Site: ")
        if s not in vault: print("[-] No entry."); return
        e=vault[s]
        if input("Change username? (y/n): ").lower()=="y": e["user"]=input("New username: ")
        if input("Change password? (y/n): ").lower()=="y":
            pw=getpass.getpass("New password (blank=auto): ")
            if not pw:
                pw=generate_password(cfg["default_length"],cfg["default_charset"]); print("Generated.")
            e["password"]=pw
        if input("Change 2FA? (y/n): ").lower()=="y":
            t=input("New TOTP (blank=remove): "); e["totp_secret"]=t if t else None
        e["last_updated"]=now(); save_vault(vault,key)
        print(f"[+] Updated {s}")
        return

    # DELETE
    if cmd=="delete":
        s=input("Site to delete: ")
        if s in vault and input(f"Confirm delete {s}? (y/n): ").lower()=="y":
            del vault[s]; save_vault(vault,key); print("[+] Deleted.")
        else: print("[-] Cancelled.")
        return

    # MAP 2FA
    if cmd.startswith("map-2fa"):
        p=cmd.split()
        if len(p)!=3: print("Usage: map-2fa <from_index> <to_index>"); return
        try:
            fi,ti=int(p[1])-1,int(p[2])-1
            if not(0<=fi<len(sites_cache) and 0<=ti<len(sites_cache)): print("[-] Invalid index."); return
            fs,ts=sites_cache[fi],sites_cache[ti]; fe,te=vault[fs],vault[ts]
            if not fe.get("totp_secret"): print(f"[-] {fs} has no 2FA secret."); return
            te["totp_secret"]=fe["totp_secret"]; save_vault(vault,key)
            print(f"[✔] Mapped 2FA {fs} → {ts}")
        except Exception as e: print(f"[-] Error: {e}")
        return

    # Unknown
    print("Unknown command. Type 'help'.")

# --- Entry point ---
if __name__=="__main__":
    main()

