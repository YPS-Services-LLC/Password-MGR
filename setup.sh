#!/bin/bash
set -e
echo "[*] Installing dependencies..."
sudo dnf install -y python3-pip wl-clipboard ydotool
pip3 install -r requirements.txt
echo "[✔] Setup complete."
