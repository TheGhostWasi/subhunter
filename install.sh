#!/usr/bin/env bash
#
# SubHunter v2.0 installer — for Kali Linux / Debian-based systems
# Usage:
#   git clone https://github.com/TheGhostWasi/subhunter.git && cd subhunter && bash install.sh
# Or one-liner (after repo is public):
#   curl -sSL https://raw.githubusercontent.com/TheGhostWasi/subhunter/main/install.sh | bash
#
set -e

echo "[*] Starting SubHunter installer..."

if ! command -v python3 &>/dev/null; then
    echo "[!] python3 not found. Install it first: sudo apt install python3 python3-pip"
    exit 1
fi

if ! command -v pip3 &>/dev/null; then
    echo "[*] Installing pip3..."
    sudo apt update && sudo apt install -y python3-pip
fi

echo "[*] Installing SubHunter and its dependencies..."
pip3 install --break-system-packages --upgrade . 2>/dev/null || pip3 install --user --upgrade .

echo ""
echo "[+] Installation complete! Try it out:"
echo "      subhunter -d example.com"
echo ""
echo "    Optional: enable YAML config file support (~/.config/subhunter/config.yaml):"
echo "      pip3 install --break-system-packages PyYAML"
echo ""
echo "    If 'subhunter: command not found' appears, add this to ~/.bashrc:"
echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
