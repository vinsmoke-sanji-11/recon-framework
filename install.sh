#!/usr/bin/env bash
# install.sh — Install all Go tools and system dependencies
set -e

echo "╔══════════════════════════════════════════╗"
echo "║   [RECON] Framework — Install Script     ║"
echo "╚══════════════════════════════════════════╝"

# Detect username
USERNAME=$(whoami)
HOME_DIR=$HOME

echo "[1/4] Installing system packages..."
sudo apt update -qq
sudo apt install -y nmap amass sublist3r chromium-browser curl wget git python3 python3-pip

echo "[2/4] Installing Go tools..."
# Check Go is installed
if ! command -v go &>/dev/null; then
  echo "⚠  Go not found. Install Go from https://go.dev/dl/ then re-run this script."
  exit 1
fi

GO_BINS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
)

for pkg in "${GO_BINS[@]}"; do
  echo "  → go install $pkg"
  go install "$pkg" 2>/dev/null || echo "    ⚠ failed (may already be installed)"
done

echo "[3/4] Installing optional Python tools..."
mkdir -p "$HOME_DIR/tools"
# cloud_enum
if [ ! -d "$HOME_DIR/tools/cloud_enum" ]; then
  git clone https://github.com/initstring/cloud_enum.git "$HOME_DIR/tools/cloud_enum" 2>/dev/null || true
fi
# SubDomainizer
if [ ! -d "$HOME_DIR/tools/SubDomainizer" ]; then
  git clone https://github.com/nsonaniya2010/SubDomainizer.git "$HOME_DIR/tools/SubDomainizer" 2>/dev/null || true
fi
# Resolvers wordlist
mkdir -p "$HOME_DIR/tools/wordlists"
if [ ! -f "$HOME_DIR/tools/wordlists/resolvers.txt" ]; then
  echo "  → Downloading resolvers.txt..."
  curl -sL "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt" \
    -o "$HOME_DIR/tools/wordlists/resolvers.txt" 2>/dev/null || echo "    ⚠ Could not download resolvers.txt"
fi

echo "[4/4] Installing Node.js dependencies..."
npm install                    # frontend
npm install --prefix . express cors js-beautify  # backend (installs to node_modules in root)

echo ""
echo "✓ Installation complete!"
echo ""
echo "Start backend:  node server.cjs"
echo "Start frontend: npm run dev"
echo "Open:           http://localhost:5173"
