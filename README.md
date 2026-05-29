# [RECON] Attack Surface Reconnaissance Framework

A 10-phase web-based attack surface recon framework for bug bounty and penetration testing.

## Stack
- **Frontend:** React 18 · TypeScript · Vite · IBM Plex Sans / JetBrains Mono
- **Backend:** Node.js · Express · CommonJS
- **Tools:** See Phase breakdown below

## Quick Start

### 1. Install Node.js (≥18)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install nodejs
```

### 2. Install Go tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/ffuf/ffuf/v2@latest
```

### 3. Install system tools
```bash
sudo apt install -y nmap amass sublist3r chromium-browser
```

### 4. Configure paths
Edit `config.cjs` — set `RECON_HOME` env var or just let it auto-detect your home directory.

### 5. Run the backend
```bash
npm install      # installs express + cors + js-beautify
node server.cjs  # starts on :8000
```

### 6. Run the frontend (separate terminal)
```bash
# From project root (where package.json is)
npm install   # installs React + Vite
npm run dev   # starts on :5173
```

Open http://localhost:5173

## Phases

| Phase | Name | Tools | Output |
|-------|------|-------|--------|
| PH-01 | Subdomain Enumeration | Subfinder, Amass, Assetfinder, CRT.sh, Sublist3r | `subdomain/merged.txt` |
| PH-02 | DNS Resolution | dnsx | `dns/records.json` |
| PH-03 | Live Host Detection | httpx | `live/merged.txt`, `live/hosts.txt` |
| PH-04 | Port Scanning | naabu + nmap | `ports/open_ports.json` |
| PH-05 | URL Crawling | gau, katana, gospider, waybackurls | `urls/merged.txt` |
| PH-06 | Screenshots | Chromium headless | `screenshots/imgs/*.png` |
| PH-07 | Confidential File Discovery | ffuf + passive + git check | `confidential/findings.json` |
| PH-08 | Origin IP Discovery | DNS/cert/Shodan analysis | `originip/results.json` |
| PH-09 | 403 Bypass | Header/path/method tricks | `bypass403/results.json` |
| PH-10 | Nuclei CVE Scan | Nuclei templates | `nuclei/findings.json` |

## Use Cases

- **Bug Bounty:** Full automated recon pipeline per target domain
- **Penetration Testing:** Structured attack surface mapping before active testing
- **Asset Discovery:** Find forgotten subdomains, exposed services, and leaked credentials
- **Continuous Monitoring:** Re-run phases to track surface changes over time

## API Reference

All endpoints follow the pattern `POST /api/<phase>/:target` to start and `GET /api/<phase>/:target` to poll status + results.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST `{target}` | Start subdomain phase |
| `/api/subdomains/:target` | GET | List discovered subdomains |
| `/api/subdomains/:target/oos` | POST `{oos:[]}` | Apply out-of-scope filter |
| `/api/dns/:target` | POST/GET | DNS resolution |
| `/api/live/:target` | POST/GET | Live host detection |
| `/api/ports/:target` | POST/GET | Port scan |
| `/api/urls/:target` | POST/GET | URL discovery |
| `/api/screenshots/:target` | POST/GET | Screenshots |
| `/api/confidential/:target` | POST/GET | Confidential files |
| `/api/originip/:target` | POST/GET | Origin IP detection |
| `/api/bypass403/:target` | POST/GET | 403 bypass attempts |
| `/api/intelligence/:target` | POST/GET | Intelligence engine |
| `/api/nuclei/:target` | POST/GET | Nuclei CVE scan |

## Legal

Only scan targets you have explicit written permission to test.
