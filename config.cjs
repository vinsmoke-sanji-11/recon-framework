// config.cjs — central path configuration
// Edit RECON_USER to match your Linux username
'use strict';

const os   = require('os');
const path = require('path');

const HOME = process.env.RECON_HOME || os.homedir();

module.exports = {
  HOME,
  BINS: {
    subfinder:     path.join(HOME, 'go/bin/subfinder'),
    amass:         '/usr/bin/amass',
    assetfinder:   path.join(HOME, 'go/bin/assetfinder'),
    shuffledns:    path.join(HOME, 'go/bin/shuffledns'),
    sublist3r:     '/usr/bin/sublist3r',
    python3:       '/usr/bin/python3',
    cloud_enum:    path.join(HOME, 'tools/cloud_enum/cloud_enum.py'),
    subdomainizer: path.join(HOME, 'tools/SubDomainizer/SubDomainizer.py'),
    dnsx:          path.join(HOME, 'go/bin/dnsx'),
    httpx:         path.join(HOME, 'go/bin/httpx'),
    naabu:         path.join(HOME, 'go/bin/naabu'),
    nmap:          '/usr/bin/nmap',
    ffuf:          path.join(HOME, 'go/bin/ffuf'),
    gau:           path.join(HOME, 'go/bin/gau'),
    gospider:      '/usr/bin/gospider',
    katana:        path.join(HOME, 'go/bin/katana'),
    waybackurls:   path.join(HOME, 'go/bin/waybackurls'),
    chromium:      '/usr/bin/chromium',
    nuclei:        path.join(HOME, 'go/bin/nuclei'),
  },
  RESOLVERS_FILE: path.join(HOME, 'tools/wordlists/resolvers.txt'),
};
