#!/usr/bin/env bash
# push-to-git.sh — Initialize and push to a new GitHub repo
set -e

if [ -z "$1" ]; then
  echo "Usage: ./push-to-git.sh https://github.com/YOUR_USERNAME/recon-framework.git"
  exit 1
fi

REMOTE_URL="$1"

echo "Initializing git repo..."
git init
git add .
git commit -m "feat: initial [RECON] attack surface framework

- 10-phase automated recon pipeline
- React + TypeScript frontend
- Express backend with per-phase routes
- Subdomain, DNS, Live, Ports, URLs, Screenshots,
  Confidential, OriginIP, 403Bypass, Nuclei phases"

git branch -M main
git remote add origin "$REMOTE_URL"
echo "Pushing to $REMOTE_URL..."
git push -u origin main

echo ""
echo "✓ Pushed to $REMOTE_URL"
