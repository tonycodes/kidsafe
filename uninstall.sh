#!/bin/bash
# KidSafe uninstaller for macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/tonywritescode/kidsafe/main/uninstall.sh | sudo bash
#    or: sudo bash uninstall.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }

echo
echo -e "${RED}╔══════════════════════════════════════╗${NC}"
echo -e "${RED}║     KidSafe Uninstaller              ║${NC}"
echo -e "${RED}╚══════════════════════════════════════╝${NC}"
echo

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Please run with sudo"
    exit 1
fi

# Stop any running instances
info "Stopping KidSafe processes..."
pkill -f "kidsafe.py start" 2>/dev/null || true
ok "Processes stopped"

# Remove LaunchAgents
info "Removing LaunchAgents..."
find /Users/*/Library/LaunchAgents -name "com.kidsafe.*" -delete 2>/dev/null || true
ok "LaunchAgents removed"

# Remove install directory
info "Removing installed files..."
rm -rf /usr/local/kidsafe
rm -f /usr/local/bin/kidsafe
ok "Files removed"

# Remove Firefox policies
info "Removing Firefox policies..."
rm -f "/Applications/Firefox.app/Contents/Resources/distribution/policies.json"
ok "Firefox policies removed"

# Remove MDM profile if installed
if profiles list 2>/dev/null | grep -q "com.kidsafe.profile"; then
    info "Removing MDM profile..."
    profiles remove -identifier com.kidsafe.profile 2>/dev/null || true
    ok "MDM profile removed"
fi

echo
echo -e "${GREEN}KidSafe has been uninstalled.${NC}"
echo -e "Config and logs in ${YELLOW}~/.kidsafe/${NC} were preserved."
echo -e "To remove those too: ${YELLOW}rm -rf ~/.kidsafe${NC}"
echo
