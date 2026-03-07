#!/bin/bash
# KidSafe installer for macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/tonycodes/kidsafe/main/install.sh | sudo bash -s -- [child_username]
#    or: sudo bash install.sh [child_username]

set -e

KIDSAFE_VERSION="1.0.0"
KIDSAFE_DIR="/usr/local/kidsafe"
REPO_URL="https://raw.githubusercontent.com/tonycodes/kidsafe/main"
CHILD_USER="${1:-emilio}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; }

echo
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     KidSafe Installer v${KIDSAFE_VERSION}         ║${NC}"
echo -e "${GREEN}║  Parental Controls for macOS         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo

# --- Pre-flight checks ---

# Must be root
if [ "$EUID" -ne 0 ]; then
    err "Please run with sudo:"
    echo "  curl -fsSL ${REPO_URL}/install.sh | sudo bash -s -- ${CHILD_USER}"
    exit 1
fi

# macOS only
if [ "$(uname)" != "Darwin" ]; then
    err "KidSafe only works on macOS."
    exit 1
fi

# Check Python 3
if ! command -v python3 &>/dev/null; then
    err "Python 3 is required. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

# Check child user exists
if ! dscl . read /Users/$CHILD_USER &>/dev/null; then
    err "User '$CHILD_USER' does not exist on this Mac."
    echo "  Available users:"
    dscl . list /Users | grep -v '^_' | grep -v '^root$' | grep -v '^nobody$' | grep -v '^daemon$' | sed 's/^/    /'
    exit 1
fi

# Check Firefox is installed
if [ ! -d "/Applications/Firefox.app" ]; then
    err "Firefox is not installed. Download it from https://www.mozilla.org/firefox/"
    exit 1
fi

info "Installing for child user: ${YELLOW}${CHILD_USER}${NC}"
echo

# --- Download files ---

info "Downloading KidSafe..."
mkdir -p "$KIDSAFE_DIR"

# Detect if running from local clone or via curl
if [ -f "$(dirname "$0")/kidsafe.py" ] && [ "$(dirname "$0")" != "." -o -f "./kidsafe.py" ]; then
    # Local install — copy from current directory
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    cp "$SCRIPT_DIR/kidsafe.py" "$KIDSAFE_DIR/kidsafe.py"
    cp "$SCRIPT_DIR/uninstall.sh" "$KIDSAFE_DIR/uninstall.sh"
    [ -f "$SCRIPT_DIR/kidsafe.mobileconfig" ] && cp "$SCRIPT_DIR/kidsafe.mobileconfig" "$KIDSAFE_DIR/kidsafe.mobileconfig"
    ok "Copied from local files"
else
    # Remote install — download from GitHub
    curl -fsSL "${REPO_URL}/kidsafe.py" -o "$KIDSAFE_DIR/kidsafe.py"
    curl -fsSL "${REPO_URL}/uninstall.sh" -o "$KIDSAFE_DIR/uninstall.sh"
    curl -fsSL "${REPO_URL}/kidsafe.mobileconfig" -o "$KIDSAFE_DIR/kidsafe.mobileconfig" 2>/dev/null || true
    ok "Downloaded from GitHub"
fi

chmod +x "$KIDSAFE_DIR/kidsafe.py"
chmod +x "$KIDSAFE_DIR/uninstall.sh"

# Create symlink
ln -sf "$KIDSAFE_DIR/kidsafe.py" /usr/local/bin/kidsafe
ok "Installed to $KIDSAFE_DIR"

# --- Grant Accessibility permissions for app enforcement ---

info "Granting Accessibility permissions for app enforcement..."
TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
if [ -f "$TCC_DB" ]; then
    # Grant accessibility to python3 and osascript so the enforcer can
    # list running apps and kill unauthorized ones via System Events
    TCC_OK=true
    for client in /usr/bin/python3 /usr/bin/osascript; do
        sqlite3 "$TCC_DB" "DELETE FROM access WHERE service='kTCCServiceAccessibility' AND client='$client' AND client_type=1;" 2>/dev/null || true
        sqlite3 "$TCC_DB" "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, boot_uuid) VALUES ('kTCCServiceAccessibility', '$client', 1, 2, 0, 1, 'UNUSED', 'UNUSED');" 2>/dev/null || TCC_OK=false
    done
    if $TCC_OK; then
        ok "Accessibility permissions granted"
    else
        warn "Could not write to TCC database (SIP may be enabled)."
        echo "  Grant permissions manually:"
        echo "  System Preferences > Security & Privacy > Privacy > Accessibility"
        echo "  Click '+' and add: /usr/bin/python3"
        echo
        echo "  Or disable SIP temporarily:"
        echo "  1. Reboot into Recovery (Cmd+R at startup)"
        echo "  2. Terminal > csrutil disable"
        echo "  3. Reboot, re-run this installer"
        echo "  4. Re-enable SIP: csrutil enable"
    fi
else
    warn "Could not find TCC database — grant Accessibility permissions manually:"
    echo "  System Preferences > Security & Privacy > Privacy > Accessibility"
    echo "  Click '+' and add: /usr/bin/python3"
fi

# --- Setup child user ---

CHILD_HOME=$(dscl . read /Users/$CHILD_USER NFSHomeDirectory | awk '{print $2}')
sudo -u $CHILD_USER mkdir -p "$CHILD_HOME/.kidsafe"
ok "Created config directory: $CHILD_HOME/.kidsafe"

# --- Create LaunchAgent for child (auto-start kiosk on login) ---

AGENT_PLIST="$CHILD_HOME/Library/LaunchAgents/com.kidsafe.kiosk.plist"
mkdir -p "$(dirname $AGENT_PLIST)"

cat > "$AGENT_PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kidsafe.kiosk</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${KIDSAFE_DIR}/kidsafe.py</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${CHILD_HOME}/.kidsafe/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${CHILD_HOME}/.kidsafe/stderr.log</string>
</dict>
</plist>
PLISTEOF

chown $CHILD_USER:staff "$AGENT_PLIST"
chmod 644 "$AGENT_PLIST"
ok "Created LaunchAgent for $CHILD_USER (auto-start on login)"

# --- Create LaunchAgent for admin (dashboard) ---

ADMIN_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "anthonyjames")
if [ "$ADMIN_USER" != "$CHILD_USER" ]; then
    ADMIN_PLIST="/Users/$ADMIN_USER/Library/LaunchAgents/com.kidsafe.dashboard.plist"
    mkdir -p "$(dirname $ADMIN_PLIST)"

    cat > "$ADMIN_PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kidsafe.dashboard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${KIDSAFE_DIR}/kidsafe.py</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
PLISTEOF

    chown $ADMIN_USER:staff "$ADMIN_PLIST"
    chmod 644 "$ADMIN_PLIST"
    ok "Created dashboard LaunchAgent for admin ($ADMIN_USER)"
fi

# --- Setup (password + config) ---

echo -e "${BLUE}Set a parent dashboard password (min 4 characters):${NC}"
while true; do
    printf "  Password: "
    read -r -s ADMIN_PASS < /dev/tty
    echo
    if [ ${#ADMIN_PASS} -ge 4 ]; then
        break
    fi
    warn "Password must be at least 4 characters. Try again."
done

info "Running setup..."
# Set HOME so kidsafe.py writes config to the child's home directory
# Use env to pass the password safely (avoids shell escaping issues)
HOME="$CHILD_HOME" KIDSAFE_SETUP_PASS="$ADMIN_PASS" python3 -c "
import os, json, hashlib, secrets, sqlite3
from pathlib import Path

config_dir = Path.home() / '.kidsafe'
config_dir.mkdir(parents=True, exist_ok=True)
config_file = config_dir / 'config.json'
db_file = config_dir / 'activity.db'

# Hash password
password = os.environ['KIDSAFE_SETUP_PASS']
salt = secrets.token_hex(16)
hashed = hashlib.sha256((salt + password).encode()).hexdigest()

# Load existing config or use defaults
if config_file.exists():
    config = json.loads(config_file.read_text())
else:
    config = {}

config['child_user'] = '$CHILD_USER'
config['admin_password_hash'] = f'{salt}:{hashed}'
config['daily_limit_minutes'] = 120
config['homepage'] = 'https://www.youtube.com/kids'

# Ensure all default keys exist
defaults = {
    'admin_port': 8484, 'warning_minutes': 10,
    'schedule': {'enabled': True, 'allowed_start': '07:00', 'allowed_end': '20:00'},
    'firefox_kiosk': True,
    'allowed_sites': ['youtube.com','youtu.be','pbskids.org','nickjr.com','disney.com',
        'disneyplus.com','netflix.com','khanacademy.org','abcya.com','coolmathgames.com',
        'starfall.com','typingclub.com','scratch.mit.edu','code.org'],
    'blocked_sites': [], 'dns_provider': 'cleanbrowsing',
    'dns_providers': {
        'cleanbrowsing': 'https://doh.cleanbrowsing.org/doh/family-filter/',
        'cloudflare_family': 'https://family.cloudflare-dns.com/dns-query',
        'opendns': 'https://doh.familyshield.opendns.com/dns-query'
    }
}
for k, v in defaults.items():
    config.setdefault(k, v)

config_file.write_text(json.dumps(config, indent=2))

# Init database
conn = sqlite3.connect(str(db_file))
conn.execute('CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TEXT NOT NULL, end_time TEXT, duration_seconds INTEGER DEFAULT 0)')
conn.execute('CREATE TABLE IF NOT EXISTS daily_usage (date TEXT PRIMARY KEY, total_seconds INTEGER DEFAULT 0)')
conn.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, detail TEXT)')
conn.commit()
conn.close()

print('Config saved to ' + str(config_file))
"

# Fix ownership — installer runs as root but config belongs to child
chown -R $CHILD_USER:staff "$CHILD_HOME/.kidsafe"

# Apply Firefox policies (needs root for /Applications/Firefox.app)
python3 "$KIDSAFE_DIR/kidsafe.py" policies
ok "Setup complete"

# --- Done ---

echo
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation Complete!            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo
echo -e "  KidSafe is installed and configured for ${YELLOW}$CHILD_USER${NC}."
echo
echo -e "  ${BLUE}What happens now:${NC}"
echo -e "  - Kiosk auto-starts when $CHILD_USER logs in"
echo -e "  - Firefox opens in fullscreen with content filtering"
echo -e "  - Daily limit: ${YELLOW}120 minutes${NC} (change in dashboard)"
echo -e "  - Schedule: ${YELLOW}7:00 AM – 8:00 PM${NC} (change in dashboard)"
echo
echo -e "  ${BLUE}Parent dashboard:${NC}"
echo -e "     ${YELLOW}http://127.0.0.1:8484${NC}"
echo
echo -e "  ${BLUE}Manual commands:${NC}"
echo -e "     ${YELLOW}kidsafe start${NC}    — start kiosk"
echo -e "     ${YELLOW}kidsafe stop${NC}     — stop kiosk"
echo -e "     ${YELLOW}kidsafe status${NC}   — check status"
echo -e "     ${YELLOW}kidsafe setup${NC}    — change settings"
echo
echo -e "  ${BLUE}To uninstall:${NC}"
echo -e "     ${YELLOW}sudo bash $KIDSAFE_DIR/uninstall.sh${NC}"
echo -e "     or: ${YELLOW}curl -fsSL ${REPO_URL}/uninstall.sh | sudo bash${NC}"
echo
