#!/usr/bin/env python3
"""
KidSafe - Lightweight parental control kiosk for macOS.

Locks a macOS user account to Firefox-only browsing with:
- Firefox kiosk mode (fullscreen, no chrome)
- DNS-based content filtering (CleanBrowsing Family)
- Website whitelist/blacklist via Firefox policies
- Daily time limits with warnings
- Activity logging
- Parent web dashboard (password protected)

Designed for macOS 11+ (Big Sur), Python 3.8+, zero dependencies.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import threading
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from types import FrameType
from urllib.parse import parse_qs, urlparse

# --- Configuration ---

CONFIG_DIR: Path = Path.home() / ".kidsafe"
CONFIG_FILE: Path = CONFIG_DIR / "config.json"
DB_FILE: Path = CONFIG_DIR / "activity.db"
LOG_FILE: Path = CONFIG_DIR / "kidsafe.log"

DEFAULT_CONFIG: Dict[str, Any] = {
    "child_user": "emilio",
    "admin_password_hash": "",
    "admin_port": 8484,
    "daily_limit_minutes": 120,
    "warning_minutes": 10,
    "schedule": {
        "enabled": True,
        "allowed_start": "07:00",
        "allowed_end": "20:00"
    },
    "firefox_kiosk": True,
    "homepage": "https://www.youtube.com/kids",
    "allowed_sites": [
        "youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "pbskids.org",
        "bbc.co.uk/cbeebies",
        "nickjr.com",
        "disney.com",
        "disneyplus.com",
        "netflix.com",
        "khanacademy.org",
        "abcya.com",
        "coolmathgames.com",
        "nationalgeographic.com/kids",
        "funbrain.com",
        "starfall.com",
        "typingclub.com",
        "scratch.mit.edu",
        "code.org"
    ],
    "blocked_sites": [],
    "dns_provider": "cleanbrowsing",
    "dns_providers": {
        "cleanbrowsing": "https://doh.cleanbrowsing.org/doh/family-filter/",
        "cloudflare_family": "https://family.cloudflare-dns.com/dns-query",
        "opendns": "https://doh.familyshield.opendns.com/dns-query"
    }
}


def log(msg: str) -> None:
    """Simple logging to file and stdout."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# --- Database ---

def init_db() -> None:
    """Initialize SQLite database for activity tracking."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            duration_seconds INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            date TEXT PRIMARY KEY,
            total_seconds INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            detail TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS browsing_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain TEXT NOT NULL,
            url TEXT NOT NULL,
            duration_seconds INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_browsing_history_timestamp
        ON browsing_history (timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_browsing_history_domain
        ON browsing_history (domain)
    """)
    conn.commit()
    conn.close()


def record_event(event_type: str, detail: str = "") -> None:
    """Record an event to the database."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.execute(
            "INSERT INTO events (timestamp, event_type, detail) VALUES (?, ?, ?)",
            (datetime.now().isoformat(), event_type, detail)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"DB error: {e}")


def get_today_usage() -> int:
    """Get total usage seconds for today."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        today = datetime.now().strftime("%Y-%m-%d")
        row = conn.execute(
            "SELECT total_seconds FROM daily_usage WHERE date = ?", (today,)
        ).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:
        return 0


def update_daily_usage(seconds: int) -> None:
    """Update today's usage total."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        today = datetime.now().strftime("%Y-%m-%d")
        conn.execute("""
            INSERT INTO daily_usage (date, total_seconds) VALUES (?, ?)
            ON CONFLICT(date) DO UPDATE SET total_seconds = ?
        """, (today, seconds, seconds))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"DB error: {e}")


def get_usage_history(days: int = 7) -> List[Dict[str, Any]]:
    """Get usage history for the last N days."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        rows = conn.execute(
            "SELECT date, total_seconds FROM daily_usage WHERE date >= ? ORDER BY date DESC",
            (cutoff,)
        ).fetchall()
        conn.close()
        return [{"date": r[0], "minutes": r[1] // 60} for r in rows]
    except Exception:
        return []


def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent events."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        rows = conn.execute(
            "SELECT timestamp, event_type, detail FROM events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [{"time": r[0], "type": r[1], "detail": r[2]} for r in rows]
    except Exception:
        return []


def record_browsing_history(domain: str, url: str, duration_seconds: int = 0) -> None:
    """Record a browsing history entry."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.execute(
            "INSERT INTO browsing_history (timestamp, domain, url, duration_seconds) "
            "VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), domain, url, duration_seconds)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"DB error recording browsing history: {e}")


def get_browsing_history(
    page: int = 1,
    per_page: int = 50,
    domain: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> Dict[str, Any]:
    """Get paginated browsing history with optional filters."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conditions: List[str] = []
        params: List[Any] = []

        if domain:
            conditions.append("domain LIKE ?")
            params.append(f"%{domain}%")
        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= ?")
            # Include the full day if only a date is given
            if len(date_to) == 10:
                params.append(date_to + "T23:59:59")
            else:
                params.append(date_to)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        # Get total count
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM browsing_history {where}", params
        ).fetchone()
        total = count_row[0] if count_row else 0

        # Get paginated results
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT id, timestamp, domain, url, duration_seconds "
            f"FROM browsing_history {where} "
            f"ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
        conn.close()

        items = [
            {
                "id": r[0],
                "timestamp": r[1],
                "domain": r[2],
                "url": r[3],
                "duration_seconds": r[4],
            }
            for r in rows
        ]

        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        }
    except Exception as e:
        log(f"DB error fetching browsing history: {e}")
        return {"items": [], "total": 0, "page": 1, "per_page": per_page, "total_pages": 1}


# --- Config ---

def load_config() -> Dict[str, Any]:
    """Load config from file, creating defaults if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config: Dict[str, Any] = json.load(f)
        # Merge any new default keys
        for key, val in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = val
        return config
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> None:
    """Save config to file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def hash_password(password: str) -> str:
    """Hash a password with a salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against stored hash."""
    if not stored:
        return False
    salt, hashed = stored.split(":")
    return hashlib.sha256((salt + password).encode()).hexdigest() == hashed


# --- Firefox Policy Management ---

FIREFOX_POLICY_DIR: Path = Path("/Applications/Firefox.app/Contents/Resources/distribution")
FIREFOX_POLICY_FILE: Path = FIREFOX_POLICY_DIR / "policies.json"


def generate_firefox_policies(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate Firefox enterprise policies for content filtering."""
    dns_url: str = config["dns_providers"].get(
        config["dns_provider"],
        config["dns_providers"]["cleanbrowsing"]
    )

    policies: Dict[str, Any] = {
        "policies": {
            # Force DNS-over-HTTPS with family filter
            "DNSOverHTTPS": {
                "Enabled": True,
                "ProviderURL": dns_url,
                "Locked": True
            },
            # Set homepage
            "Homepage": {
                "URL": config["homepage"],
                "Locked": True,
                "StartPage": "homepage"
            },
            # Block about:config and other dangerous pages
            "BlockAboutConfig": True,
            "BlockAboutProfiles": True,
            "BlockAboutAddons": True,
            # Disable developer tools
            "DisableDeveloperTools": True,
            # Disable private browsing
            "DisablePrivateBrowsing": True,
            # Disable profile import
            "DisableProfileImport": True,
            # Disable form history
            "DisableFormHistory": True,
            # Disable password manager (kid doesn't need it)
            "PasswordManagerEnabled": False,
            # Enable tracking protection
            "EnableTrackingProtection": {
                "Value": True,
                "Locked": True
            },
            # Block popups
            "PopupBlocking": {
                "Default": True,
                "Locked": True
            },
            # Block dangerous downloads
            "Preferences": {
                "browser.safebrowsing.downloads.enabled": {
                    "Value": True,
                    "Status": "locked"
                },
                "browser.safebrowsing.malware.enabled": {
                    "Value": True,
                    "Status": "locked"
                },
                "network.trr.mode": {
                    "Value": 3,
                    "Status": "locked"
                }
            },
            # No first run pages
            "OverrideFirstRunPage": "",
            "OverridePostUpdatePage": "",
            "NoDefaultBookmarks": True
        }
    }

    # Add bookmarks for allowed sites
    toolbar_bookmarks: List[Dict[str, str]] = []
    for site in config["allowed_sites"][:10]:
        name = site.split(".")[0].replace("/", " ").title()
        toolbar_bookmarks.append({
            "Title": name,
            "URL": f"https://{site}",
            "Placement": "toolbar"
        })

    if toolbar_bookmarks:
        policies["policies"]["ManagedBookmarks"] = toolbar_bookmarks

    # Website filter (whitelist mode if allowed_sites is set)
    if config.get("allowed_sites"):
        # Block everything, then allow specific sites
        web_filter: Dict[str, List[str]] = {"Block": ["*"]}
        exceptions = [f"*://*.{site}/*" for site in config["allowed_sites"]]
        # Also allow the homepage domain
        homepage_domain = urlparse(config["homepage"]).netloc
        if homepage_domain:
            exceptions.append(f"*://*.{homepage_domain}/*")
            exceptions.append(f"*://{homepage_domain}/*")
        web_filter["Exceptions"] = exceptions
        policies["policies"]["WebsiteFilter"] = web_filter

    # Add explicit blocks
    if config.get("blocked_sites"):
        if "WebsiteFilter" not in policies["policies"]:
            policies["policies"]["WebsiteFilter"] = {}
        block_patterns = [f"*://*.{site}/*" for site in config["blocked_sites"]]
        policies["policies"]["WebsiteFilter"]["Block"] = block_patterns

    return policies


def apply_firefox_policies(config: Dict[str, Any]) -> bool:
    """Write Firefox enterprise policies to disk."""
    policies = generate_firefox_policies(config)
    try:
        FIREFOX_POLICY_DIR.mkdir(parents=True, exist_ok=True)
        with open(FIREFOX_POLICY_FILE, "w") as f:
            json.dump(policies, f, indent=2)
        log("Firefox policies applied")
        record_event("policy_update", "Firefox policies updated")
        return True
    except PermissionError:
        log("ERROR: Cannot write Firefox policies — need admin permissions")
        return False


# --- Browsing History Tracker ---


def find_firefox_places_db() -> Optional[Path]:
    """Find Firefox's places.sqlite database in the default profile."""
    profiles_dir = Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles"
    if not profiles_dir.exists():
        return None
    # Look for the default-release profile first, then any profile
    for pattern in ["*.default-release", "*.default", "*"]:
        for profile in profiles_dir.glob(pattern):
            places = profile / "places.sqlite"
            if places.exists():
                return places
    return None


class BrowsingTracker:
    """Tracks browsing history by reading Firefox's places.sqlite."""

    def __init__(self, check_interval: int = 30) -> None:
        self.check_interval: int = check_interval
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None
        self.last_visit_id: int = 0
        self._current_url: Optional[str] = None
        self._current_url_start: Optional[datetime] = None

    def start(self) -> None:
        """Start the browsing tracker background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log("Browsing history tracker started")

    def stop(self) -> None:
        """Stop the browsing tracker."""
        self._flush_current_page()
        self.running = False

    def _flush_current_page(self) -> None:
        """Record duration for the current page before moving on."""
        if self._current_url and self._current_url_start:
            duration = int((datetime.now() - self._current_url_start).total_seconds())
            if duration > 0:
                domain = urlparse(self._current_url).netloc
                record_browsing_history(domain, self._current_url, duration)

    def _poll_firefox_history(self) -> None:
        """Read new history entries from Firefox's places.sqlite."""
        places_db = find_firefox_places_db()
        if not places_db:
            return

        try:
            # Copy the database to avoid locking issues with Firefox
            tmp_db = CONFIG_DIR / "places_copy.sqlite"
            shutil.copy2(str(places_db), str(tmp_db))

            conn = sqlite3.connect(str(tmp_db))
            # moz_historyvisits has: id, from_visit, place_id, visit_date, visit_type
            # moz_places has: id, url, title, rev_host, visit_count, ...
            # visit_date is in microseconds since epoch
            rows = conn.execute(
                "SELECT v.id, p.url, v.visit_date "
                "FROM moz_historyvisits v "
                "JOIN moz_places p ON v.place_id = p.id "
                "WHERE v.id > ? "
                "ORDER BY v.id ASC",
                (self.last_visit_id,)
            ).fetchall()
            conn.close()

            # Clean up temp file
            try:
                tmp_db.unlink()
            except Exception:
                pass

            for row in rows:
                visit_id: int = row[0]
                url: str = row[1]
                visit_date_us: int = row[2]
                self.last_visit_id = visit_id

                # Skip internal Firefox URLs
                if url.startswith(("about:", "moz-", "chrome:", "resource:", "file:")):
                    continue

                parsed = urlparse(url)
                domain = parsed.netloc
                if not domain:
                    continue

                # Calculate duration: if we had a previous URL, flush it
                now = datetime.now()
                if self._current_url and self._current_url != url:
                    self._flush_current_page()

                self._current_url = url
                # Use Firefox's visit timestamp if available
                if visit_date_us:
                    visit_time = datetime.fromtimestamp(visit_date_us / 1_000_000)
                    self._current_url_start = visit_time
                else:
                    self._current_url_start = now

                # Record the visit with 0 duration initially (duration updated on next visit)
                record_browsing_history(domain, url, 0)

        except Exception as e:
            log(f"Browsing tracker error: {e}")

    def _run(self) -> None:
        """Background thread loop."""
        # Initialize last_visit_id from Firefox DB to avoid importing old history
        places_db = find_firefox_places_db()
        if places_db:
            try:
                tmp_db = CONFIG_DIR / "places_copy.sqlite"
                shutil.copy2(str(places_db), str(tmp_db))
                conn = sqlite3.connect(str(tmp_db))
                row = conn.execute(
                    "SELECT MAX(id) FROM moz_historyvisits"
                ).fetchone()
                conn.close()
                try:
                    tmp_db.unlink()
                except Exception:
                    pass
                if row and row[0]:
                    self.last_visit_id = row[0]
                    log(f"Browsing tracker initialized at visit ID {self.last_visit_id}")
            except Exception as e:
                log(f"Error initializing browsing tracker: {e}")

        while self.running:
            try:
                self._poll_firefox_history()
            except Exception as e:
                log(f"Browsing tracker error: {e}")
            time.sleep(self.check_interval)


# --- Firefox Kiosk Manager ---

# --- App Enforcer (kills unauthorized apps) ---
# Uses `ps` to find running .app processes — no Accessibility permissions needed.

# .app bundles that are allowed to run (lowercase). Everything else from
# /Applications/ or /System/Applications/ gets killed.
ALLOWED_APP_BUNDLES: Set[str] = {
    "firefox.app",
}


def find_unauthorized_apps() -> Dict[str, List[int]]:
    """Find running .app processes that aren't in the allowed list.
    Returns dict of {app_name: [pids]} for apps that should be killed.
    No special permissions required — just reads `ps` output."""
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm"],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return {}

    apps: Dict[str, List[int]] = {}  # {app_name: [pids]}
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        pid_str, comm = parts
        if "/Applications/" not in comm:
            continue
        m = re.search(r"/([^/]+\.app)/", comm)
        if not m:
            continue
        app_name = m.group(1)
        if app_name.lower() in ALLOWED_APP_BUNDLES:
            continue
        apps.setdefault(app_name, []).append(int(pid_str))
    return apps


def kill_unauthorized_apps() -> List[str]:
    """Kill all unauthorized .app processes. Returns list of app names killed."""
    apps = find_unauthorized_apps()
    killed: List[str] = []
    for app_name, pids in apps.items():
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        killed.append(app_name)
    return killed


class AppEnforcer:
    """Background thread that continuously kills unauthorized apps."""

    def __init__(self, check_interval: int = 2) -> None:
        self.check_interval: int = check_interval
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log("App enforcer started — unauthorized apps will be killed")

    def stop(self) -> None:
        self.running = False

    def _run(self) -> None:
        while self.running:
            try:
                killed = kill_unauthorized_apps()
                for app in killed:
                    log(f"Killed unauthorized app: {app}")
                    record_event("app_blocked", app)
            except Exception as e:
                log(f"Enforcer error: {e}")
            time.sleep(self.check_interval)


# --- Firefox Kiosk Manager ---

class KioskManager:
    """Manages Firefox in kiosk mode with time limits."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config: Dict[str, Any] = config
        self.firefox_process: Optional[subprocess.Popen[bytes]] = None
        self.session_start: Optional[datetime] = None
        self.running: bool = False
        self.session_seconds: int = 0
        self.enforcer: AppEnforcer = AppEnforcer(check_interval=2)
        self.browsing_tracker: BrowsingTracker = BrowsingTracker(check_interval=30)

    def is_within_schedule(self) -> bool:
        """Check if current time is within allowed schedule."""
        if not self.config["schedule"]["enabled"]:
            return True
        now = datetime.now().strftime("%H:%M")
        start: str = self.config["schedule"]["allowed_start"]
        end: str = self.config["schedule"]["allowed_end"]
        return start <= now <= end

    def get_remaining_minutes(self) -> int:
        """Get remaining minutes for today."""
        used = get_today_usage()
        limit: int = self.config["daily_limit_minutes"] * 60
        remaining = max(0, limit - used)
        return remaining // 60

    def hide_dock(self) -> None:
        """Auto-hide the Dock so the child only sees Firefox."""
        try:
            subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events" to set autohide of dock preferences to true'],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    def ensure_firefox_fullscreen(self) -> None:
        """Make sure Firefox is in fullscreen. Sends Cmd+Shift+F if not."""
        try:
            # Check if Firefox has a fullscreen window
            result = subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events" to tell process "firefox" to get value of attribute "AXFullScreen" of window 1'],
                capture_output=True, text=True, timeout=3
            )
            if result.stdout.strip() == "false":
                # Send Cmd+Shift+F to enter fullscreen
                subprocess.run(
                    ["osascript", "-e",
                     'tell application "System Events" to tell process "firefox" to keystroke "f" using {command down, shift down}'],
                    capture_output=True, timeout=3
                )
                log("Re-maximized Firefox to fullscreen")
        except Exception:
            pass

    def launch_firefox(self) -> bool:
        """Launch Firefox in kiosk mode."""
        cmd = ["/Applications/Firefox.app/Contents/MacOS/firefox"]
        if self.config["firefox_kiosk"]:
            cmd.append("--kiosk")
        cmd.append(self.config["homepage"])

        self.hide_dock()

        try:
            self.firefox_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.session_start = datetime.now()
            log(f"Firefox launched (PID: {self.firefox_process.pid})")
            record_event("firefox_start", f"PID: {self.firefox_process.pid}")
            return True
        except Exception as e:
            log(f"Failed to launch Firefox: {e}")
            return False

    def stop_firefox(self) -> None:
        """Stop Firefox gracefully."""
        if self.firefox_process:
            try:
                self.firefox_process.terminate()
                self.firefox_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.firefox_process.kill()
            except Exception:
                pass
            self.firefox_process = None
            log("Firefox stopped")
            record_event("firefox_stop")

    def is_firefox_running(self) -> bool:
        """Check if Firefox process is still running."""
        if self.firefox_process:
            return self.firefox_process.poll() is None
        return False

    def show_notification(self, title: str, message: str) -> None:
        """Show a macOS notification."""
        try:
            subprocess.run([
                "osascript", "-e",
                f'display notification "{message}" with title "{title}"'
            ], timeout=5, capture_output=True)
        except Exception:
            pass

    def show_times_up_screen(self) -> None:
        """Show a 'Time's Up' dialog."""
        try:
            subprocess.run([
                "osascript", "-e",
                'display dialog "Time\'s up for today! See you tomorrow." '
                'buttons {"OK"} default button "OK" '
                'with title "KidSafe" with icon caution'
            ], timeout=30, capture_output=True)
        except Exception:
            pass

    def show_outside_schedule_screen(self) -> None:
        """Show an 'Outside Schedule' dialog."""
        start = self.config["schedule"]["allowed_start"]
        end = self.config["schedule"]["allowed_end"]
        try:
            subprocess.run([
                "osascript", "-e",
                f'display dialog "Computer time is between {start} and {end}." '
                'buttons {"OK"} default button "OK" '
                'with title "KidSafe" with icon caution'
            ], timeout=30, capture_output=True)
        except Exception:
            pass

    def run(self) -> None:
        """Main kiosk loop."""
        self.running = True
        log("KidSafe kiosk manager started")
        record_event("kiosk_start")

        # Start the app enforcer — kills any non-whitelisted GUI apps
        self.enforcer.start()

        # Start browsing history tracker
        self.browsing_tracker.start()

        while self.running:
            try:
                # Check schedule
                if not self.is_within_schedule():
                    if self.is_firefox_running():
                        self.stop_firefox()
                    self.show_outside_schedule_screen()
                    record_event("outside_schedule")
                    time.sleep(60)
                    continue

                # Check time limit
                today_usage = get_today_usage()
                limit_seconds = self.config["daily_limit_minutes"] * 60

                if today_usage >= limit_seconds:
                    if self.is_firefox_running():
                        self.stop_firefox()
                    self.show_times_up_screen()
                    record_event("time_limit_reached", f"{today_usage // 60} minutes used")
                    time.sleep(60)
                    continue

                # Warning when close to limit
                remaining = limit_seconds - today_usage
                warning_threshold = self.config["warning_minutes"] * 60
                if remaining <= warning_threshold and remaining > (warning_threshold - 60):
                    self.show_notification(
                        "KidSafe",
                        f"{remaining // 60} minutes left for today!"
                    )

                # Launch Firefox if not running
                if not self.is_firefox_running():
                    self.launch_firefox()
                    time.sleep(5)
                    continue

                # Ensure Firefox stays fullscreen
                if self.session_seconds % 5 == 0:
                    self.ensure_firefox_fullscreen()

                # Update usage tracking
                if self.session_start:
                    elapsed = (datetime.now() - self.session_start).total_seconds()
                    self.session_seconds = int(elapsed)
                    update_daily_usage(today_usage + 1)

                time.sleep(1)

            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Kiosk loop error: {e}")
                time.sleep(5)

        self.browsing_tracker.stop()
        self.enforcer.stop()
        self.stop_firefox()
        record_event("kiosk_stop")
        log("KidSafe kiosk manager stopped")

    def stop(self) -> None:
        """Signal the kiosk to stop."""
        self.running = False


# --- Parent Dashboard Web Server ---

DASHBOARD_HTML: str = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KidSafe Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f5f5f7; color: #1d1d1f; padding: 20px; max-width: 800px; margin: 0 auto; }
  h1 { font-size: 28px; margin-bottom: 8px; }
  h2 { font-size: 20px; margin: 24px 0 12px; color: #6e6e73; }
  .subtitle { color: #6e6e73; margin-bottom: 24px; }
  .card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .stat { display: inline-block; text-align: center; margin-right: 32px; }
  .stat-value { font-size: 36px; font-weight: 700; color: #0071e3; }
  .stat-label { font-size: 13px; color: #6e6e73; margin-top: 4px; }
  .bar { height: 8px; background: #e5e5ea; border-radius: 4px; margin: 8px 0; }
  .bar-fill { height: 100%; background: #0071e3; border-radius: 4px; transition: width 0.3s; }
  .bar-fill.warning { background: #ff9500; }
  .bar-fill.danger { background: #ff3b30; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e5ea; }
  th { font-weight: 600; color: #6e6e73; font-size: 13px; text-transform: uppercase; }
  td { font-size: 14px; }
  input, select { padding: 8px 12px; border: 1px solid #d2d2d7; border-radius: 8px;
                  font-size: 14px; width: 100%; margin-bottom: 8px; }
  button { padding: 10px 20px; background: #0071e3; color: white; border: none;
           border-radius: 8px; font-size: 14px; cursor: pointer; margin-right: 8px; }
  button:hover { background: #0077ed; }
  button.danger { background: #ff3b30; }
  button.danger:hover { background: #ff453a; }
  .tag { display: inline-block; background: #e5e5ea; padding: 4px 10px;
         border-radius: 6px; font-size: 13px; margin: 2px; }
  .tag .remove { cursor: pointer; margin-left: 4px; color: #ff3b30; }
  .form-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
  .form-row input { flex: 1; }
  .form-row button { flex-shrink: 0; }
  .event-type { font-weight: 600; font-size: 12px; padding: 2px 8px; border-radius: 4px; }
  .event-type.firefox_start { background: #d1f2d1; color: #1b7a1b; }
  .event-type.firefox_stop { background: #fdd; color: #c00; }
  .event-type.time_limit_reached { background: #fff3cd; color: #856404; }
  .event-type.kiosk_start { background: #d1ecf1; color: #0c5460; }
  .tabs { display: flex; gap: 0; margin-bottom: 24px; border-bottom: 2px solid #e5e5ea; }
  .tab { padding: 10px 20px; cursor: pointer; font-size: 14px; font-weight: 600; color: #6e6e73;
         border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.2s; }
  .tab:hover { color: #1d1d1f; }
  .tab.active { color: #0071e3; border-bottom-color: #0071e3; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .filter-row { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-row input { flex: 1; min-width: 120px; }
  .pagination { display: flex; justify-content: space-between; align-items: center; margin-top: 12px;
                padding-top: 12px; border-top: 1px solid #e5e5ea; }
  .pagination button { padding: 6px 14px; font-size: 13px; }
  .pagination button:disabled { opacity: 0.5; cursor: not-allowed; }
  .page-info { font-size: 13px; color: #6e6e73; }
  .url-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .duration { font-variant-numeric: tabular-nums; }
  .sortable { cursor: pointer; user-select: none; }
  .sortable:hover { color: #0071e3; }
  .sortable::after { content: ' \u2195'; font-size: 10px; }
  #login { max-width: 300px; margin: 100px auto; }
</style>
</head>
<body>
<div id="app"></div>
<script>
const app = document.getElementById('app');
let token = sessionStorage.getItem('kidsafe_token') || '';

async function api(path, method='GET', body=null) {
  const opts = { method, headers: {'Content-Type': 'application/json'} };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  return res.json();
}

async function login(pass) {
  const data = await api('/login', 'POST', { password: pass });
  if (data.token) { token = data.token; sessionStorage.setItem('kidsafe_token', token); render(); }
  else alert('Wrong password');
}

function showLogin() {
  app.innerHTML = `
    <div id="login" class="card">
      <h1>KidSafe</h1>
      <p class="subtitle">Parent Dashboard</p>
      <input type="password" id="pass" placeholder="Admin password" onkeydown="if(event.key==='Enter')document.getElementById('loginBtn').click()">
      <button id="loginBtn">Log In</button>
    </div>`;
  document.getElementById('loginBtn').onclick = () => login(document.getElementById('pass').value);
}

let activeTab = 'overview';
let browsingPage = 1;
let browsingSort = { col: 'timestamp', dir: 'desc' };

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + tab));
  if (tab === 'activity') loadBrowsingHistory();
}

function formatDuration(secs) {
  if (!secs || secs === 0) return '-';
  if (secs < 60) return secs + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ' + (secs % 60) + 's';
  return Math.floor(secs / 3600) + 'h ' + Math.floor((secs % 3600) / 60) + 'm';
}

async function loadBrowsingHistory() {
  const domain = (document.getElementById('bh-domain') || {}).value || '';
  const dateFrom = (document.getElementById('bh-from') || {}).value || '';
  const dateTo = (document.getElementById('bh-to') || {}).value || '';
  let url = '/browsing-history?page=' + browsingPage + '&per_page=50';
  if (domain) url += '&domain=' + encodeURIComponent(domain);
  if (dateFrom) url += '&date_from=' + encodeURIComponent(dateFrom);
  if (dateTo) url += '&date_to=' + encodeURIComponent(dateTo);
  const data = await api(url);
  const items = data.items || [];

  // Client-side sort
  items.sort((a, b) => {
    let va = a[browsingSort.col], vb = b[browsingSort.col];
    if (browsingSort.col === 'duration_seconds') { va = va || 0; vb = vb || 0; }
    if (va < vb) return browsingSort.dir === 'asc' ? -1 : 1;
    if (va > vb) return browsingSort.dir === 'asc' ? 1 : -1;
    return 0;
  });

  const tbody = document.getElementById('bh-tbody');
  if (tbody) {
    tbody.innerHTML = items.length === 0
      ? '<tr><td colspan="4" style="text-align:center;color:#6e6e73;padding:24px">No browsing history found</td></tr>'
      : items.map(i => `<tr>
          <td>${i.domain}</td>
          <td class="url-cell" title="${i.url}">${i.url}</td>
          <td>${new Date(i.timestamp).toLocaleString()}</td>
          <td class="duration">${formatDuration(i.duration_seconds)}</td>
        </tr>`).join('');
  }
  const pageInfo = document.getElementById('bh-page-info');
  if (pageInfo) pageInfo.textContent = 'Page ' + data.page + ' of ' + data.total_pages + ' (' + data.total + ' total)';
  const prevBtn = document.getElementById('bh-prev');
  const nextBtn = document.getElementById('bh-next');
  if (prevBtn) prevBtn.disabled = data.page <= 1;
  if (nextBtn) nextBtn.disabled = data.page >= data.total_pages;
}

function bhSort(col) {
  if (browsingSort.col === col) browsingSort.dir = browsingSort.dir === 'asc' ? 'desc' : 'asc';
  else { browsingSort.col = col; browsingSort.dir = 'desc'; }
  loadBrowsingHistory();
}
function bhPrev() { browsingPage = Math.max(1, browsingPage - 1); loadBrowsingHistory(); }
function bhNext() { browsingPage++; loadBrowsingHistory(); }
function bhSearch() { browsingPage = 1; loadBrowsingHistory(); }

async function render() {
  if (!token) return showLogin();
  const [status, config, history, events] = await Promise.all([
    api('/status'), api('/config'), api('/history'), api('/events')
  ]);
  if (status.error === 'unauthorized') { token = ''; sessionStorage.removeItem('kidsafe_token'); return showLogin(); }

  const usedPct = Math.min(100, (status.used_minutes / config.daily_limit_minutes) * 100);
  const barClass = usedPct > 90 ? 'danger' : usedPct > 70 ? 'warning' : '';

  app.innerHTML = `
    <h1>KidSafe</h1>
    <p class="subtitle">Parental Dashboard for ${config.child_user}</p>

    <div class="card">
      <div class="stat"><div class="stat-value">${status.remaining_minutes}</div><div class="stat-label">Minutes Left Today</div></div>
      <div class="stat"><div class="stat-value">${status.used_minutes}</div><div class="stat-label">Minutes Used</div></div>
      <div class="stat"><div class="stat-value">${status.firefox_running ? 'ON' : 'OFF'}</div><div class="stat-label">Firefox Status</div></div>
      <div class="bar"><div class="bar-fill ${barClass}" style="width:${usedPct}%"></div></div>
    </div>

    <div class="tabs">
      <div class="tab ${activeTab==='overview'?'active':''}" data-tab="overview" onclick="switchTab('overview')">Overview</div>
      <div class="tab ${activeTab==='activity'?'active':''}" data-tab="activity" onclick="switchTab('activity')">Activity</div>
    </div>

    <div id="tab-overview" class="tab-content ${activeTab==='overview'?'active':''}">
      <h2>Settings</h2>
      <div class="card">
        <label>Daily Time Limit (minutes)</label>
        <div class="form-row">
          <input type="number" id="limit" value="${config.daily_limit_minutes}" min="1" max="480">
          <button onclick="saveLimit()">Save</button>
        </div>
        <label>Schedule</label>
        <div class="form-row">
          <input type="time" id="sched_start" value="${config.schedule.allowed_start}">
          <span>to</span>
          <input type="time" id="sched_end" value="${config.schedule.allowed_end}">
          <button onclick="saveSchedule()">Save</button>
        </div>
        <label>Homepage</label>
        <div class="form-row">
          <input type="url" id="homepage" value="${config.homepage}">
          <button onclick="saveHomepage()">Save</button>
        </div>
      </div>

      <h2>Allowed Sites</h2>
      <div class="card">
        <div id="sites">${config.allowed_sites.map(s => `<span class="tag">${s}<span class="remove" onclick="removeSite('${s}')">&times;</span></span>`).join(' ')}</div>
        <div class="form-row" style="margin-top:12px">
          <input type="text" id="newsite" placeholder="example.com">
          <button onclick="addSite()">Add</button>
        </div>
      </div>

      <h2>Usage History (7 days)</h2>
      <div class="card">
        <table><tr><th>Date</th><th>Minutes</th></tr>
          ${(history || []).map(h => `<tr><td>${h.date}</td><td>${h.minutes}</td></tr>`).join('')}
        </table>
      </div>

      <h2>Recent Activity</h2>
      <div class="card">
        <table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>
          ${(events || []).slice(0, 20).map(e => `<tr><td>${new Date(e.time).toLocaleString()}</td><td><span class="event-type ${e.type}">${e.type}</span></td><td>${e.detail || ''}</td></tr>`).join('')}
        </table>
      </div>

      <h2>Controls</h2>
      <div class="card">
        <button onclick="resetTime()">Reset Today's Time</button>
        <button onclick="applyPolicies()">Apply Firefox Policies</button>
        <button class="danger" onclick="stopKiosk()">Stop Kiosk</button>
      </div>
    </div>

    <div id="tab-activity" class="tab-content ${activeTab==='activity'?'active':''}">
      <h2>Browsing History</h2>
      <div class="card">
        <div class="filter-row">
          <input type="text" id="bh-domain" placeholder="Filter by domain..." onkeydown="if(event.key==='Enter')bhSearch()">
          <input type="date" id="bh-from" placeholder="From date">
          <input type="date" id="bh-to" placeholder="To date">
          <button onclick="bhSearch()">Search</button>
        </div>
        <table>
          <tr>
            <th class="sortable" onclick="bhSort('domain')">Domain</th>
            <th>URL</th>
            <th class="sortable" onclick="bhSort('timestamp')">Timestamp</th>
            <th class="sortable" onclick="bhSort('duration_seconds')">Duration</th>
          </tr>
          <tbody id="bh-tbody">
            <tr><td colspan="4" style="text-align:center;color:#6e6e73;padding:24px">Loading...</td></tr>
          </tbody>
        </table>
        <div class="pagination">
          <button id="bh-prev" onclick="bhPrev()" disabled>Previous</button>
          <span id="bh-page-info" class="page-info">Page 1</span>
          <button id="bh-next" onclick="bhNext()">Next</button>
        </div>
      </div>
    </div>`;

  if (activeTab === 'activity') loadBrowsingHistory();
}

async function saveLimit() {
  await api('/config', 'POST', { daily_limit_minutes: parseInt(document.getElementById('limit').value) });
  render();
}
async function saveSchedule() {
  await api('/config', 'POST', { schedule: { enabled: true, allowed_start: document.getElementById('sched_start').value, allowed_end: document.getElementById('sched_end').value }});
  render();
}
async function saveHomepage() {
  await api('/config', 'POST', { homepage: document.getElementById('homepage').value });
  render();
}
async function addSite() {
  const site = document.getElementById('newsite').value.trim().replace(/^https?:\\/\\//, '').replace(/\\/+$/, '');
  if (!site) return;
  const cfg = await api('/config');
  cfg.allowed_sites.push(site);
  await api('/config', 'POST', { allowed_sites: cfg.allowed_sites });
  render();
}
async function removeSite(site) {
  const cfg = await api('/config');
  cfg.allowed_sites = cfg.allowed_sites.filter(s => s !== site);
  await api('/config', 'POST', { allowed_sites: cfg.allowed_sites });
  render();
}
async function resetTime() {
  if (confirm('Reset today\\'s time usage to zero?')) { await api('/reset-time', 'POST'); render(); }
}
async function applyPolicies() {
  const r = await api('/apply-policies', 'POST');
  alert(r.message || 'Done');
}
async function stopKiosk() {
  if (confirm('Stop the kiosk? Firefox will close.')) { await api('/stop-kiosk', 'POST'); render(); }
}

render();
setInterval(render, 30000);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the parent dashboard."""

    server_version: str = "KidSafe/1.0"
    config: Optional[Dict[str, Any]] = None
    kiosk: Optional[KioskManager] = None
    auth_tokens: Set[str] = set()

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default HTTP logging."""
        pass

    def send_json(self, data: Any, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:] in DashboardHandler.auth_tokens
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        parsed_path = parsed.path
        parsed_query = parsed.query

        if parsed_path == "/" or parsed_path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
            return

        if not self.check_auth():
            self.send_json({"error": "unauthorized"}, 401)
            return

        assert DashboardHandler.config is not None
        if parsed_path == "/api/status":
            used = get_today_usage()
            limit = DashboardHandler.config["daily_limit_minutes"] * 60
            self.send_json({
                "used_minutes": used // 60,
                "remaining_minutes": max(0, (limit - used)) // 60,
                "limit_minutes": DashboardHandler.config["daily_limit_minutes"],
                "firefox_running": DashboardHandler.kiosk.is_firefox_running() if DashboardHandler.kiosk else False,
                "within_schedule": DashboardHandler.kiosk.is_within_schedule() if DashboardHandler.kiosk else True
            })
        elif parsed_path == "/api/config":
            safe_config = {k: v for k, v in DashboardHandler.config.items() if k != "admin_password_hash"}
            self.send_json(safe_config)
        elif parsed_path == "/api/history":
            self.send_json(get_usage_history())
        elif parsed_path == "/api/events":
            self.send_json(get_recent_events())
        elif parsed_path == "/api/browsing-history":
            params = parse_qs(parsed_query)
            page = int(params.get("page", ["1"])[0])
            per_page = int(params.get("per_page", ["50"])[0])
            domain = params.get("domain", [None])[0]
            date_from = params.get("date_from", [None])[0]
            date_to = params.get("date_to", [None])[0]
            self.send_json(get_browsing_history(
                page=max(1, page),
                per_page=min(100, max(1, per_page)),
                domain=domain,
                date_from=date_from,
                date_to=date_to,
            ))
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        assert DashboardHandler.config is not None
        content_length = int(self.headers.get("Content-Length", "0"))
        body: Dict[str, Any] = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        if self.path == "/api/login":
            password: str = body.get("password", "")
            if verify_password(password, DashboardHandler.config.get("admin_password_hash", "")):
                token = secrets.token_hex(32)
                DashboardHandler.auth_tokens.add(token)
                self.send_json({"token": token})
            else:
                self.send_json({"error": "invalid password"}, 401)
            return

        if not self.check_auth():
            self.send_json({"error": "unauthorized"}, 401)
            return

        if self.path == "/api/config":
            DashboardHandler.config.update(body)
            save_config(DashboardHandler.config)
            record_event("config_update", json.dumps(body))
            self.send_json({"ok": True})
        elif self.path == "/api/reset-time":
            update_daily_usage(0)
            record_event("time_reset", "Admin reset daily time")
            self.send_json({"ok": True})
        elif self.path == "/api/apply-policies":
            ok = apply_firefox_policies(DashboardHandler.config)
            self.send_json({"ok": ok, "message": "Policies applied" if ok else "Failed — need admin permissions"})
        elif self.path == "/api/stop-kiosk":
            if DashboardHandler.kiosk:
                DashboardHandler.kiosk.stop()
            self.send_json({"ok": True})
        else:
            self.send_json({"error": "not found"}, 404)


def run_dashboard(config: Dict[str, Any], kiosk: KioskManager, port: int = 8484) -> None:
    """Start the parent dashboard web server."""
    DashboardHandler.config = config
    DashboardHandler.kiosk = kiosk
    server = HTTPServer(("127.0.0.1", port), DashboardHandler)
    log(f"Dashboard running at http://127.0.0.1:{port}")
    server.serve_forever()


# --- CLI ---

def cmd_setup(args: List[str]) -> None:
    """Interactive setup (or non-interactive with flags)."""
    # Parse flags for non-interactive mode
    flags: Dict[str, str] = {}
    i = 0
    while i < len(args):
        if args[i] == "--child" and i + 1 < len(args):
            flags["child"] = args[i + 1]; i += 2
        elif args[i] == "--password" and i + 1 < len(args):
            flags["password"] = args[i + 1]; i += 2
        elif args[i] == "--password-env" and i + 1 < len(args):
            flags["password"] = os.environ.get(args[i + 1], ""); i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            flags["limit"] = args[i + 1]; i += 2
        elif args[i] == "--homepage" and i + 1 < len(args):
            flags["homepage"] = args[i + 1]; i += 2
        else:
            i += 1

    print("=== KidSafe Setup ===\n")
    config = load_config()

    if "child" in flags:
        config["child_user"] = flags["child"]
    else:
        child_user = input(f"Child's username [{config['child_user']}]: ").strip()
        if child_user:
            config["child_user"] = child_user

    if "password" in flags:
        if len(flags["password"]) >= 4:
            config["admin_password_hash"] = hash_password(flags["password"])
        else:
            print("Password must be at least 4 characters.")
            sys.exit(1)
    else:
        print("\nSet an admin password for the parent dashboard:")
        while True:
            password = input("Password: ").strip()
            if len(password) >= 4:
                config["admin_password_hash"] = hash_password(password)
                break
            print("Password must be at least 4 characters.")

    if "limit" in flags:
        config["daily_limit_minutes"] = int(flags["limit"])
    else:
        limit = input(f"\nDaily time limit in minutes [{config['daily_limit_minutes']}]: ").strip()
        if limit and limit.isdigit():
            config["daily_limit_minutes"] = int(limit)

    if "homepage" in flags:
        config["homepage"] = flags["homepage"]
    else:
        homepage = input(f"Homepage URL [{config['homepage']}]: ").strip()
        if homepage:
            config["homepage"] = homepage

    save_config(config)
    init_db()

    print("\nApplying Firefox policies...")
    apply_firefox_policies(config)

    print(f"\nSetup complete! Config saved to {CONFIG_FILE}")
    print(f"Run 'kidsafe start' to launch the kiosk.")
    print(f"Parent dashboard: http://127.0.0.1:{config['admin_port']}")


def cmd_start(args: List[str]) -> None:
    """Start the kiosk and dashboard."""
    config = load_config()
    init_db()

    if not config.get("admin_password_hash"):
        print("Run 'kidsafe setup' first to set an admin password.")
        sys.exit(1)

    apply_firefox_policies(config)

    kiosk = KioskManager(config)

    # Start dashboard in background thread
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        args=(config, kiosk, config["admin_port"]),
        daemon=True
    )
    dashboard_thread.start()

    # Handle SIGTERM gracefully
    def handle_signal(signum: int, frame: Optional[FrameType]) -> None:
        log("Received shutdown signal")
        kiosk.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Run kiosk (blocks until stopped)
    kiosk.run()


def cmd_stop(args: List[str]) -> None:
    """Stop the kiosk by finding and killing the process."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "kidsafe.py start"],
            capture_output=True, text=True
        )
        pids = result.stdout.strip().split("\n")
        for pid in pids:
            if pid and pid != str(os.getpid()):
                os.kill(int(pid), signal.SIGTERM)
                print(f"Stopped KidSafe (PID: {pid})")
        if not any(p for p in pids if p):
            print("KidSafe is not running.")
    except Exception as e:
        print(f"Error: {e}")


def cmd_status(args: List[str]) -> None:
    """Show current status."""
    config = load_config()
    used = get_today_usage()
    limit = config["daily_limit_minutes"] * 60
    remaining = max(0, (limit - used)) // 60

    print(f"Child user:    {config['child_user']}")
    print(f"Today's usage: {used // 60} minutes")
    print(f"Remaining:     {remaining} minutes")
    print(f"Daily limit:   {config['daily_limit_minutes']} minutes")
    print(f"Schedule:      {config['schedule']['allowed_start']} - {config['schedule']['allowed_end']}")
    print(f"Dashboard:     http://127.0.0.1:{config['admin_port']}")


def cmd_reset(args: List[str]) -> None:
    """Reset today's time."""
    update_daily_usage(0)
    print("Today's usage reset to zero.")


def cmd_policies(args: List[str]) -> None:
    """Apply Firefox policies."""
    config = load_config()
    if apply_firefox_policies(config):
        print("Firefox policies applied successfully.")
    else:
        print("Failed to apply policies. Try with sudo.")


def main() -> None:
    if len(sys.argv) < 2:
        print("KidSafe - Parental Control Kiosk for macOS")
        print()
        print("Usage: kidsafe <command>")
        print()
        print("Commands:")
        print("  setup     Interactive setup wizard")
        print("  start     Start kiosk + parent dashboard")
        print("  stop      Stop the kiosk")
        print("  status    Show current status")
        print("  reset     Reset today's time usage")
        print("  policies  Apply Firefox policies")
        sys.exit(0)

    commands = {
        "setup": cmd_setup,
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "reset": cmd_reset,
        "policies": cmd_policies,
    }

    cmd = sys.argv[1]
    if cmd in commands:
        commands[cmd](sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
