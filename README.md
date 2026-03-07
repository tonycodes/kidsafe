# KidSafe

Lightweight parental control kiosk for macOS. Locks a user account to Firefox-only browsing with content filtering, time limits, and a parent dashboard.

Single Python file, zero dependencies — just macOS and Firefox.

## Features

- **Firefox kiosk mode** — fullscreen, no browser chrome
- **Content filtering** — DNS-over-HTTPS via CleanBrowsing Family filter
- **Website whitelist** — only approved sites accessible (configurable)
- **Daily time limits** — with warnings and schedule (e.g. 7am–8pm)
- **Activity logging** — tracks sessions and usage in SQLite
- **Parent dashboard** — web UI at `http://127.0.0.1:8484` to manage settings, view usage, and control the kiosk
- **Auto-start on login** — LaunchAgent starts the kiosk when the child logs in
- **MDM profile** — optional `.mobileconfig` to restrict the Dock and hide System Preferences

## Requirements

- macOS 11+ (Big Sur or later)
- Python 3.8+ (included with macOS / Xcode CLI tools)
- Firefox installed in `/Applications/`
- A separate macOS user account for the child

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/tonycodes/kidsafe/main/install.sh | sudo bash -s -- <child_username>
```

For example:

```bash
curl -fsSL https://raw.githubusercontent.com/tonycodes/kidsafe/main/install.sh | sudo bash -s -- emilio
```

You'll be prompted for a parent dashboard password. That's it — everything else is configured automatically:

1. Downloads KidSafe to `/usr/local/kidsafe/`
2. Creates a `kidsafe` symlink in `/usr/local/bin/`
3. Sets up LaunchAgents for auto-start on login
4. Applies Firefox enterprise policies (DNS filtering, locked settings)
5. Configures the kiosk (120 min daily limit, 7am–8pm schedule)

To re-run setup later or change settings interactively:

```bash
kidsafe setup
```

## Usage

```bash
# Start the kiosk + dashboard
sudo -u <child_username> kidsafe start

# Check status
kidsafe status

# Stop the kiosk
kidsafe stop

# Reset today's time usage
kidsafe reset

# Re-apply Firefox policies after config changes
sudo kidsafe policies
```

The kiosk starts automatically when the child logs in (via LaunchAgent). The parent dashboard is available at:

```
http://127.0.0.1:8484
```

## Parent Dashboard

The dashboard lets you:

- View remaining time and usage stats
- Adjust daily time limit and schedule
- Change the homepage
- Add/remove allowed websites
- View activity history and events
- Reset time or stop the kiosk remotely

## Configuration

Config is stored at `~/.kidsafe/config.json` (in the child's home directory). Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `daily_limit_minutes` | 120 | Max screen time per day |
| `schedule.allowed_start` | 07:00 | Earliest allowed time |
| `schedule.allowed_end` | 20:00 | Latest allowed time |
| `homepage` | youtube.com/kids | Browser start page |
| `allowed_sites` | 17 kid-safe sites | Whitelist of allowed domains |
| `dns_provider` | cleanbrowsing | DNS-over-HTTPS provider |
| `admin_port` | 8484 | Dashboard port |

## How It Works

- **Firefox Enterprise Policies** — written to `/Applications/Firefox.app/Contents/Resources/distribution/policies.json`. Forces DNS-over-HTTPS with CleanBrowsing Family filter, disables developer tools, private browsing, and about:config. Locks all settings so they can't be changed in Firefox.
- **Kiosk Mode** — Firefox launches with `--kiosk` flag (fullscreen, no URL bar, no tabs).
- **Website Filter** — Firefox's built-in `WebsiteFilter` policy blocks all sites except those in the whitelist.
- **Time Tracking** — usage tracked per-second in SQLite, enforced with configurable daily limits and time-of-day schedule.
- **LaunchAgent** — `com.kidsafe.kiosk.plist` runs at login with `KeepAlive` so Firefox restarts if closed.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/tonycodes/kidsafe/main/uninstall.sh | sudo bash
```

Or if installed locally:

```bash
sudo bash /usr/local/kidsafe/uninstall.sh
```

This removes the app, LaunchAgents, Firefox policies, and any installed MDM profile. Config and logs in `~/.kidsafe/` are preserved — delete manually if needed.

## License

MIT
