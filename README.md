# CLAUD Hosting Panel — Pro Upgrade

A premium, mobile-first Python hosting panel for **PythonAnywhere** (Free & Paid). This release upgrades the existing panel *without removing a single feature* — every route, template, and flow you already had still works. The upgrade layer adds a real-time terminal, AI error detector, process manager, live monitoring, backups, and a glassmorphic AMOLED bottom-sheet UI on top.

## What's new

### Console terminal (real-time)
- WebSocket streaming via Flask-SocketIO with automatic polling fallback (works on PythonAnywhere Free where WS may be restricted).
- ANSI color rendering, search-in-logs, download logs, clear, auto-scroll toggle, fullscreen.
- Command history (↑/↓), `$ command` bar wired to `/server/command/<folder>` (15 s timeout, sandboxed to server folder).
- Live per-process CPU / RAM / thread / uptime counters.
- Live system CPU / RAM / Disk / Network monitor.
- Process manager: list root + children, one-tap kill by PID.
- One-click Start / Restart / Stop / Kill; **Force Restart** and **Force Stop** available to admins.

### AI Auto-Fix
- Deterministic pattern engine in `ai_fixer.py` (no external API needed, PA-friendly).
- Detects `ModuleNotFoundError`, `ImportError`, `SyntaxError`, `IndentationError`, `PermissionError`, `FileNotFoundError`, `RuntimeError`, `TypeError`, `ValueError`, `AttributeError`, `NameError`, `KeyError`, `RecursionError`, `MemoryError`, `UnicodeDecodeError`, port-in-use, disk full, connection refused, missing environment variables, and more.
- Every finding includes a **plain-English explanation**, a **recommended fix**, a **confidence score**, and — where relevant — the **exact `pip install --user …` command**.
- Import-name → pip-name translation for common tricky packages (`cv2 → opencv-python`, `PIL → Pillow`, `bs4 → beautifulsoup4`, etc.).
- **Copy Fix** and **One-tap Install** buttons.
- Bulk-install button for every missing requirement detected at once.
- Auto-scanning: diagnoses are pushed into the terminal in real time as errors appear.

### Automatic crash recovery
- Background monitor thread watches every running process.
- On crash: records a `crash_events` row, flags the server, optionally auto-restarts.
- **Restart-loop guard**: max 3 auto-restarts in a 60-second window.

### Server operations
- **Backups**: create / list / restore / download / delete (per-server, gzip-compressed, excludes `console.log`).
- **Clone server** (respects the user's server limit).
- **Transfer ownership** (admin-only).
- **Download entire server as ZIP** (owner or admin).
- **Auto-restart toggle** per server.

### Admin panel additions
- Live headline stats endpoint with 3-second cache (`/admin/dashboard-stats`).
- **Download any user's server as ZIP** (`/admin/download-server/<sid>`).
- **Force restart / force stop** any server (`/admin/force/<action>/<sid>`).
- **Login history** feed (`/admin/login-history`).
- Existing suspend / unsuspend / delete / login-as / manage-user flows are unchanged.

### Mobile UI (additive)
- Premium iOS-inspired **AMOLED black** theme with **cyan accent** and glassmorphism.
- **Floating action button** ("bolt") in the bottom-right of every dashboard/admin page.
- **Bottom sheet** with **five bottom-nav tabs**: Live · Console · Procs · AI Fix · More.
- Swipe-down to dismiss, keyboard shortcut **P** to open, **Esc** to close.
- Skeleton loaders, smooth animations, touch-friendly hit targets, `env(safe-area-inset)` respected.
- Zero changes to your existing dashboard markup — the panel is injected via `panel.css` + `panel.js` before `</body>`.

### Performance
- Delta-based log streaming (bytes-accurate).
- Terminal DOM auto-prunes to the last 400 chunks to stay responsive on low-end phones.
- 3-second server-side cache on admin headline stats.
- Optional **gzip compression** via `flask-compress` (auto-detected — safe if missing).
- Reused Socket.IO connection for terminal + stats.

### Security
- All new endpoints are permission-checked (`auth_check` + `verify_folder_ownership`).
- All new *mutating* endpoints require the existing CSRF token.
- Path-traversal protection via the existing `safe_path` helper.
- IP block / rate limiting / session timeout / login history / audit log — all still active and now surfaced through the admin panel.
- Pip installs use strict allow-list regex and `--user` (never root).

## File layout

```
hosting_panel/
├── main.py                # existing panel (upgraded to load enhancements)
├── enhancements.py        # NEW — additive routes, sockets, crash monitor
├── ai_fixer.py            # NEW — deterministic Python error analyzer
├── requirements.txt       # +flask-compress (optional)
├── README.md              # this file
├── static/
│   └── panel/
│       ├── panel.css      # NEW — premium AMOLED / cyan mobile UI
│       └── panel.js       # NEW — Pro Panel bottom-sheet client
└── templates/
    ├── index.html
    └── web/
        ├── login.html
        ├── signup.html
        ├── dashboard.html          # +Pro Panel injection at </body>
        ├── admin_login.html
        ├── admin_panel.html        # +Pro Panel injection at </body>
        └── admin_manage_user.html  # +Pro Panel injection at </body>
```

## Deploying on Railway (recommended for this panel)

This panel spawns subprocesses, streams WebSockets, and runs a background
crash-monitor thread — all of which need a real persistent container, not a
shared WSGI slot. Changes made to support this:

* `eventlet.monkey_patch()` now runs first in `main.py`, before any other
  import — without it, one user's blocking subprocess/file call would
  freeze the Socket.IO loop for every other connected user.
* `SocketIO(async_mode='eventlet')` is explicit instead of auto-detected.
* All storage paths (SQLite DB, `storage/instances`, `storage/backups`,
  `static/uploads`) now resolve through a `DATA_DIR` env var instead of
  the process's working directory, in both `main.py` and `enhancements.py`.
* Socket.IO CORS is now driven by a `CORS_ORIGINS` env var instead of a
  hardcoded `*`.
* Session cookies get `Secure` automatically when `RAILWAY_ENVIRONMENT`
  is present (Railway sets this for you — don't set it yourself).

### Steps

1. Push this folder to a GitHub repo, then in Railway: **New Project → Deploy from GitHub repo**.
2. **Add a Volume** to the service (Settings → Volumes) and mount it at `/data`.
   Without this, every redeploy wipes the database and every hosted user's files.
3. Set variables (Settings → Variables) — see `.env.example` for the full list:
   - `SESSION_SECRET` — a fixed random string (required, or sessions reset on every redeploy)
   - `DATA_DIR` = `/data` (matches the volume mount path)
   - `CORS_ORIGINS` — set once Railway gives you a domain, to lock this down from `*`
4. Railway auto-detects Python via `requirements.txt` (Nixpacks) and uses the
   `Procfile` (`web: python main.py`) as the start command — `railway.json`
   pins this explicitly along with an auto-restart policy.
5. Deploy. Once live, go to Settings → Networking → **Generate Domain**, then
   go back and set `CORS_ORIGINS` to that domain and redeploy.

## Deploying on PythonAnywhere

1. Upload the folder (or `git pull`).
2. In a Bash console:
   ```bash
   cd hosting_panel
   pip install --user -r requirements.txt
   ```
3. In the **Web** tab, point your WSGI file at `main:app` (unchanged).
4. Ensure the **Working directory** is `/home/<you>/hosting_panel` so `storage/` is created next to the code.
5. Reload the web app.

PythonAnywhere Free notes:
- WebSocket is not always available — the panel silently falls back to HTTP polling every 2.5 s for the terminal and every 3 s for stats. All features stay functional.
- No Docker, no root, no privileged ports required.
- `pip install --user` is used for in-panel package installs, matching PA conventions.

## API additions (quick reference)

| Method | Path | Purpose |
|---|---|---|
| GET | `/ai/analyze/<folder>` | AI diagnoses of recent console output |
| POST | `/ai/quickfix/<folder>` | Top diagnosis only |
| GET | `/server/processes/<folder>` | List root + child processes |
| POST | `/server/kill-pid/<folder>` | Kill a single PID (CSRF) |
| GET/POST | `/server/autorestart/<folder>` | Read/toggle auto-restart |
| POST | `/server/backup/<folder>` | Create a backup (CSRF) |
| GET | `/server/backups/<folder>` | List backups |
| GET | `/server/backup-download/<folder>/<name>` | Download a backup |
| POST | `/server/backup-restore/<folder>` | Restore a backup (CSRF) |
| POST | `/server/backup-delete/<folder>` | Delete a backup (CSRF) |
| POST | `/server/clone/<folder>` | Clone server (CSRF) |
| POST | `/admin/transfer-server/<sid>` | Change owner (admin, CSRF) |
| GET | `/admin/download-server/<sid>` | Admin ZIP download |
| POST | `/admin/force/<start\|stop\|restart>/<sid>` | Admin force action |
| GET | `/admin/login-history` | Recent login events |
| GET | `/admin/dashboard-stats` | Cached admin headline stats |

Socket.IO events: `term:subscribe`, `term:unsubscribe`, `term:data`, `term:diagnosis`, `stats:subscribe`, `stats:data`, `panel:hello`.

## Backwards compatibility

Nothing was renamed or removed. Every existing route, template, session flow, CSRF flow, and security helper works exactly as before. The upgrade is fully **additive**: if you disable `enhancements.py` (rename or delete it), the panel keeps running with its original feature set.
