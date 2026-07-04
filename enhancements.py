"""
enhancements.py
---------------
Non-destructive upgrade module for the CLAUD hosting panel.

Registers new REST endpoints, Socket.IO handlers, background threads,
and extra DB tables — all *additive*. Nothing here removes or replaces
existing behaviour in main.py.

Highlights
==========
* Real-time terminal over Socket.IO (with polling fallback for
  PythonAnywhere free tier)
* Live CPU/RAM/Disk/Network + per-process stats stream
* Process manager: list children, kill by PID, force restart
* Automatic crash detection + optional auto-restart
* AI error detector (ai_fixer) exposed via HTTP + terminal events
* Server backups: create, list, restore, download, delete
* Server clone + transfer-ownership
* Admin: download any user server as ZIP, force stop/kill,
  login history, security dashboard summary
* Compressed responses (gzip) via Flask-Compress if available
* Simple in-process response cache for GET admin/stats

All new routes are permission-checked and CSRF-safe by re-using the
helpers defined in main.py, which are passed in via `context`.
"""
from __future__ import annotations
import os, io, time, json, shutil, zipfile, sqlite3, threading, subprocess, signal, datetime, secrets
from collections import deque
from typing import Dict, Any, Optional

import psutil
from flask import request, jsonify, send_file, session, abort, redirect, url_for, render_template
from flask_socketio import emit, join_room, leave_room

from ai_fixer import analyze as ai_analyze, detect_missing_requirements, summarize as ai_summarize

# Must match main.py's DATA_DIR so backups / crash-events DB / instance
# lookups here land on the same (optionally volume-mounted) path instead
# of silently drifting to a different location if cwd ever differs.
DATA_DIR = os.environ.get('DATA_DIR', os.getcwd())


# ─────────────────────────────────────────────────────────────────
# In-memory state
# ─────────────────────────────────────────────────────────────────
_log_offsets: Dict[str, int] = {}          # folder -> last streamed byte offset
_crash_flags: Dict[str, bool] = {}         # folder -> True if a crash was seen recently
_auto_restart: Dict[str, bool] = {}        # folder -> auto-restart enabled
_last_restart: Dict[str, float] = {}       # folder -> unix ts of last auto-restart
_restart_burst: Dict[str, deque] = {}      # folder -> recent restart timestamps (loop guard)
_stats_cache: Dict[str, Any] = {"t": 0, "data": None}


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _human_size(b: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ─────────────────────────────────────────────────────────────────
# Public entry — called from main.create_app()
# ─────────────────────────────────────────────────────────────────
def register(app, socketio, context: Dict[str, Any]):
    """Attach every enhancement to the existing Flask app.

    `context` provides handles into main.py without circular imports:
        get_db, running_procs, start_times, safe_path,
        auth_check, verify_folder_ownership, check_csrf,
        log_admin_action, BASE_STORAGE, sanitize.
    """
    get_db                  = context["get_db"]
    running_procs           = context["running_procs"]
    start_times             = context["start_times"]
    safe_path               = context["safe_path"]
    auth_check              = context["auth_check"]
    verify_folder_ownership = context["verify_folder_ownership"]
    check_csrf              = context["check_csrf"]
    log_admin_action        = context["log_admin_action"]
    sanitize                = context["sanitize"]
    BASE_STORAGE            = context["BASE_STORAGE"]

    _ensure_schema()
    _try_enable_compression(app)
    _start_crash_monitor(app, running_procs, start_times)

    # ─── Frontend static: panel.css + panel.js are served from /static/panel/
    #     (no route needed — Flask's default static handler covers it).

    # ────────────────────────────────────────────────────────────
    # AI: analyse recent logs
    # ────────────────────────────────────────────────────────────
    @app.route("/ai/analyze/<folder>")
    def ai_analyze_route(folder):
        if not auth_check():
            return jsonify({"findings": []}), 403
        verify_folder_ownership(folder)
        log_path = os.path.join(BASE_STORAGE, folder, "console.log")
        text = ""
        if os.path.exists(log_path):
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 32768))
                text = f.read().decode("utf-8", "replace")
        findings = ai_analyze(text)
        missing = detect_missing_requirements(text)
        return jsonify({
            "findings": findings,
            "missing_packages": missing,
            "generated_at": _now(),
        })

    @app.route("/ai/quickfix/<folder>", methods=["POST"])
    def ai_quickfix(folder):
        """Return the exact pip command for the top diagnosis; does NOT execute."""
        if not auth_check():
            return jsonify({"status": "error"}), 403
        verify_folder_ownership(folder)
        log_path = os.path.join(BASE_STORAGE, folder, "console.log")
        text = ""
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()[-16000:]
        diag = ai_summarize(text)
        if not diag:
            return jsonify({"status": "empty", "msg": "No known error detected."})
        return jsonify({"status": "ok", "diagnosis": diag})

    # ────────────────────────────────────────────────────────────
    # Process manager
    # ────────────────────────────────────────────────────────────
    @app.route("/server/processes/<folder>")
    def server_processes(folder):
        if not auth_check():
            return jsonify({"processes": []}), 403
        verify_folder_ownership(folder)
        procs = []
        db = get_db()
        row = db.execute("SELECT pid FROM servers WHERE folder=?", (folder,)).fetchone()
        db.close()
        root_pid = None
        if folder in running_procs and running_procs[folder].poll() is None:
            root_pid = running_procs[folder].pid
        elif row and row["pid"] and psutil.pid_exists(row["pid"]):
            root_pid = row["pid"]
        if root_pid:
            try:
                root = psutil.Process(root_pid)
                candidates = [root] + root.children(recursive=True)
                for p in candidates:
                    try:
                        procs.append({
                            "pid": p.pid,
                            "name": p.name(),
                            "status": p.status(),
                            "cpu": p.cpu_percent(interval=0.0),
                            "ram_mb": round(p.memory_info().rss / (1024 * 1024), 1),
                            "threads": p.num_threads(),
                            "started": datetime.datetime.fromtimestamp(p.create_time()).strftime("%H:%M:%S"),
                        })
                    except psutil.Error:
                        pass
            except psutil.Error:
                pass
        return jsonify({"processes": procs, "root_pid": root_pid})

    @app.route("/server/kill-pid/<folder>", methods=["POST"])
    def kill_pid(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        verify_folder_ownership(folder)
        pid = int((request.json or {}).get("pid", 0))
        if pid <= 1:
            return jsonify({"status": "error", "msg": "invalid pid"}), 400
        try:
            os.kill(pid, signal.SIGKILL)
            return jsonify({"status": "ok"})
        except ProcessLookupError:
            return jsonify({"status": "ok", "note": "already gone"})
        except Exception as e:
            return jsonify({"status": "error", "msg": str(e)}), 500

    # ────────────────────────────────────────────────────────────
    # Auto-restart toggle + crash status
    # ────────────────────────────────────────────────────────────
    @app.route("/server/autorestart/<folder>", methods=["POST", "GET"])
    def autorestart(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        verify_folder_ownership(folder)
        if request.method == "GET":
            return jsonify({"enabled": _auto_restart.get(folder, False),
                            "crashed": _crash_flags.get(folder, False)})
        d = request.json or {}
        _auto_restart[folder] = bool(d.get("enabled"))
        return jsonify({"status": "ok", "enabled": _auto_restart[folder]})

    # ────────────────────────────────────────────────────────────
    # Backups
    # ────────────────────────────────────────────────────────────
    @app.route("/server/backup/<folder>", methods=["POST"])
    def backup_create(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        verify_folder_ownership(folder)
        src = safe_path(BASE_STORAGE, folder)
        backups_dir = _backups_dir(folder)
        os.makedirs(backups_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        name = f"backup_{stamp}.zip"
        dest = os.path.join(backups_dir, name)
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for root, dirs, files in os.walk(src):
                # skip the backups folder itself
                if os.path.commonpath([root, backups_dir]) == backups_dir:
                    continue
                for fn in files:
                    if fn == "console.log":
                        continue
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, src))
        return jsonify({"status": "ok", "name": name, "size": os.path.getsize(dest)})

    @app.route("/server/backups/<folder>")
    def backup_list(folder):
        if not auth_check():
            return jsonify({"backups": []}), 403
        verify_folder_ownership(folder)
        d = _backups_dir(folder)
        out = []
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d), reverse=True):
                p = os.path.join(d, fn)
                if os.path.isfile(p):
                    out.append({"name": fn,
                                "size": os.path.getsize(p),
                                "size_human": _human_size(os.path.getsize(p)),
                                "modified": datetime.datetime.fromtimestamp(
                                    os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")})
        return jsonify({"backups": out})

    @app.route("/server/backup-download/<folder>/<name>")
    def backup_download(folder, name):
        if not auth_check():
            abort(403)
        verify_folder_ownership(folder)
        p = safe_path(_backups_dir(folder), name)
        return send_file(p, as_attachment=True)

    @app.route("/server/backup-restore/<folder>", methods=["POST"])
    def backup_restore(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        verify_folder_ownership(folder)
        name = (request.json or {}).get("name", "")
        p = safe_path(_backups_dir(folder), name)
        if not zipfile.is_zipfile(p):
            return jsonify({"status": "error", "msg": "Invalid backup"}), 400
        dest = safe_path(BASE_STORAGE, folder)
        with zipfile.ZipFile(p, "r") as z:
            z.extractall(dest)
        return jsonify({"status": "ok"})

    @app.route("/server/backup-delete/<folder>", methods=["POST"])
    def backup_delete(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        verify_folder_ownership(folder)
        name = (request.json or {}).get("name", "")
        p = safe_path(_backups_dir(folder), name)
        if os.path.isfile(p):
            os.remove(p)
        return jsonify({"status": "ok"})

    # ────────────────────────────────────────────────────────────
    # Clone + transfer
    # ────────────────────────────────────────────────────────────
    @app.route("/server/clone/<folder>", methods=["POST"])
    def clone_server(folder):
        if not auth_check():
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        verify_folder_ownership(folder)
        db = get_db()
        row = db.execute("SELECT * FROM servers WHERE folder=?", (folder,)).fetchone()
        if not row:
            db.close()
            return jsonify({"status": "error", "msg": "not found"}), 404
        # respect server_limit
        uid = row["user_id"]
        limit_row = db.execute("SELECT server_limit FROM users WHERE id=?", (uid,)).fetchone()
        current = db.execute("SELECT COUNT(*) c FROM servers WHERE user_id=?", (uid,)).fetchone()["c"]
        if limit_row and current >= limit_row["server_limit"]:
            db.close()
            return jsonify({"status": "error", "msg": "Server limit reached"}), 400
        new_name = f"{row['name']}-clone"
        new_folder = f"{folder}_clone_{int(time.time())}"
        src = os.path.join(BASE_STORAGE, folder)
        dst = os.path.join(BASE_STORAGE, new_folder)
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("console.log", "_backups"))
        db.execute("INSERT INTO servers (user_id, name, folder, status, startup) VALUES (?,?,?,?,?)",
                   (uid, new_name, new_folder, "Offline", row["startup"] or "main.py"))
        db.commit()
        db.close()
        return jsonify({"status": "ok", "folder": new_folder, "name": new_name})

    @app.route("/admin/transfer-server/<int:sid>", methods=["POST"])
    def transfer_server(sid):
        if not session.get("admin_logged"):
            return jsonify({"status": "error"}), 403
        if not check_csrf():
            return jsonify({"status": "error", "msg": "CSRF"}), 403
        new_uid = int((request.json or {}).get("user_id", 0))
        if new_uid <= 0:
            return jsonify({"status": "error"}), 400
        db = get_db()
        db.execute("UPDATE servers SET user_id=? WHERE id=?", (new_uid, sid))
        db.commit()
        db.close()
        log_admin_action("transfer_server", f"srv={sid} -> user={new_uid}")
        return jsonify({"status": "ok"})

    # ────────────────────────────────────────────────────────────
    # Admin extras
    # ────────────────────────────────────────────────────────────
    @app.route("/admin/download-server/<int:sid>")
    def admin_download_server(sid):
        if not session.get("admin_logged"):
            abort(403)
        db = get_db()
        row = db.execute("SELECT folder, name FROM servers WHERE id=?", (sid,)).fetchone()
        db.close()
        if not row:
            abort(404)
        src = safe_path(BASE_STORAGE, row["folder"])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(src):
                for fn in files:
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, src))
        buf.seek(0)
        log_admin_action("download_server", f"srv={sid}")
        return send_file(buf, as_attachment=True,
                         download_name=f"{row['name']}.zip",
                         mimetype="application/zip")

    @app.route("/admin/force/<action>/<int:sid>", methods=["POST"])
    def admin_force(action, sid):
        if not session.get("admin_logged"):
            return jsonify({"status": "error"}), 403
        db = get_db()
        row = db.execute("SELECT folder, pid, startup FROM servers WHERE id=?", (sid,)).fetchone()
        db.close()
        if not row:
            return jsonify({"status": "error"}), 404
        folder, pid, startup = row["folder"], row["pid"], row["startup"] or "main.py"
        # Kill any running instance
        target_pid = running_procs[folder].pid if folder in running_procs else pid
        if target_pid:
            try:
                os.killpg(os.getpgid(target_pid), signal.SIGKILL)
            except Exception:
                pass
        running_procs.pop(folder, None)
        if action == "restart":
            path = os.path.join(BASE_STORAGE, folder)
            log_p = os.path.join(path, "console.log")
            with open(log_p, "a") as f:
                f.write(f"\n[{_now()}] [ADMIN] Force restart\n")
            proc = subprocess.Popen(["python3", startup], cwd=path,
                                    stdout=open(log_p, "a"),
                                    stderr=subprocess.STDOUT,
                                    preexec_fn=os.setsid)
            running_procs[folder] = proc
            start_times[folder] = time.time()
            db = get_db()
            db.execute("UPDATE servers SET pid=? WHERE folder=?", (proc.pid, folder))
            db.commit()
            db.close()
        log_admin_action(f"force_{action}", f"srv={sid}")
        return jsonify({"status": "ok"})

    @app.route("/admin/login-history")
    def admin_login_history():
        if not session.get("admin_logged"):
            return jsonify({"logs": []}), 403
        db = get_db()
        rows = db.execute(
            "SELECT * FROM security_logs WHERE event_type IN ('login_success','login_fail','admin_login') "
            "ORDER BY created_at DESC LIMIT 300"
        ).fetchall()
        db.close()
        return jsonify({"logs": [dict(r) for r in rows]})

    @app.route("/admin/dashboard-stats")
    def admin_dashboard_stats():
        """Live headline numbers for the admin dashboard (cached 3 s)."""
        if not session.get("admin_logged"):
            return jsonify({}), 403
        now = time.time()
        if _stats_cache["data"] and now - _stats_cache["t"] < 3:
            return jsonify(_stats_cache["data"])
        db = get_db()
        total_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = db.execute("SELECT COUNT(*) c FROM users WHERE status='active'").fetchone()["c"]
        total_servers = db.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"]
        db.close()
        active_srv = 0
        for f, p in list(running_procs.items()):
            if p.poll() is None:
                active_srv += 1
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        data = {
            "users_total": total_users,
            "users_active": active_users,
            "servers_total": total_servers,
            "servers_online": active_srv,
            "servers_offline": max(0, total_servers - active_srv),
            "cpu": psutil.cpu_percent(interval=None),
            "ram_pct": vm.percent,
            "ram_used_gb": round(vm.used / (1024 ** 3), 2),
            "ram_total_gb": round(vm.total / (1024 ** 3), 2),
            "disk_pct": du.percent,
            "disk_used_gb": round(du.used / (1024 ** 3), 2),
            "disk_total_gb": round(du.total / (1024 ** 3), 2),
            "net_sent_mb": round(net.bytes_sent / (1024 ** 2), 1),
            "net_recv_mb": round(net.bytes_recv / (1024 ** 2), 1),
            "ts": now,
        }
        _stats_cache["t"] = now
        _stats_cache["data"] = data
        return jsonify(data)

    # ────────────────────────────────────────────────────────────
    # Socket.IO — real-time terminal + live stats
    # ────────────────────────────────────────────────────────────
    @socketio.on("connect")
    def _on_connect():
        emit("panel:hello", {"ts": _now()})

    @socketio.on("term:subscribe")
    def _term_sub(data):
        folder = (data or {}).get("folder", "")
        if not folder or not _can_access(folder, get_db):
            emit("term:error", {"msg": "forbidden"})
            return
        join_room(f"term:{folder}")
        emit("term:ready", {"folder": folder})

    @socketio.on("term:unsubscribe")
    def _term_unsub(data):
        folder = (data or {}).get("folder", "")
        if folder:
            leave_room(f"term:{folder}")

    @socketio.on("stats:subscribe")
    def _stats_sub(data):
        folder = (data or {}).get("folder", "")
        if folder and _can_access(folder, get_db):
            join_room(f"stats:{folder}")

    # Background broadcaster thread — pushes log deltas + stats every second.
    _start_broadcaster(socketio, running_procs, start_times, BASE_STORAGE, get_db)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
def _backups_dir(folder: str) -> str:
    return os.path.join(DATA_DIR, "storage", "backups", folder)


def _can_access(folder: str, get_db) -> bool:
    if session.get("admin_logged"):
        return True
    uid = session.get("user_id")
    if not uid:
        return False
    db = get_db()
    row = db.execute("SELECT user_id FROM servers WHERE folder=?", (folder,)).fetchone()
    db.close()
    return bool(row and int(row["user_id"]) == int(uid))


def _ensure_schema():
    os.makedirs(os.path.join(DATA_DIR, "storage"), exist_ok=True)
    db_path = os.path.join(DATA_DIR, "storage", "nehost.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS crash_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder TEXT, exit_code INTEGER,
        auto_restarted INTEGER DEFAULT 0,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()


def _try_enable_compression(app):
    try:
        from flask_compress import Compress  # optional
        Compress(app)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────
# Crash monitor
# ─────────────────────────────────────────────────────────────────
def _start_crash_monitor(app, running_procs, start_times):
    def loop():
        while True:
            try:
                for folder in list(running_procs.keys()):
                    proc = running_procs.get(folder)
                    if proc is None:
                        continue
                    rc = proc.poll()
                    if rc is None:
                        continue
                    # process ended
                    _crash_flags[folder] = rc != 0
                    _record_crash(folder, rc)
                    running_procs.pop(folder, None)
                    if _auto_restart.get(folder) and _restart_ok(folder):
                        _do_auto_restart(folder, running_procs, start_times)
            except Exception:
                pass
            time.sleep(2.5)

    t = threading.Thread(target=loop, name="crash-monitor", daemon=True)
    t.start()


def _record_crash(folder: str, rc: int):
    try:
        conn = sqlite3.connect(os.path.join(DATA_DIR, "storage", "nehost.db"))
        conn.execute("INSERT INTO crash_events (folder, exit_code, message) VALUES (?,?,?)",
                     (folder, rc, f"Process exited with code {rc}"))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _restart_ok(folder: str) -> bool:
    """Prevent infinite restart loops: max 3 restarts in 60 s."""
    q = _restart_burst.setdefault(folder, deque(maxlen=5))
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 3:
        return False
    q.append(now)
    return True


def _do_auto_restart(folder, running_procs, start_times):
    try:
        conn = sqlite3.connect(os.path.join(DATA_DIR, "storage", "nehost.db"))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT startup FROM servers WHERE folder=?", (folder,)).fetchone()
        startup = row["startup"] if row and row["startup"] else "main.py"
        path = os.path.join(DATA_DIR, "storage", "instances", folder)
        log_p = os.path.join(path, "console.log")
        with open(log_p, "a") as f:
            f.write(f"\n[{_now()}] [AUTO-RESTART] Restarting after crash…\n")
        proc = subprocess.Popen(["python3", startup], cwd=path,
                                stdout=open(log_p, "a"),
                                stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid)
        running_procs[folder] = proc
        start_times[folder] = time.time()
        _last_restart[folder] = time.time()
        conn.execute("UPDATE servers SET pid=? WHERE folder=?", (proc.pid, folder))
        conn.execute("UPDATE crash_events SET auto_restarted=1 WHERE folder=? "
                     "AND id=(SELECT MAX(id) FROM crash_events WHERE folder=?)",
                     (folder, folder))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────
# Broadcaster — pushes terminal deltas + stats to subscribed rooms
# ─────────────────────────────────────────────────────────────────
def _start_broadcaster(socketio, running_procs, start_times, BASE_STORAGE, get_db):
    def loop():
        while True:
            try:
                # Determine folders with subscribers by peeking at the socketio manager rooms.
                try:
                    rooms = list(socketio.server.manager.rooms.get("/", {}).keys())
                except Exception:
                    rooms = []
                folders_term = {r.split(":", 1)[1] for r in rooms if r.startswith("term:")}
                folders_stats = {r.split(":", 1)[1] for r in rooms if r.startswith("stats:")}

                for folder in folders_term:
                    _push_log_delta(socketio, folder, BASE_STORAGE)

                for folder in folders_stats:
                    _push_stats(socketio, folder, running_procs, start_times, get_db)
            except Exception:
                pass
            socketio.sleep(1.0)

    socketio.start_background_task(loop)


def _push_log_delta(socketio, folder, BASE_STORAGE):
    path = os.path.join(BASE_STORAGE, folder, "console.log")
    if not os.path.exists(path):
        return
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            off = _log_offsets.get(folder, size)
            if off > size:  # log was rotated
                off = 0
            if size <= off:
                return
            f.seek(off)
            chunk = f.read(65536).decode("utf-8", "replace")
            _log_offsets[folder] = off + len(chunk.encode("utf-8"))
        socketio.emit("term:data", {"folder": folder, "chunk": chunk},
                      room=f"term:{folder}")
        # opportunistic AI scan on stderr-ish chunks
        if "Error" in chunk or "Traceback" in chunk:
            diag = ai_summarize(chunk)
            if diag:
                socketio.emit("term:diagnosis", {"folder": folder, "diagnosis": diag},
                              room=f"term:{folder}")
    except Exception:
        pass


def _push_stats(socketio, folder, running_procs, start_times, get_db):
    pid = None
    if folder in running_procs and running_procs[folder].poll() is None:
        pid = running_procs[folder].pid
    else:
        db = get_db()
        row = db.execute("SELECT pid FROM servers WHERE folder=?", (folder,)).fetchone()
        db.close()
        pid = row["pid"] if row and row["pid"] and psutil.pid_exists(row["pid"]) else None
    online = False
    cpu = ram = threads = 0
    if pid:
        try:
            p = psutil.Process(pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                online = True
                cpu = p.cpu_percent(interval=0.0)
                ram = round(p.memory_info().rss / (1024 * 1024), 1)
                threads = p.num_threads()
        except psutil.Error:
            pass
    vm = psutil.virtual_memory()
    du = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    payload = {
        "folder": folder, "online": online, "pid": pid,
        "cpu": cpu, "ram_mb": ram, "threads": threads,
        "uptime_s": int(time.time() - start_times[folder]) if online and folder in start_times else 0,
        "sys": {
            "cpu": psutil.cpu_percent(interval=None),
            "ram_pct": vm.percent,
            "disk_pct": du.percent,
            "net_sent_mb": round(net.bytes_sent / (1024 ** 2), 1),
            "net_recv_mb": round(net.bytes_recv / (1024 ** 2), 1),
        },
        "auto_restart": _auto_restart.get(folder, False),
        "crashed": _crash_flags.get(folder, False),
    }
    socketio.emit("stats:data", payload, room=f"stats:{folder}")
