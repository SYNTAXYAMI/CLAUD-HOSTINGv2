"""
AI Error Detector & Auto-Fix Recommender
----------------------------------------
Pure-Python, no external API needed. Scans console output (or a raw error
string) and returns a structured diagnosis: category, human explanation,
recommended fix, and — when applicable — the exact `pip install` command
to run.

Everything here is deterministic pattern matching designed to be *fast*
(safe for PythonAnywhere free tier) and to work offline. It covers the
most common Python runtime failures encountered by hosted apps.
"""
from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

# ─────────────────────────────────────────────────────────────────
# Pattern catalogue
# Each entry: (regex, builder(match) -> diagnosis dict)
# A diagnosis dict has:
#   type, title, explanation, fix, command (optional), confidence (0-100)
# ─────────────────────────────────────────────────────────────────

# Well-known name -> pip package overrides (import name differs from pip name)
IMPORT_TO_PIP = {
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome",
    "dotenv": "python-dotenv",
    "telegram": "python-telegram-bot",
    "discord": "discord.py",
    "google": "google-api-python-client",
    "OpenSSL": "pyOpenSSL",
    "magic": "python-magic",
    "dateutil": "python-dateutil",
    "MySQLdb": "mysqlclient",
    "psycopg2": "psycopg2-binary",
    "serial": "pyserial",
}


def _module_fix(mod: str) -> Dict[str, Any]:
    pkg = IMPORT_TO_PIP.get(mod, mod)
    return {
        "type": "ModuleNotFoundError",
        "title": f"Missing Python module: {mod}",
        "explanation": (
            f"Your app tried to `import {mod}` but the package isn't "
            f"installed in this environment. Install it with pip, then "
            f"restart the server."
        ),
        "fix": f"Install '{pkg}' via pip using the Copy Fix button below.",
        "command": f"pip install --user {pkg}",
        "confidence": 96,
    }


PATTERNS = [
    # ── Missing modules ──────────────────────────────────────────
    (
        re.compile(r"ModuleNotFoundError: No module named ['\"]([\w\.]+)['\"]"),
        lambda m: _module_fix(m.group(1).split(".")[0]),
    ),
    (
        re.compile(r"ImportError: No module named ['\"]?([\w\.]+)['\"]?"),
        lambda m: _module_fix(m.group(1).split(".")[0]),
    ),
    (
        re.compile(r"ImportError: cannot import name ['\"]([^'\"]+)['\"] from ['\"]([^'\"]+)['\"]"),
        lambda m: {
            "type": "ImportError",
            "title": f"Cannot import '{m.group(1)}' from '{m.group(2)}'",
            "explanation": (
                f"'{m.group(1)}' does not exist in the installed version of "
                f"'{m.group(2)}'. This usually means the package is outdated, "
                f"was renamed, or you upgraded past a breaking change."
            ),
            "fix": f"Upgrade '{m.group(2)}' to the latest version.",
            "command": f"pip install --user --upgrade {m.group(2)}",
            "confidence": 85,
        },
    ),
    # ── Syntax ───────────────────────────────────────────────────
    (
        re.compile(r'File "([^"]+)", line (\d+)[\s\S]{0,120}?SyntaxError: (.+)'),
        lambda m: {
            "type": "SyntaxError",
            "title": f"Syntax error in {m.group(1).split('/')[-1]}:{m.group(2)}",
            "explanation": (
                f"Python could not parse this file. Message: {m.group(3).strip()}."
            ),
            "fix": (
                "Open the file in the built-in editor at the reported line "
                "and check for a missing colon, unmatched bracket, or invalid "
                "indentation."
            ),
            "confidence": 92,
        },
    ),
    (
        re.compile(r"IndentationError: (.+)"),
        lambda m: {
            "type": "IndentationError",
            "title": "Indentation error",
            "explanation": f"Python indentation is inconsistent: {m.group(1).strip()}.",
            "fix": "Re-indent the block. Never mix tabs and spaces — pick one.",
            "confidence": 90,
        },
    ),
    # ── Filesystem ───────────────────────────────────────────────
    (
        re.compile(r"FileNotFoundError:.+?['\"]([^'\"]+)['\"]"),
        lambda m: {
            "type": "FileNotFoundError",
            "title": f"File not found: {m.group(1)}",
            "explanation": (
                f"Your code tried to open '{m.group(1)}' but that path does "
                f"not exist in the server folder."
            ),
            "fix": (
                "Upload the file through the File Manager, or fix the path "
                "in your code. Remember paths are relative to the server "
                "folder, not your local machine."
            ),
            "confidence": 94,
        },
    ),
    (
        re.compile(r"PermissionError: \[Errno 13\][^\n]*['\"]?([^'\"\n]+)['\"]?"),
        lambda m: {
            "type": "PermissionError",
            "title": "Permission denied",
            "explanation": (
                f"The process cannot access '{m.group(1).strip()}'. "
                f"On PythonAnywhere this usually means writing outside your "
                f"home directory or opening a system file."
            ),
            "fix": "Write into the server folder only. Do not touch /etc, /var, or another user's files.",
            "confidence": 88,
        },
    ),
    (
        re.compile(r"OSError: \[Errno 28\]"),
        lambda m: {
            "type": "OSError",
            "title": "Disk full",
            "explanation": "The server ran out of disk space while writing a file.",
            "fix": "Delete old logs or unused files from the File Manager, then restart.",
            "confidence": 95,
        },
    ),
    # ── Networking ───────────────────────────────────────────────
    (
        re.compile(r"OSError: \[Errno 98\] Address already in use"),
        lambda m: {
            "type": "PortInUse",
            "title": "Port already in use",
            "explanation": (
                "Another process is already bound to the port your app "
                "wants. This usually means the previous instance didn't "
                "shut down cleanly."
            ),
            "fix": "Click Kill Process, wait 3 seconds, then Restart.",
            "confidence": 93,
        },
    ),
    (
        re.compile(r"ConnectionRefusedError"),
        lambda m: {
            "type": "ConnectionRefusedError",
            "title": "Connection refused",
            "explanation": "Your app tried to reach a service that isn't accepting connections (wrong host/port, or the target is down).",
            "fix": "Verify the host, port, and firewall. On PythonAnywhere free plans, outbound traffic is limited to a whitelist.",
            "confidence": 82,
        },
    ),
    # ── Runtime ──────────────────────────────────────────────────
    (
        re.compile(r"RecursionError: maximum recursion depth exceeded"),
        lambda m: {
            "type": "RecursionError",
            "title": "Infinite recursion",
            "explanation": "A function keeps calling itself without a base case, exhausting the stack.",
            "fix": "Add an exit condition or convert the recursion to an iterative loop.",
            "confidence": 90,
        },
    ),
    (
        re.compile(r"MemoryError"),
        lambda m: {
            "type": "MemoryError",
            "title": "Out of memory",
            "explanation": "The process used more RAM than the environment allows.",
            "fix": "Stream large files instead of loading them fully, or upgrade your plan.",
            "confidence": 85,
        },
    ),
    (
        re.compile(r"KeyError: ['\"]?([^'\"\n]+)['\"]?"),
        lambda m: {
            "type": "KeyError",
            "title": f"Missing key: {m.group(1).strip()}",
            "explanation": f"You accessed dict['{m.group(1).strip()}'] but the key doesn't exist.",
            "fix": "Use dict.get('key') to fall back to None, or check with `if 'key' in dict:` first.",
            "confidence": 80,
        },
    ),
    (
        re.compile(r"TypeError: (.+)"),
        lambda m: {
            "type": "TypeError",
            "title": "Type mismatch",
            "explanation": f"Wrong argument type or wrong number of arguments: {m.group(1).strip()[:140]}.",
            "fix": "Check the function signature at the traceback line and pass the correct type.",
            "confidence": 70,
        },
    ),
    (
        re.compile(r"ValueError: (.+)"),
        lambda m: {
            "type": "ValueError",
            "title": "Invalid value",
            "explanation": f"A function received the right type but a bad value: {m.group(1).strip()[:140]}.",
            "fix": "Validate/normalize inputs before passing them in.",
            "confidence": 65,
        },
    ),
    (
        re.compile(r"AttributeError: (.+)"),
        lambda m: {
            "type": "AttributeError",
            "title": "Missing attribute",
            "explanation": f"{m.group(1).strip()[:160]}",
            "fix": "The object doesn't have that attribute. Check the object type and library version.",
            "confidence": 72,
        },
    ),
    (
        re.compile(r"NameError: name ['\"]?([^'\"\n]+)['\"]? is not defined"),
        lambda m: {
            "type": "NameError",
            "title": f"'{m.group(1)}' is not defined",
            "explanation": "You used a variable or function that was never declared or imported in this scope.",
            "fix": "Import it, define it, or fix the typo.",
            "confidence": 90,
        },
    ),
    (
        re.compile(r"RuntimeError: (.+)"),
        lambda m: {
            "type": "RuntimeError",
            "title": "Runtime error",
            "explanation": f"{m.group(1).strip()[:180]}",
            "fix": "Inspect the traceback in the terminal to find the exact line, then handle the failure explicitly.",
            "confidence": 60,
        },
    ),
    (
        re.compile(r"UnicodeDecodeError"),
        lambda m: {
            "type": "UnicodeDecodeError",
            "title": "Text decode error",
            "explanation": "A file was read as text but contains bytes that aren't valid for the assumed encoding.",
            "fix": "Open the file with encoding='utf-8', errors='replace', or read it as binary ('rb').",
            "confidence": 88,
        },
    ),
    # ── Environment ──────────────────────────────────────────────
    (
        re.compile(r"KeyError: ['\"]([A-Z][A-Z0-9_]+)['\"]"),
        lambda m: {
            "type": "MissingEnv",
            "title": f"Missing environment variable: {m.group(1)}",
            "explanation": f"Your code called os.environ['{m.group(1)}'] but the variable isn't set.",
            "fix": f"Set {m.group(1)} in the panel Environment tab, or use os.environ.get('{m.group(1)}', default).",
            "confidence": 78,
        },
    ),
]


def analyze(log_text: str, max_findings: int = 6) -> List[Dict[str, Any]]:
    """Return de-duplicated diagnoses ordered by confidence."""
    if not log_text:
        return []
    tail = log_text[-16000:]  # only look at recent output
    seen = set()
    out: List[Dict[str, Any]] = []
    for rx, build in PATTERNS:
        for m in rx.finditer(tail):
            try:
                diag = build(m)
            except Exception:
                continue
            key = (diag["type"], diag["title"])
            if key in seen:
                continue
            seen.add(key)
            out.append(diag)
            if len(out) >= max_findings * 2:
                break
    out.sort(key=lambda d: -d.get("confidence", 0))
    return out[:max_findings]


def summarize(log_text: str) -> Optional[Dict[str, Any]]:
    """Return the single highest-confidence diagnosis, or None."""
    findings = analyze(log_text, max_findings=1)
    return findings[0] if findings else None


def detect_missing_requirements(log_text: str) -> List[str]:
    """Return unique pip package names that appear missing based on the log."""
    pkgs: List[str] = []
    for m in re.finditer(r"No module named ['\"]([\w]+)", log_text or ""):
        mod = m.group(1)
        pkg = IMPORT_TO_PIP.get(mod, mod)
        if pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs
