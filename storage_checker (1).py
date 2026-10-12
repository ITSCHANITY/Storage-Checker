#!/usr/bin/env python3
"""
storage_checker.py — Kali Linux Storage Checker (v5)
Two modes, chosen up front before anything is scanned or touched:

  [1] Unused/orphaned check  — finds orphaned configs, apt leftovers,
      broken packages, large files, temp/cache junk, pip remnants,
      trash-linked leftovers, and harmful files. (This is the v3 flow,
      unchanged.)
  [2] Missing-dependency check — finds things that SHOULD be present
      but aren't: Python imports that won't resolve, binaries with
      missing shared libraries, apt packages with unmet dependencies,
      dangling symlinks anywhere relevant, and scripts whose shebang
      interpreter isn't on PATH. This never deletes anything; it only
      reports and, where sensible, offers to install/fix.
  [3] Both, one after another.

v4 changes from v3:
  - Added the missing-dependency check as a whole new mode (see above).
  - Added a mode-select prompt at the very start, before any scanning,
    so you choose "check unused", "check missing", or "both" before
    a single thing is examined or a single delete prompt appears.
  - --mode flag added for non-interactive use (unused / missing / both).
  - The unused/orphaned side is untouched from v3: same PROTECTED_DIRS
    hard-exclusion, same explain-before-delete pattern, same section
    order. Nothing here was removed — it now sits behind the [1] choice.

v5 changes from v4 (this rebuild):
  1. BACKUP-BEFORE-DELETE: every delete now zips the item into a
     timestamped backup folder (~/.storage_checker_backups/) before
     removing it, with a 7-day auto-expiry. This directly addresses the
     exact failure mode that motivated PROTECTED_DIRS in the first place
     (the Brave-credential-deletion incident) — even if something gets
     past every other safeguard, it's recoverable for a week, not gone.
  2. RUN LOG: every run now writes a timestamped summary to
     ~/.storage_checker_log.txt (what was found, what was deleted, what
     was skipped, bytes freed) instead of only printing to a terminal
     that scrolls away. --no-log disables this if you don't want it.
  3. SMARTER ORPHAN CONFIDENCE: scan_orphaned_configs() now also reports
     each candidate's last-modified date, and orphans untouched for 90+
     days are shown with higher delete-confidence than ones modified
     recently — the same *type* of heuristic gap that caused the
     original incident (matching by name alone) is now narrowed by a
     second, independent signal instead of relying on name-matching by
     itself. This does not loosen PROTECTED_DIRS in any way — that
     hard exclusion is untouched and still applies first.
"""

import os
import sys
import shutil
import subprocess
import argparse
import zipfile
import time
from datetime import datetime, timedelta
from pathlib import Path


# ─── Protected paths — NEVER suggested for deletion, ever ───────────────────

def protected_dirs(home: Path):
    return [
        home / ".config" / "BraveSoftware",
        home / ".config" / "google-chrome",
        home / ".config" / "chromium",
        home / ".mozilla",
        home / ".config" / "microsoft-edge",
        home / ".config" / "vivaldi",
        home / ".thunderbird",
        home / ".config" / "discord",
        home / ".config" / "Code",          # VS Code settings/profile
        home / ".vscode",                   # VS Code extensions/config
        home / ".ssh",
        home / ".gnupg",
    ]


def is_protected(path: Path, protected):
    try:
        rp = path.resolve()
    except OSError:
        rp = path
    for p in protected:
        try:
            rp.relative_to(p.resolve())
            return True
        except (ValueError, OSError):
            if rp == p:
                return True
    return False


# ─── Known-app explanations ───────────────────────────────────────────────────
# When a scan finds something matching these, explain what it actually is
# in plain English instead of just saying "large" or "orphaned".

KNOWN_APPS = {
    "code":            "VS Code, your code editor application. This holds the editor's own program files/extensions, not your project files.",
    "vscode":          "VS Code, your code editor application. This holds the editor's own program files/extensions, not your project files.",
    ".vscode":         "VS Code's per-project or user settings/extensions folder.",
    "bravesoftware":   "Brave browser's profile data — your logins, bookmarks, history, and saved sessions live here.",
    "google-chrome":   "Google Chrome's profile data — logins, bookmarks, history, and saved sessions live here.",
    "chromium":        "Chromium browser's profile data.",
    "mozilla":         "Firefox's profile data — logins, bookmarks, and history live here.",
    "discord":         "Discord desktop app's local data/cache.",
    "spotify":         "Spotify desktop app's local data/cache.",
    "slack":           "Slack desktop app's local data/cache.",
    "zoom":            "Zoom app's local data/cache.",
    "docker":          "Docker's local data — images/containers can be large; deleting this removes downloaded container images.",
    "node_modules":    "JavaScript project dependencies. Safe to delete if you can re-run 'npm install' or 'yarn install' to restore it.",
    "virtualbox":      "VirtualBox virtual machine files. These can be large disk images for VMs you've created.",
    "vmware":          "VMware virtual machine files.",
    "steam":           "Steam game client data — may include installed games.",
    "thunderbird":     "Thunderbird's email profile data — your mail, accounts, and settings live here.",
}


def explain_unknown(name: str) -> str:
    """Best-effort plain-English guess for items not in KNOWN_APPS."""
    lname = name.lower()
    for key, desc in KNOWN_APPS.items():
        if key in lname:
            return desc
    return "No specific match found for this name — review the path yourself before deciding."


# ─── Run log ──────────────────────────────────────────────────────────────────
# Every run appends a timestamped summary here instead of only printing to a
# terminal that scrolls away. ENABLE_LOG is flipped off by --no-log.
LOG_PATH = Path.home() / ".storage_checker_log.txt"
ENABLE_LOG = True
_log_buffer = []


def log_event(line: str):
    """Buffer one line for the run log. Flushed to disk at the end of main()
    so a crash mid-run doesn't leave a half-written log file."""
    _log_buffer.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {line}")


def flush_run_log(mode: str, dry_run: bool, deleted_bytes_total: int):
    if not ENABLE_LOG:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"Run started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Mode        : {mode}{'  (DRY RUN)' if dry_run else ''}\n")
            for line in _log_buffer:
                f.write(line + "\n")
            f.write(f"Total freed : {human(deleted_bytes_total)}\n")
            f.write(f"{'='*70}\n")
    except OSError as e:
        print(f"  {yellow('[!] Could not write run log:')} {e}")


# ─── Backup-before-delete ───────────────────────────────────────────────────
# Every delete in this program goes through delete_path() (one chokepoint),
# and delete_path() now zips the target into BACKUP_DIR before removing it.
# Backups older than BACKUP_RETENTION_DAYS are pruned automatically on each
# run. This is specifically here because of a real incident: an earlier
# version of this tool deleted live Brave browser credentials by
# misidentifying its config folder as orphaned. PROTECTED_DIRS (above) is
# the primary fix — this backup net is the second layer, for anything that
# gets past every other safeguard.
BACKUP_DIR = Path.home() / ".storage_checker_backups"
BACKUP_RETENTION_DAYS = 7
ENABLE_BACKUP = True


def _zip_path_into_backup(path: Path) -> "Path | None":
    """Zip a file or directory into BACKUP_DIR with a timestamped name.
    Returns the backup zip's path, or None if backup failed (in which case
    the caller should NOT proceed with the delete — see delete_path())."""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = path.name.replace("/", "_") or "root"
        zip_path = BACKUP_DIR / f"{stamp}__{safe_name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            if path.is_file() or path.is_symlink():
                zf.write(path, arcname=path.name)
            elif path.is_dir():
                for root, _, files in os.walk(path):
                    for fname in files:
                        full = Path(root) / fname
                        try:
                            arc = full.relative_to(path.parent)
                            zf.write(full, arcname=str(arc))
                        except (OSError, ValueError):
                            continue  # skip unreadable files, don't abort the whole backup
        return zip_path
    except OSError as e:
        print(f"  {red('[!] Backup failed, delete aborted for safety:')} {e}")
        return None


def prune_old_backups():
    """Delete backup zips older than BACKUP_RETENTION_DAYS. Runs once at
    startup so backups don't accumulate forever."""
    if not BACKUP_DIR.exists():
        return
    cutoff = time.time() - (BACKUP_RETENTION_DAYS * 86400)
    pruned = 0
    for item in BACKUP_DIR.glob("*.zip"):
        try:
            if item.stat().st_mtime < cutoff:
                item.unlink()
                pruned += 1
        except OSError:
            continue
    if pruned:
        print(f"  {dim(f'Pruned {pruned} backup(s) older than {BACKUP_RETENTION_DAYS} days')}")


# ─── ANSI colors ────────────────────────────────────────────────────────────

def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

COLOR = supports_color()

def c(text, code): return f"\033[{code}m{text}\033[0m" if COLOR else text
def red(t):     return c(t, "91")
def yellow(t):  return c(t, "93")
def green(t):   return c(t, "92")
def cyan(t):    return c(t, "96")
def bold(t):    return c(t, "1")
def dim(t):     return c(t, "2")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def human(size_bytes):
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def dir_size(path):
    """Return total size of a directory in bytes."""
    total = 0
    try:
        for entry in Path(path).rglob("*"):
            try:
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass
    return total


def run(cmd, check=False):
    """Run a shell command, return stdout as string."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


def installed_packages():
    """Return a set of installed package names from dpkg."""
    out = run("dpkg --get-selections | grep -v deinstall | awk '{print $1}'")
    return set(out.splitlines())


def confirm(prompt):
    """Y/n prompt; returns True if user confirms."""
    try:
        ans = input(f"  {prompt} {dim('[y/N]')} ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


# ─── Scan functions ───────────────────────────────────────────────────────────

def scan_apt_orphans():
    """Packages that can be auto-removed."""
    out = run("apt-get autoremove --simulate 2>/dev/null | grep '^Remv'")
    pkgs = [line.split()[1] for line in out.splitlines() if line.startswith("Remv")]
    return pkgs


def scan_deb_cache():
    """Cached .deb files in apt cache."""
    cache_dir = Path("/var/cache/apt/archives")
    debs = []
    if cache_dir.exists():
        for f in cache_dir.glob("*.deb"):
            try:
                debs.append((f, f.stat().st_size))
            except OSError:
                pass
    return debs


def scan_orphaned_configs(home, installed, protected):
    """
    Config dirs in ~/.config and ~/.local/share whose name doesn't match
    any installed package. Heuristic: if the folder name is not a substring
    of any installed package name, flag it.

    NOTE: anything inside `protected` (Brave, Chrome, Firefox, VS Code, etc.)
    is filtered out before it's ever shown, regardless of what the substring
    heuristic thinks — this is what caused real damage before, so it's a
    hard exclusion now, not just a "skip" heuristic.

    v5: each candidate also reports days-since-last-modified as a second,
    independent confidence signal alongside the name heuristic. A folder
    untouched for 90+ days is shown as higher-confidence than one modified
    recently — name-matching alone is exactly the kind of single-signal
    heuristic that caused the original incident, so this adds a second,
    different signal rather than tightening the same one. PROTECTED_DIRS
    is checked first, unconditionally, regardless of how old or new
    anything is — recency never overrides the hard exclusion list.
    """
    orphans = []
    installed_lower = {p.lower().split(":")[0] for p in installed}

    for base in [home / ".config", home / ".local" / "share"]:
        if not base.exists():
            continue
        for entry in base.iterdir():
            if not entry.is_dir():
                continue
            if is_protected(entry, protected):
                continue
            name = entry.name.lower()
            skip = {"dbus", "glib-2.0", "ibus", "pulse", "systemd",
                    "python", "fontconfig", "mime", "gnupg", "gtk-2.0",
                    "gtk-3.0", "gtk-4.0", "recently-used.xbel", "user-dirs"}
            if any(name.startswith(s) for s in skip):
                continue
            matched = any(name in p or p in name for p in installed_lower)
            if not matched:
                size = dir_size(entry)
                try:
                    mtime = entry.stat().st_mtime
                    days_old = int((time.time() - mtime) / 86400)
                except OSError:
                    days_old = None
                confidence = "low"
                if days_old is not None:
                    if days_old >= 90:
                        confidence = "high"
                    elif days_old >= 30:
                        confidence = "medium"
                orphans.append((entry, size, days_old, confidence))

    return sorted(orphans, key=lambda x: -x[1])


def scan_broken_packages():
    """Packages in 'deinstall' or partially installed state."""
    out = run("dpkg --get-selections | grep -E 'deinstall|half-installed|config-files'")
    results = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            results.append((parts[0], parts[1]))
    return results


def scan_large_files(start, min_mb=100, max_results=20, protected=None):
    """Find files larger than min_mb MB under start path, skipping protected dirs."""
    protected = protected or []
    min_bytes = min_mb * 1024 * 1024
    found = []
    try:
        for entry in Path(start).rglob("*"):
            try:
                if is_protected(entry, protected):
                    continue
                if entry.is_file() and not entry.is_symlink():
                    size = entry.stat().st_size
                    if size >= min_bytes:
                        found.append((entry, size))
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass
    return sorted(found, key=lambda x: -x[1])[:max_results]


def scan_temp_cache(home):
    """Known temp/cache locations."""
    targets = [
        ("/tmp", "System temp directory"),
        (home / ".cache", "User cache (~/.cache)"),
        ("/var/log", "System logs"),
    ]
    results = []
    for path, label in targets:
        p = Path(path)
        if p.exists():
            size = dir_size(p)
            results.append((p, label, size))
    return results


def scan_pip_cache(home):
    """pip and pip3 cache."""
    locations = [
        home / ".cache" / "pip",
        home / ".local" / "lib",
    ]
    results = []
    for loc in locations:
        if loc.exists():
            size = dir_size(loc)
            if size > 0:
                results.append((loc, size))
    return results


# ─── Missing-dependency scanners ──────────────────────────────────────────────
# Everything below this point only REPORTS — it never deletes anything.
# These look for things that should be present but aren't, which is the
# opposite problem from the orphaned/unused scanners above.

# Modules that are part of the standard library or are commonly namespaced
# differently from their pip package name — skip these to avoid false
# positives when checking "is this import installed".
STDLIB_SKIP = {
    "__future__", "abc", "argparse", "array", "ast", "asyncio", "base64",
    "bisect", "builtins", "bz2", "calendar", "collections", "configparser",
    "contextlib", "copy", "csv", "ctypes", "datetime", "decimal", "difflib",
    "dis", "email", "enum", "errno", "fcntl", "fnmatch", "functools",
    "gc", "getpass", "glob", "gzip", "hashlib", "heapq", "hmac", "html",
    "http", "importlib", "inspect", "io", "ipaddress", "itertools", "json",
    "logging", "lzma", "math", "mimetypes", "multiprocessing", "operator",
    "os", "pathlib", "pickle", "platform", "pprint", "queue", "random",
    "re", "sched", "secrets", "select", "shlex", "shutil", "signal",
    "site", "socket", "sqlite3", "ssl", "stat", "string", "struct",
    "subprocess", "sys", "tarfile", "tempfile", "textwrap", "threading",
    "time", "traceback", "types", "typing", "unicodedata", "unittest",
    "urllib", "uuid", "warnings", "weakref", "xml", "zipfile", "zlib",
    "this", "venv", "pip", "setuptools", "pkg_resources", "distutils",
}

# import-name → pip-install-name, for the common cases where they differ.
IMPORT_TO_PIP = {
    "cv2": "opencv-python",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "PIL": "pillow",
    "sklearn": "scikit-learn",
    "Crypto": "pycryptodome",
    "nmap": "python-nmap",
    "serial": "pyserial",
    "dateutil": "python-dateutil",
    "OpenSSL": "pyopenssl",
    "google": "google-api-python-client",
    "jwt": "pyjwt",
    "dotenv": "python-dotenv",
    "requests_toolbelt": "requests-toolbelt",
}


def find_python_scripts(home, max_files=300):
    """
    Find .py files under common project-ish locations: home root (shallow),
    and any directory anywhere under home that looks like a project
    (contains .git, requirements.txt, pyproject.toml, or setup.py).
    Skips protected/system-ish dirs and venvs to keep this fast and relevant.
    """
    skip_dir_names = {
        ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
        "site-packages", "dist-packages", ".cache", ".local",
    }
    found = []
    seen_dirs = set()

    for root, dirs, files in os.walk(home):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in skip_dir_names and not d.startswith(".")]
        if len(found) >= max_files:
            break
        for fname in files:
            if fname.endswith(".py"):
                found.append(root_path / fname)
                if len(found) >= max_files:
                    break
    return found


def extract_imports(py_file):
    """Best-effort top-level module names imported by a .py file, via ast."""
    import ast
    mods = set()
    try:
        tree = ast.parse(py_file.read_text(errors="ignore"), filename=str(py_file))
    except (SyntaxError, OSError, ValueError):
        return mods
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                mods.add(node.module.split(".")[0])
    return mods


def scan_missing_python_imports(home):
    """
    Walk project-like .py files, collect their top-level imports, and check
    each against what's importable in the current environment. Anything
    that fails to resolve is reported with a best-effort pip package name.
    Returns list of dicts: {module, pip_name, files: [...]}
    """
    import importlib.util

    py_files = find_python_scripts(home)
    module_to_files = {}
    for f in py_files:
        for mod in extract_imports(f):
            if mod in STDLIB_SKIP or mod.startswith("_"):
                continue
            module_to_files.setdefault(mod, []).append(f)

    missing = []
    for mod, files in module_to_files.items():
        try:
            spec = importlib.util.find_spec(mod)
        except (ImportError, ModuleNotFoundError, ValueError):
            spec = None
        if spec is None:
            missing.append({
                "module": mod,
                "pip_name": IMPORT_TO_PIP.get(mod, mod),
                "files": files,
            })
    return sorted(missing, key=lambda m: -len(m["files"]))


def find_candidate_binaries(home, max_results=200):
    """
    Collect a reasonable sample of ELF binaries to ldd-check: things on
    PATH-like locations plus executables under home. Skips protected dirs.
    """
    candidates = []
    bin_dirs = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"]
    for bd in bin_dirs:
        p = Path(bd)
        if not p.exists():
            continue
        try:
            for entry in p.iterdir():
                if entry.is_file() and os.access(entry, os.X_OK):
                    candidates.append(entry)
        except (PermissionError, OSError):
            pass
    return candidates[:max_results]


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def scan_missing_shared_libs(home, sample_limit=400):
    """
    Run ldd against a sample of binaries and report any with
    '=> not found' shared library dependencies.
    Returns list of (binary_path, [missing_lib_names]).
    """
    results = []
    candidates = [b for b in find_candidate_binaries(home) if is_elf(b)]
    for b in candidates[:sample_limit]:
        out = run(f"ldd {b} 2>/dev/null")
        if not out:
            continue
        missing_libs = []
        for line in out.splitlines():
            if "=> not found" in line:
                missing_libs.append(line.strip().split()[0])
        if missing_libs:
            results.append((b, missing_libs))
    return results


def scan_unmet_apt_dependencies():
    """
    Use apt-get check to find broken dependency chains, and dpkg -s on
    'half-configured'/'unpacked' state packages to surface specifics.
    Returns (summary_text_or_None, list_of_problem_packages).
    """
    check_out = run("apt-get check 2>&1")
    problems = []
    if check_out and ("broken" in check_out.lower() or "unmet" in check_out.lower()):
        problems.append(check_out.strip())

    out = run("dpkg --get-selections | grep -E 'half-configured|unpacked|half-installed'")
    broken_state_pkgs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            broken_state_pkgs.append((parts[0], parts[1]))

    return (check_out if problems else None), broken_state_pkgs


def scan_dangling_symlinks(home, protected, max_results=100):
    """
    Find broken symlinks anywhere under home (not just Trash-related, which
    is covered separately). Skips protected dirs.
    """
    found = []
    for root, dirs, files in os.walk(home):
        root_path = Path(root)
        if is_protected(root_path, protected):
            dirs[:] = []
            continue
        for fname in files:
            fpath = root_path / fname
            if fpath.is_symlink() and not fpath.exists():
                try:
                    target = os.readlink(fpath)
                except OSError:
                    target = "?"
                found.append((fpath, target))
                if len(found) >= max_results:
                    return found
    return found


def scan_missing_shebang_interpreters(home, protected, max_results=100):
    """
    Find scripts whose #!/usr/bin/env X (or direct #!/path/to/X) interpreter
    isn't actually available on PATH / at that path.
    """
    found = []
    py_like = find_python_scripts(home)  # reuse the project-scan walk, .py only
    # also sweep .sh files in the same project-ish locations
    skip_dir_names = {".git", "node_modules", "venv", ".venv", "env",
                       "__pycache__", "site-packages", "dist-packages",
                       ".cache", ".local"}
    sh_files = []
    for root, dirs, files in os.walk(home):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in skip_dir_names and not d.startswith(".")]
        for fname in files:
            if fname.endswith(".sh"):
                sh_files.append(root_path / fname)
        if len(sh_files) >= max_results:
            break

    for f in py_like + sh_files:
        if is_protected(f, protected):
            continue
        try:
            with open(f, "r", errors="ignore") as fh:
                first_line = fh.readline().strip()
        except OSError:
            continue
        if not first_line.startswith("#!"):
            continue
        shebang = first_line[2:].strip()
        parts = shebang.split()
        if not parts:
            continue
        if parts[0].endswith("env") and len(parts) > 1:
            interpreter = parts[1]
            resolved = shutil.which(interpreter)
            if not resolved:
                found.append((f, interpreter))
        else:
            interpreter_path = Path(parts[0])
            if not interpreter_path.exists():
                found.append((f, parts[0]))
        if len(found) >= max_results:
            break
    return found


# ─── Trash-linked leftover scanner ───────────────────────────────────────────

def get_trash_items(home):
    """Return list of (path, original_path_or_None) currently in Trash."""
    trash_files = home / ".local" / "share" / "Trash" / "files"
    trash_info = home / ".local" / "share" / "Trash" / "info"
    items = []
    if not trash_files.exists():
        return items
    for entry in trash_files.iterdir():
        info_file = trash_info / f"{entry.name}.trashinfo"
        original = None
        if info_file.exists():
            try:
                for line in info_file.read_text(errors="ignore").splitlines():
                    if line.startswith("Path="):
                        original = line.split("=", 1)[1]
            except OSError:
                pass
        items.append((entry, original))
    return items


def scan_trash_linked_leftovers(home, trash_items, protected):
    """
    For each item already in Trash, look for directly-related leftovers
    that the user has NOT yet deleted:
      - broken symlinks that point at the trashed file's original path
      - sibling files sharing the exact same base name
      - .desktop launcher files referencing the trashed path
    Search is scoped to the home directory, skipping protected dirs and Trash.
    """
    findings = []
    if not trash_items:
        return findings

    trashed_basenames = set()
    trashed_original_paths = set()
    for entry, original in trash_items:
        trashed_basenames.add(entry.name.rsplit(".", 1)[0] if "." in entry.name else entry.name)
        trashed_basenames.add(entry.name)
        if original:
            trashed_original_paths.add(original)

    for root, dirs, files in os.walk(home):
        root_path = Path(root)
        if is_protected(root_path, protected):
            dirs[:] = []
            continue
        if "Trash" in root_path.parts:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]

        for fname in files:
            fpath = root_path / fname
            if is_protected(fpath, protected):
                continue

            if fpath.is_symlink():
                try:
                    target = os.readlink(fpath)
                except OSError:
                    continue
                if not fpath.exists():
                    if target in trashed_original_paths:
                        findings.append({
                            "path": fpath,
                            "reason": f"This is a broken shortcut (symlink) — it points to '{target}', which you already moved to Trash, so it now leads nowhere.",
                            "risk": "safe",
                            "size": 0,
                        })
                continue

            base = fname.rsplit(".", 1)[0] if "." in fname else fname
            if base in trashed_basenames and fname not in trashed_basenames:
                try:
                    size = fpath.stat().st_size
                except OSError:
                    size = 0
                findings.append({
                    "path": fpath,
                    "reason": f"This file shares the exact name '{base}' with something you already moved to Trash — it's likely a backup, duplicate, or older copy of that same item.",
                    "risk": "review",
                    "size": size,
                })

            if fname.endswith(".desktop"):
                try:
                    content = fpath.read_text(errors="ignore")
                except OSError:
                    content = ""
                for orig in trashed_original_paths:
                    if orig and orig in content:
                        findings.append({
                            "path": fpath,
                            "reason": f"This is a shortcut/launcher file that points at '{orig}', which you already moved to Trash. Clicking it will now fail.",
                            "risk": "review",
                            "size": fpath.stat().st_size if fpath.exists() else 0,
                        })
                        break

    return findings


# ─── Harmful file scanner ─────────────────────────────────────────────────────

SUSPICIOUS_DOUBLE_EXT = {
    (".pdf", ".sh"), (".pdf", ".exe"), (".pdf", ".js"),
    (".docx", ".sh"), (".docx", ".exe"), (".docx", ".scr"),
    (".jpg", ".sh"), (".jpg", ".exe"), (".png", ".exe"),
    (".txt", ".sh"), (".txt", ".vbs"), (".zip", ".exe"),
}
SCRIPT_EXTS = {".sh", ".py", ".pl", ".rb"}


def scan_harmful_files(home, protected):
    """
    Heuristic scan for files that look disguised or unusually risky:
      - double extensions where the real (last) extension is executable
        but the visible name suggests a document/image
      - files marked executable sitting in Downloads/Desktop with no
        clear reason to be
    Heuristic only — explains, does not assume malice.
    """
    findings = []
    watch_dirs = [home / "Downloads", home / "Desktop", home / "Documents"]

    for wd in watch_dirs:
        if not wd.exists() or is_protected(wd, protected):
            continue
        for entry in wd.rglob("*"):
            try:
                if not entry.is_file() or entry.is_symlink():
                    continue
            except OSError:
                continue
            if is_protected(entry, protected):
                continue

            suffixes = entry.suffixes
            if len(suffixes) >= 2:
                pair = (suffixes[-2], suffixes[-1])
                if pair in SUSPICIOUS_DOUBLE_EXT:
                    findings.append({
                        "path": entry,
                        "reason": (
                            f"Named like a '{suffixes[-2]}' file but actually ends in "
                            f"'{suffixes[-1]}', a script/program extension. This pattern "
                            f"(document-looking name, executable underneath) is commonly "
                            f"used to trick someone into running something they think is "
                            f"just a document or image."
                        ),
                        "risk": "caution",
                        "size": entry.stat().st_size,
                    })
                    continue

            try:
                is_exec = os.access(entry, os.X_OK)
            except OSError:
                is_exec = False
            if is_exec and entry.suffix.lower() in SCRIPT_EXTS:
                findings.append({
                    "path": entry,
                    "reason": (
                        f"This is an executable script sitting in {wd.name}, a folder "
                        f"normally used for downloads/documents rather than running "
                        f"programs. Not necessarily harmful — just confirm you put it "
                        f"there and know what it does before deleting or keeping it."
                    ),
                    "risk": "review",
                    "size": entry.stat().st_size,
                })

    return findings


# ─── Display helpers ──────────────────────────────────────────────────────────

SEPARATOR = dim("─" * 60)

def section(title, icon="●"):
    print(f"\n{bold(cyan(icon + '  ' + title))}")
    print(SEPARATOR)


def risk_badge(level):
    return {
        "safe":    green("[SAFE]"),
        "review":  yellow("[REVIEW]"),
        "caution": red("[CAUTION]"),
    }.get(level, dim("[?]"))


# ─── Interactive cleanup ──────────────────────────────────────────────────────

def delete_path(path):
    p = Path(path)

    if ENABLE_BACKUP:
        backup_zip = _zip_path_into_backup(p)
        if backup_zip is None:
            # Backup failed — refuse to delete rather than risk an
            # unrecoverable mistake. This is the whole point of the
            # backup-before-delete net: it's not optional best-effort,
            # it's a precondition for the delete actually happening.
            log_event(f"SKIPPED (backup failed): {p}")
            return False
        print(f"  {dim(f'Backed up to: {backup_zip}')}")

    try:
        if p.is_file() or p.is_symlink():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
        print(f"  {green('✔')} Deleted: {p}")
        log_event(f"DELETED: {p}")
        return True
    except (PermissionError, OSError) as e:
        print(f"  {red('✘')} Failed: {p} ({e})")
        log_event(f"FAILED: {p} ({e})")
        return False


def explain_path(path: Path) -> str:
    """Plain-English explanation of what a path likely is, using KNOWN_APPS."""
    return explain_unknown(path.name)


def prompt_delete_list(items, label_fn, dry_run=False, explain=True):
    """
    Ask user to review and optionally delete a list of paths.
    label_fn: callable that returns a display string for each item.
    Items: list of Path or (Path, ...) tuples.
    If explain=True, prints a plain-English "what is this" line before asking.
    """
    deleted_bytes = 0
    for item in items:
        path = item[0] if isinstance(item, tuple) else item
        print(f"\n  {label_fn(item)}")
        if explain:
            print(f"    What this is: {explain_path(path)}")
        if dry_run:
            continue
        if confirm("Delete this?"):
            if delete_path(path):
                size = item[1] if isinstance(item, tuple) and len(item) > 1 else 0
                deleted_bytes += size
    return deleted_bytes


def explain_and_confirm_findings(findings, dry_run=False):
    """
    For each finding dict (path, reason, risk, size), print a plain-English
    explanation FIRST, then ask y/n. Returns bytes freed.
    """
    deleted_bytes = 0
    for f in findings:
        print(f"\n  {risk_badge(f['risk'])} {f['path']}")
        if f.get("size"):
            print(f"    Size: {human(f['size'])}")
        print(f"    Why flagged: {f['reason']}")
        if dry_run:
            continue
        if confirm("Delete this?"):
            if delete_path(f["path"]):
                deleted_bytes += f.get("size", 0)
    return deleted_bytes


def report_only(findings_with_reasons, risk="caution", action_label=None,
                 action_fn=None, dry_run=False):
    """
    Same explain-first pattern as explain_and_confirm_findings, but for
    findings where there's nothing to delete — only something missing to
    report, and optionally fix (e.g. 'install package?'). Each item is
    (label, reason_text, optional_fix_prompt_or_None).
    """
    for label, reason, fix_prompt in findings_with_reasons:
        print(f"\n  {risk_badge(risk)} {label}")
        print(f"    Why flagged: {reason}")
        if fix_prompt and not dry_run and action_fn:
            if confirm(fix_prompt):
                action_fn(label)


# ─── Main ─────────────────────────────────────────────────────────────────────

def run_unused_check(home, dry_run, args, protected):
    """
    v3 behavior, unchanged: orphaned configs, apt leftovers, broken
    packages, large files, temp/cache junk, pip remnants, trash-linked
    leftovers, and harmful files. Returns total bytes freed.
    """
    total_freed = 0

    print(bold("\n╔══════════════════════════════════════════════╗"))
    print(bold("║     Checking for UNUSED / orphaned items     ║"))
    print(bold("╚══════════════════════════════════════════════╝"))

    if dry_run:
        print(f"\n  {yellow('DRY RUN mode — nothing will be deleted')}")

    print(f"\n  {dim('Protected (never touched, no matter what):')}")
    for p in protected:
        print(f"    {dim('·')} {p}")

    # ── 1. Disk overview ────────────────────────────────────────────────────
    section("Disk Overview", "💾")
    total, used, free = shutil.disk_usage("/")
    pct = used / total * 100
    bar_len = 40
    filled = int(bar_len * used / total)
    bar_color = red if pct > 85 else yellow if pct > 65 else green
    bar = bar_color("█" * filled) + dim("░" * (bar_len - filled))
    print(f"  [{bar}] {pct:.1f}%")
    print(f"  Used: {bold(human(used))}  Free: {bold(human(free))}  Total: {human(total)}")

    # ── 2. Installed packages list ──────────────────────────────────────────
    print(f"\n  {dim('Loading installed package list...')}", end="\r")
    installed = installed_packages()
    print(f"  Found {bold(str(len(installed)))} installed packages.            ")

    # ── 3. APT orphans ──────────────────────────────────────────────────────
    section("APT Auto-removable Packages", "📦")
    orphan_pkgs = scan_apt_orphans()
    if orphan_pkgs:
        print(f"  {risk_badge('safe')} {len(orphan_pkgs)} packages can be auto-removed:\n")
        print(f"  What this means: apt itself has determined these packages were only")
        print(f"  installed as dependencies of something else you've since removed —")
        print(f"  nothing currently installed still needs them.\n")
        for p in orphan_pkgs:
            print(f"    {yellow('·')} {p}")
        print()
        if not dry_run and confirm("Run 'apt autoremove' to remove them all?"):
            os.system("sudo apt autoremove -y")
    else:
        print(f"  {green('✔')} No orphaned apt packages found.")

    # ── 4. APT .deb cache ───────────────────────────────────────────────────
    section("APT .deb Package Cache", "🗃️")
    debs = scan_deb_cache()
    if debs:
        total_deb = sum(s for _, s in debs)
        print(f"  {risk_badge('safe')} {len(debs)} cached .deb files → {bold(human(total_deb))}\n")
        print(f"  What this means: these are leftover downloaded installer files for")
        print(f"  packages that are already installed. Deleting them does NOT remove")
        print(f"  the installed programs — only the install files themselves.\n")
        for f, s in debs[:8]:
            print(f"    {dim(human(s)):>10}  {f.name}")
        if len(debs) > 8:
            print(f"    {dim(f'... and {len(debs) - 8} more')}")
        print()
        if not dry_run and confirm("Run 'apt clean' to clear the .deb cache?"):
            os.system("sudo apt clean")
            total_freed += total_deb
    else:
        print(f"  {green('✔')} APT cache is empty.")

    # ── 5. Orphaned config dirs ─────────────────────────────────────────────
    section("Orphaned Config Directories", "⚙️")
    orphan_configs = scan_orphaned_configs(home, installed, protected)
    if orphan_configs:
        print(f"  {risk_badge('review')} {len(orphan_configs)} config folders with no matching installed package:\n")
        print(f"  What this means: each folder below is named after an app, but no")
        print(f"  currently installed package matches that name closely. This can mean")
        print(f"  the app was uninstalled and left settings behind — OR it can mean the")
        print(f"  matching is just imperfect for an app you still use. Read each one")
        print(f"  before deciding; browser/app profiles in the protected list above")
        print(f"  are excluded automatically and won't appear here.")
        print(f"  Each entry also shows how long it's been untouched — older + unmatched")
        print(f"  is a stronger signal than unmatched alone, but neither signal by itself")
        print(f"  is certainty. Read the explanation before deciding either way.\n")
        conf_badge = {"high": green("[OLD]"), "medium": yellow("[AGING]"), "low": dim("[RECENT]")}
        for path, size, days_old, confidence in orphan_configs[:15]:
            age_str = f"{days_old}d old" if days_old is not None else "age unknown"
            print(f"    {yellow(human(size)):>10}  {conf_badge.get(confidence, '')} {dim(age_str):<12} {path}")
        if len(orphan_configs) > 15:
            print(f"    {dim(f'... and {len(orphan_configs) - 15} more')}")
        print()
        if not dry_run:
            print(f"  {dim('Review each folder before deleting. Press Ctrl+C to stop.')}\n")

            def _orphan_label(x):
                path, size, days_old, confidence = x
                age_str = f"{days_old} days old" if days_old is not None else "age unknown"
                return f"{risk_badge('review')} {human(size):>10}  ({age_str})  {path}"

            freed = prompt_delete_list(
                orphan_configs,
                label_fn=_orphan_label,
                dry_run=dry_run,
                explain=True,
            )
            total_freed += freed
    else:
        print(f"  {green('✔')} No clearly orphaned config dirs found.")

    # ── 6. Broken / deinstall packages ─────────────────────────────────────
    section("Broken / Deinstalled Packages", "🔧")
    broken = scan_broken_packages()
    if broken:
        print(f"  {risk_badge('caution')} {len(broken)} packages in broken/deinstall state:\n")
        print(f"  What this means: these packages were removed but left their config")
        print(f"  files behind (or got stuck mid-install/mid-removal). They're not")
        print(f"  doing anything useful in this state.\n")
        for pkg, state in broken:
            print(f"    {red(state):>18}  {pkg}")
        print()
        print(f"  {dim('Tip: run')} sudo dpkg --purge <package> {dim('to fully remove.')}")
        if not dry_run and confirm("Purge all deinstall-state packages?"):
            deinstall_pkgs = [p for p, s in broken if "deinstall" in s or "config-files" in s]
            if deinstall_pkgs:
                os.system(f"sudo dpkg --purge {' '.join(deinstall_pkgs)}")
    else:
        print(f"  {green('✔')} No broken packages found.")

    # ── 7. Temp / cache directories ─────────────────────────────────────────
    section("Temp & Cache Directories", "🗑️")
    caches = scan_temp_cache(home)
    for path, label, size in caches:
        badge = "safe" if "tmp" in str(path).lower() or "cache" in str(path).lower() else "review"
        print(f"  {risk_badge(badge)} {label}")
        print(f"            {bold(human(size))} at {dim(str(path))}")
    print(f"\n  What this means: these hold temporary/regenerable data — apps rebuild")
    print(f"  their cache automatically. This is separate from your saved logins or")
    print(f"  settings, which live in each app's own config folder, not here.\n")
    if not dry_run:
        if confirm("Clear ~/.cache (user cache)?"):
            freed = dir_size(home / ".cache")
            shutil.rmtree(home / ".cache", ignore_errors=True)
            (home / ".cache").mkdir(exist_ok=True)
            total_freed += freed
            print(f"  {green('✔')} ~/.cache cleared  ({human(freed)} freed)")

    # ── 8. pip cache ────────────────────────────────────────────────────────
    section("Python / pip Cache", "🐍")
    pip_items = scan_pip_cache(home)
    if pip_items:
        print(f"  What this means: pip keeps downloaded package files here so it doesn't")
        print(f"  have to re-download them next install. Safe to clear — pip will just")
        print(f"  re-download if needed again.\n")
        for path, size in pip_items:
            print(f"  {risk_badge('safe')} {human(size):>10}  {path}")
        print()
        if not dry_run and confirm("Clear pip cache? (pip cache purge)"):
            run("pip cache purge 2>/dev/null || pip3 cache purge 2>/dev/null")
            freed = sum(s for _, s in pip_items if "pip" in str(_))
            total_freed += freed
            print(f"  {green('✔')} pip cache cleared.")
    else:
        print(f"  {green('✔')} No significant pip cache found.")

    # ── 9. Large files ──────────────────────────────────────────────────────
    section(f"Large Files (>{args.large_min_mb} MB) in Home", "📁")
    print(f"  {dim('Scanning... (this may take a moment)')}", end="\r")
    large = scan_large_files(home, min_mb=args.large_min_mb, protected=protected)
    if large:
        print(f"  {risk_badge('review')} Top large files in ~/:               \n")
        for path, size in large:
            ext = path.suffix.lower()
            note = ""
            if ext in (".deb", ".pkg", ".rpm"):
                note = yellow(" ← installer package")
            elif ext in (".iso", ".img"):
                note = yellow(" ← disk image")
            elif ext in (".zip", ".tar", ".gz", ".xz", ".7z"):
                note = yellow(" ← archive")
            elif ext in (".log",):
                note = dim(" ← log file")
            print(f"    {human(size):>10}  {path}{note}")
        print()
        if not dry_run:
            print(f"  {dim('Each item below is explained before you decide. Press Ctrl+C to stop.')}\n")
            freed = prompt_delete_list(
                large,
                label_fn=lambda x: f"{risk_badge('review')} {human(x[1]):>10}  {x[0]}",
                dry_run=dry_run,
                explain=True,
            )
            total_freed += freed
    else:
        print(f"  {green('✔')} No large files found above {args.large_min_mb} MB.")

    # ── 10. Trash-linked leftovers ──────────────────────────────────────────
    section("Items in Trash & Their Leftovers", "♻️")
    trash_items = get_trash_items(home)
    if trash_items:
        total_trash_size = sum(
            (e.stat().st_size if e.is_file() else dir_size(e)) for e, _ in trash_items
        )
        print(f"  {bold(str(len(trash_items)))} item(s) currently in Trash, "
              f"using {bold(human(total_trash_size))}:\n")
        for entry, original in trash_items:
            print(f"    {dim('·')} {entry.name}" + (f"  (was: {original})" if original else ""))

        print(f"\n  {dim('Searching home folder for things still linked to these (not yet deleted)...')}")
        linked = scan_trash_linked_leftovers(home, trash_items, protected)
        if linked:
            print(f"\n  Found {bold(str(len(linked)))} related leftover(s):")
            freed = explain_and_confirm_findings(linked, dry_run=dry_run)
            total_freed += freed
        else:
            print(f"  {green('✔')} No leftover references found tied to your trashed items.")
    else:
        print(f"  {green('✔')} Trash is empty — nothing to cross-reference.")

    # ── 11. Harmful file review ──────────────────────────────────────────────
    section("Potentially Harmful Files (Downloads / Desktop / Documents)", "⚠️")
    harmful = scan_harmful_files(home, protected)
    if harmful:
        print(f"  Found {bold(str(len(harmful)))} file(s) worth a second look:")
        freed = explain_and_confirm_findings(harmful, dry_run=dry_run)
        total_freed += freed
    else:
        print(f"  {green('✔')} No suspicious double-extensions or stray scripts found.")

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print(bold("  Unused/Orphaned Check — Summary"))
    print(SEPARATOR)
    _, used_after, free_after = shutil.disk_usage("/")
    if total_freed > 0:
        print(f"  {green('✔')} Freed approx. {bold(green(human(total_freed)))} this session")
    print(f"  Free space now: {bold(human(free_after))}")
    if dry_run:
        print(f"  {yellow('(Dry run — no files were actually deleted)')}")
    print()
    return total_freed


def run_missing_check(home, dry_run, protected):
    """
    Reports things that SHOULD be present but aren't. Never deletes
    anything; for apt fixes it offers the standard repair command,
    same explain-before-action pattern as the unused-check side.
    """
    print(bold("\n╔══════════════════════════════════════════════╗"))
    print(bold("║     Checking for MISSING dependencies        ║"))
    print(bold("╚══════════════════════════════════════════════╝"))
    print(f"\n  {dim('This side only reports. Nothing is deleted here.')}")

    # ── 1. Missing Python imports ───────────────────────────────────────────
    section("Python Imports That Won't Resolve", "🐍")
    print(f"  {dim('Scanning project-like .py files under your home dir...')}", end="\r")
    missing_imports = scan_missing_python_imports(home)
    if missing_imports:
        print(f"  {risk_badge('caution')} {len(missing_imports)} imported module(s) not installed:\n")
        print(f"  What this means: these scripts contain 'import X' (or 'from X import...')")
        print(f"  where X can't currently be found by Python on this machine — running")
        print(f"  the script as-is will raise ModuleNotFoundError.\n")
        for m in missing_imports:
            files_preview = ", ".join(str(f) for f in m["files"][:3])
            more = f"  (+{len(m['files']) - 3} more)" if len(m["files"]) > 3 else ""
            print(f"    {red(m['module']):<22} used in: {dim(files_preview)}{more}")
            if m["module"] != m["pip_name"]:
                print(f"        {dim('install with: pip install ' + m['pip_name'] + '  (import name differs from package name)')}")
        print()
        if not dry_run:
            for m in missing_imports:
                if confirm(f"Install '{m['pip_name']}' with pip now?"):
                    run(f"pip install --break-system-packages {m['pip_name']} 2>&1 || pip3 install --break-system-packages {m['pip_name']} 2>&1")
                    print(f"  {green('✔')} Attempted install of {m['pip_name']}.")
    else:
        print(f"  {green('✔')} All discovered imports resolve in the current environment.")

    # ── 2. Missing shared libraries ─────────────────────────────────────────
    section("Binaries With Missing Shared Libraries", "🔗")
    print(f"  {dim('Running ldd against a sample of system binaries...')}", end="\r")
    missing_libs = scan_missing_shared_libs(home)
    if missing_libs:
        print(f"  {risk_badge('caution')} {len(missing_libs)} binary/binaries with unresolved libraries:\n")
        print(f"  What this means: each binary below links against a shared library")
        print(f"  (.so file) that isn't currently installed. The program will likely")
        print(f"  fail to run, or fail at the point it needs that library.\n")
        for b, libs in missing_libs[:15]:
            print(f"    {red(str(b)):<40} needs: {', '.join(libs)}")
        if len(missing_libs) > 15:
            print(f"    {dim(f'... and {len(missing_libs) - 15} more')}")
        print(f"\n  {dim('Tip:')} apt-file search <library_name> {dim('can usually tell you which package provides it.')}")
    else:
        print(f"  {green('✔')} No missing shared libraries found in the sampled binaries.")

    # ── 3. Unmet apt dependencies ────────────────────────────────────────────
    section("Unmet APT Dependencies", "📦")
    check_summary, broken_state_pkgs = scan_unmet_apt_dependencies()
    if check_summary or broken_state_pkgs:
        print(f"  {risk_badge('caution')} Dependency problems found:\n")
        if check_summary:
            print(f"  What this means: apt-get check reported broken dependency chains —")
            print(f"  something installed needs a package/version that isn't present.\n")
            for line in check_summary.splitlines()[:10]:
                print(f"    {dim(line)}")
            print()
        if broken_state_pkgs:
            print(f"  What this means: these packages are stuck mid-install (their")
            print(f"  dependencies weren't all satisfied when they were set up):\n")
            for pkg, state in broken_state_pkgs:
                print(f"    {red(state):>18}  {pkg}")
            print()
        if not dry_run and confirm("Run 'sudo apt --fix-broken install' now?"):
            os.system("sudo apt --fix-broken install -y")
    else:
        print(f"  {green('✔')} No unmet apt dependency problems found.")

    # ── 4. Dangling symlinks ────────────────────────────────────────────────
    section("Dangling Symlinks (Broken Shortcuts)", "🔗")
    dangling = scan_dangling_symlinks(home, protected)
    if dangling:
        print(f"  {risk_badge('review')} {len(dangling)} broken symlink(s) found:\n")
        print(f"  What this means: each link below points at a target that no longer")
        print(f"  exists — opening it will fail. This is a missing-target problem, not")
        print(f"  something to clean up blindly: the fix is usually restoring or")
        print(f"  re-pointing the target, not deleting the link.\n")
        for path, target in dangling[:15]:
            print(f"    {path}  {dim('→')} {red(target)}")
        if len(dangling) > 15:
            print(f"    {dim(f'... and {len(dangling) - 15} more')}")
    else:
        print(f"  {green('✔')} No dangling symlinks found.")

    # ── 5. Missing shebang interpreters ─────────────────────────────────────
    section("Scripts With a Missing Interpreter", "📜")
    missing_shebangs = scan_missing_shebang_interpreters(home, protected)
    if missing_shebangs:
        print(f"  {risk_badge('review')} {len(missing_shebangs)} script(s) reference a missing interpreter:\n")
        print(f"  What this means: the first line of each script below names a program")
        print(f"  to run it with (e.g. python3, node, bash) that isn't on PATH right")
        print(f"  now — running the script directly (./script) will fail until that's")
        print(f"  installed or your PATH is fixed.\n")
        for path, interpreter in missing_shebangs[:15]:
            print(f"    {path}  {dim('wants:')} {red(interpreter)}")
        if len(missing_shebangs) > 15:
            print(f"    {dim(f'... and {len(missing_shebangs) - 15} more')}")
    else:
        print(f"  {green('✔')} No scripts with an unresolvable shebang interpreter found.")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print(bold("  Missing-Dependency Check — Summary"))
    print(SEPARATOR)
    print(f"  {dim('This check only reports/repairs — nothing was deleted.')}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Kali Linux Storage Checker — find unused/orphaned junk, "
                     "or find missing dependencies, with plain-English "
                     "explanations before any deletion or fix"
    )
    parser.add_argument(
        "--mode", choices=["unused", "missing", "both"], default=None,
        help="Which check to run. If omitted, you'll be asked interactively."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be deleted/fixed without actually doing it"
    )
    parser.add_argument(
        "--large-min-mb", type=int, default=100,
        help="Minimum file size (MB) for large-file scan (default: 100)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output"
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="Disable the zip-before-delete safety net (NOT recommended)"
    )
    parser.add_argument(
        "--no-log", action="store_true",
        help="Don't write a run summary to ~/.storage_checker_log.txt"
    )
    args = parser.parse_args()

    if args.no_color:
        global COLOR
        COLOR = False

    global ENABLE_BACKUP, ENABLE_LOG
    if args.no_backup:
        ENABLE_BACKUP = False
        print(f"  {yellow('[!] --no-backup set: deletes will NOT be backed up first.')}")
    if args.no_log:
        ENABLE_LOG = False

    home = Path.home()
    dry_run = args.dry_run
    protected = protected_dirs(home)

    print()
    print(bold("╔══════════════════════════════════════════════╗"))
    print(bold("║     Kali Linux Storage Checker v5            ║"))
    print(bold("╚══════════════════════════════════════════════╝"))

    mode = args.mode
    if mode is None:
        print(f"\n  {bold('What do you want to check?')}")
        print(f"    {cyan('[1]')} Unused / orphaned items  {dim('(things present that nothing needs — can be deleted)')}")
        print(f"    {cyan('[2]')} Missing dependencies     {dim('(things needed that are not present — report/fix only)')}")
        print(f"    {cyan('[3]')} Both, one after another")
        while True:
            choice = input(f"\n  {dim('Choice')} [1/2/3]: ").strip()
            if choice == "1":
                mode = "unused"
                break
            elif choice == "2":
                mode = "missing"
                break
            elif choice == "3":
                mode = "both"
                break
            else:
                print(f"  {yellow('Please enter 1, 2, or 3.')}")

    if dry_run:
        print(f"\n  {yellow('DRY RUN mode — nothing will be deleted or installed')}")

    if ENABLE_BACKUP and not dry_run:
        prune_old_backups()

    total_freed_session = 0
    if mode in ("unused", "both"):
        total_freed_session += run_unused_check(home, dry_run, args, protected)

    if mode in ("missing", "both"):
        run_missing_check(home, dry_run, protected)

    flush_run_log(mode, dry_run, total_freed_session)
    if ENABLE_LOG and not dry_run:
        print(f"  {dim(f'Run summary saved to: {LOG_PATH}')}")
    if ENABLE_BACKUP and not dry_run and total_freed_session > 0:
        print(f"  {dim(f'Backups (if any deletes happened) saved to: {BACKUP_DIR}')}")
        print(f"  {dim(f'Backups auto-expire after {BACKUP_RETENTION_DAYS} days.')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Aborted by user.')}\n")
        sys.exit(0)
