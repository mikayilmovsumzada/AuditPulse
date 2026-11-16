#!/usr/bin/env python3
"""FileAudit: reads auditd events for watched folders and serves a dashboard.

Runs as root (needs /var/log/audit/audit.log). Stdlib only.
"""
import base64
import grp
import hmac
import ipaddress
import json
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOG = os.environ.get("FA_LOG", "/var/log/audit/audit.log")
DB = os.environ.get("FA_DB", "/var/lib/fileaudit/events.db")
HOST = os.environ.get("FA_HOST", "127.0.0.1")
PORT = int(os.environ.get("FA_PORT", "8088"))
# Optional panel password (HTTP Basic auth, any user name). Required when HOST is not loopback.
PASSWORD = os.environ.get("FA_PASSWORD", "")
# Extra host names the panel may be opened by (comma-separated), e.g. "audit.lan,192.168.1.20".
ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("FA_ALLOWED_HOSTS", "").split(",") if h.strip()}
AUTH_WINDOW = 15 * 60
AUTH_MAX_FAILS = 5
# Persistent audit rules (loaded at boot by augenrules). The panel edits only our own -w lines.
RULES_FILE = os.environ.get("FA_RULES", "/etc/audit/rules.d/fileaudit.rules")
MAX_WATCHES = 16
# Never watched: virtual file systems, the audit log itself and our own database (would loop forever).
FORBIDDEN_ROOTS = ("/proc", "/sys", "/dev", "/run", "/var/log/audit")
# Offered in the panel as one-click choices when they exist on this machine.
SUGGESTED_DIRS = ("/var/www", "/srv", "/opt", "/etc/nginx", "/etc/apache2", "/etc/ssh", "/etc/cron.d",
                  "/var/spool/cron", "/usr/local/bin", "/home", "/etc", "/root")
WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_ROWS = 200_000
KEY_PREFIX = "fa_"

# x86_64 syscall numbers -> names (fallback when log is not ENRICHED)
SYSCALLS = {
    2: "open", 257: "openat", 437: "openat2", 85: "creat", 82: "rename",
    264: "renameat", 316: "renameat2", 83: "mkdir", 258: "mkdirat", 84: "rmdir",
    87: "unlink", 263: "unlinkat", 90: "chmod", 91: "fchmod", 268: "fchmodat",
    452: "fchmodat2", 92: "chown", 93: "fchown", 94: "lchown", 260: "fchownat",
    76: "truncate", 77: "ftruncate", 86: "link", 265: "linkat", 88: "symlink",
    266: "symlinkat", 188: "setxattr", 189: "lsetxattr", 190: "fsetxattr",
    197: "removexattr", 198: "lremovexattr", 199: "fremovexattr",
    132: "utime", 235: "utimes", 280: "utimensat", 261: "futimesat",
}
OPEN = {"open", "openat", "openat2", "creat"}
CHMOD = {"chmod": 1, "fchmod": 1, "fchmodat": 2, "fchmodat2": 2}
CHOWN = {"chown": 1, "fchown": 1, "lchown": 1, "fchownat": 2}
ERR_DENIED = {"-13", "-1"}  # EACCES, EPERM

LINE_RE = re.compile(r"^type=(\S+) msg=audit\((\d+\.\d+):(\d+)\):\s?(.*)$")
FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

_name_cache = {}


def user_name(uid):
    if uid in (None, "", "4294967295", "-1", "unset"):
        return None
    key = ("u", uid)
    if key not in _name_cache:
        try:
            _name_cache[key] = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            _name_cache[key] = f"uid {uid}"
    return _name_cache[key]


def group_name(gid):
    key = ("g", gid)
    if key not in _name_cache:
        try:
            _name_cache[key] = grp.getgrgid(int(gid)).gr_name
        except (KeyError, ValueError):
            _name_cache[key] = f"gid {gid}"
    return _name_cache[key]


HEX_KEYS = {"name", "cwd", "proctitle", "exe", "comm"}


def fields(text):
    text = text.split("\x1d", 1)[0]  # drop ENRICHED tail
    out = {}
    for k, v in FIELD_RE.findall(text):
        if v.startswith('"'):
            v = v[1:-1]  # quoted values are plain text
        elif k in HEX_KEYS:
            v = decode_hex(v)  # unquoted names/paths are hex-encoded by auditd
        out.setdefault(k, v)
    return out


def enriched(text):
    if "\x1d" not in text:
        return {}
    return {k: v.strip('"') for k, v in FIELD_RE.findall(text.split("\x1d", 1)[1])}


def decode_hex(value):
    if value and re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            pass
    return value


def ftype(mode):
    try:
        m = int(mode, 8)
    except (TypeError, ValueError):
        return "file"
    t = m & 0o170000
    return {0o040000: "dir", 0o120000: "link"}.get(t, "file")


class Event:
    __slots__ = ("ts", "serial", "syscall", "paths", "cwd", "proctitle", "born")

    def __init__(self, ts, serial):
        self.ts, self.serial = ts, serial
        self.syscall, self.paths, self.cwd, self.proctitle = None, [], None, None
        self.born = time.time()


def full_path(name, cwd):
    if not name or name == "(null)":
        return None
    if not name.startswith("/") and cwd:
        name = os.path.join(cwd, name)
    return os.path.normpath(name)


_inode_dirs = {}


def dir_by_inode(inode, roots):
    """Find a directory path by inode under the watched roots (cached)."""
    try:
        inode = int(inode)
    except (TypeError, ValueError):
        return None
    if inode in _inode_dirs:
        return _inode_dirs[inode]
    for root in roots:
        stack = [root]
        while stack:
            d = stack.pop()
            try:
                st = os.stat(d, follow_symlinks=False)
                if st.st_ino == inode:
                    if len(_inode_dirs) > 5000:
                        _inode_dirs.clear()
                    _inode_dirs[inode] = d
                    return d
                with os.scandir(d) as it:
                    stack.extend(e.path for e in it if e.is_dir(follow_symlinks=False))
            except OSError:
                pass
    return None


AT_SYSCALLS = {"openat", "openat2", "mkdirat", "unlinkat", "renameat", "renameat2", "fchmodat",
               "fchmodat2", "fchownat", "linkat", "symlinkat", "utimensat", "futimesat"}


def resolve_items(ev, sc, name, roots):
    """Full paths for PATH items; handles *at() syscalls with a real dirfd."""
    dirfd_used = name in AT_SYSCALLS and sc.get("a0") not in (None, "ffffff9c", "ffffffffffffff9c")
    parents = [p for p in ev.paths if p.get("nametype") == "PARENT"]
    out, k = [], 0
    for p in ev.paths:
        name = p.get("name") if p.get("name") not in (None, "(null)") else None
        fp = None
        if name and not name.startswith("/") and dirfd_used and p.get("nametype") != "PARENT" and parents:
            parent = parents[min(k, len(parents) - 1)]
            base = dir_by_inode(parent.get("inode"), roots)
            if base:
                fp = os.path.normpath(os.path.join(base, name))
            k += 1
        fp = fp or full_path(p.get("name"), ev.cwd)
        # remember directory inodes so later dirfd-relative events (rm -r) resolve
        trusted = not (dirfd_used and p.get("nametype") == "PARENT")
        if fp and trusted and ftype(p.get("mode")) == "dir" and p.get("inode"):
            try:
                if len(_inode_dirs) > 5000:
                    _inode_dirs.clear()
                _inode_dirs[int(p["inode"])] = fp
            except ValueError:
                pass
        out.append((p, fp))
    return out


def classify(ev):
    """Turn a raw grouped audit event into one dashboard row (or None)."""
    sc = ev.syscall
    if not sc or not sc.get("key", "").startswith(KEY_PREFIX):
        return None
    name = sc.get("_name") or SYSCALLS.get(int(sc.get("syscall", "0")), "")
    success = sc.get("success") == "yes"
    if not success and sc.get("exit") not in ERR_DENIED:
        return None  # e.g. EEXIST/ENOENT probes: noise
    if not success and name in ("open", "openat"):
        # denied read-only opens (e.g. pgrep reading /proc/*/environ) are not changes
        try:
            flags = int(sc.get("a1" if name == "open" else "a2", "0"), 16)
        except ValueError:
            flags = 0
        if not flags & (0o1 | 0o2 | 0o100 | 0o1000):  # O_WRONLY|O_RDWR|O_CREAT|O_TRUNC
            return None

    all_roots = [d for ds in ROOTS.values() for d in ds]
    items = resolve_items(ev, sc, name, ROOTS.get(sc.get("key"), all_roots))
    by_type = lambda t: [(p, fp) for p, fp in items if p.get("nametype") == t and fp]
    normal = by_type("NORMAL") or [(p, fp) for p, fp in items if p.get("nametype") != "PARENT" and fp]
    created, deleted = by_type("CREATE"), by_type("DELETE")

    if not success and not normal and not created and not deleted:
        # denied before the kernel reached the child: only PARENT is logged.
        # Recover the target name from the command line when it is unambiguous.
        parents = by_type("PARENT")
        if not parents:
            return None
        pdir = parents[0][1].rstrip("/") or "/"
        guess = None
        for arg in (ev.proctitle or "").split()[1:]:
            fp = full_path(arg, ev.cwd)
            if fp and os.path.dirname(fp) == pdir:
                guess = fp
        fake = {"nametype": "CREATE" if name in ("mkdir", "mkdirat", "creat") or
                (name in OPEN and int(sc.get("a2" if name != "open" else "a1", "0"), 16) & 0o100)
                else "NORMAL", "mode": "040000" if name in ("mkdir", "mkdirat") else "0100000"}
        tgt = [(fake, guess or pdir + "/…")]
        if fake["nametype"] == "CREATE":
            created = tgt
        else:
            normal = tgt

    row = dict(action=None, ftype="file", path=None, path2=None,
               old_mode=None, new_mode=None, old_owner=None, new_owner=None)

    if name in ("rename", "renameat", "renameat2"):
        if deleted and created:
            row.update(action="rename", path=deleted[0][1], path2=created[0][1],
                       ftype=ftype(deleted[0][0].get("mode")))
        elif normal:
            row.update(action="rename", path=normal[0][1])
    elif name in ("mkdir", "mkdirat"):
        tgt = created or normal
        row.update(action="create", ftype="dir", path=tgt[0][1] if tgt else None)
    elif name in ("unlink", "unlinkat", "rmdir"):
        tgt = deleted or normal
        if tgt:
            is_dir = name == "rmdir" or ftype(tgt[0][0].get("mode")) == "dir"
            row.update(action="delete", ftype="dir" if is_dir else ftype(tgt[0][0].get("mode")), path=tgt[0][1])
    elif name in ("link", "linkat", "symlink", "symlinkat"):
        tgt = created or normal
        row.update(action="create", ftype="link", path=tgt[-1][1] if tgt else None)
    elif name in OPEN:
        if created:
            row.update(action="create", path=created[0][1], ftype=ftype(created[0][0].get("mode")))
        elif normal:
            row.update(action="modify", path=normal[0][1], ftype=ftype(normal[0][0].get("mode")))
    elif name in ("truncate", "ftruncate"):
        if normal:
            row.update(action="modify", path=normal[0][1])
    elif name in CHMOD:
        arg = sc.get(f"a{CHMOD[name]}", "0")
        tgt = normal[0] if normal else (items[0] if items else None)
        row["action"] = "chmod"
        if tgt:
            row.update(path=tgt[1], ftype=ftype(tgt[0].get("mode")))
            try:
                row["old_mode"] = f"{int(tgt[0].get('mode', '0'), 8) & 0o7777:04o}"
            except ValueError:
                pass
        try:
            row["new_mode"] = f"{int(arg, 16) & 0o7777:04o}"
        except ValueError:
            pass
    elif name in CHOWN:
        i = CHOWN[name]
        uid, gid = sc.get(f"a{i}"), sc.get(f"a{i + 1}")
        tgt = normal[0] if normal else (items[0] if items else None)
        row["action"] = "chown"
        if tgt:
            row.update(path=tgt[1], ftype=ftype(tgt[0].get("mode")))
            row["old_owner"] = f"{user_name(tgt[0].get('ouid')) or '?'}:{group_name(tgt[0].get('ogid'))}"
        old_u, old_g = (row["old_owner"] or "?:?").split(":", 1)
        nu = old_u if uid in (None, "ffffffff") else (user_name(str(int(uid, 16))) or "?")
        ng = old_g if gid in (None, "ffffffff") else group_name(str(int(gid, 16)))
        row["new_owner"] = f"{nu}:{ng}"
    elif "xattr" in name or name in ("utime", "utimes", "utimensat", "futimesat"):
        if normal:
            row.update(action="attr", path=normal[0][1], ftype=ftype(normal[0][0].get("mode")))
    if not row["action"] or not row["path"]:
        return None
    watch = sc.get("key", "")[len(KEY_PREFIX):]
    if watch == "denied":
        # generic EACCES/EPERM rule: keep only attempts inside watched folders
        hit = [(d, k) for k, ds in ROOTS.items() if k != KEY_PREFIX + "denied" for d in ds
               if row["path"] == d or row["path"].startswith(d.rstrip("/") + "/")]
        if not hit:
            return None
        watch = hit[0][1][len(KEY_PREFIX):]

    if not success:
        row["action_result"] = "denied"
    auid, euid = sc.get("auid"), sc.get("euid")
    cmd = ev.proctitle or None
    hidden = any(part.startswith(".") for part in (row["path"] or "").split("/") if part)
    row.update(
        ev_key=f"{ev.ts}:{ev.serial}", ts=float(ev.ts), serial=int(ev.serial),
        success=1 if success else 0,
        auid=auid, auser=user_name(auid), euid=euid, euser=user_name(euid),
        exe=sc.get("exe"), comm=sc.get("comm"), cmd=(cmd or "")[:400] or None,
        watch=watch, hidden=1 if hidden else 0,
        tty=sc.get("tty"),
    )
    row.pop("action_result", None)
    return row


COLUMNS = ["ev_key", "ts", "serial", "action", "ftype", "path", "path2", "old_mode", "new_mode",
           "old_owner", "new_owner", "success", "auid", "auser", "euid", "euser", "exe", "comm",
           "cmd", "watch", "hidden", "tty"]


def db_connect():
    con = sqlite3.connect(DB, timeout=10, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def db_init():
    # Commands can contain secrets typed on the command line: only root may read the database.
    os.makedirs(os.path.dirname(DB), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(DB), 0o700)
    con = db_connect()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ev_key TEXT UNIQUE, ts REAL, serial INTEGER, action TEXT, ftype TEXT,
      path TEXT, path2 TEXT, old_mode TEXT, new_mode TEXT, old_owner TEXT, new_owner TEXT,
      success INTEGER, auid TEXT, auser TEXT, euid TEXT, euser TEXT, exe TEXT, comm TEXT,
      cmd TEXT, watch TEXT, hidden INTEGER, tty TEXT);
    CREATE INDEX IF NOT EXISTS ix_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS ix_action ON events(action);
    CREATE INDEX IF NOT EXISTS ix_auser ON events(auser);
    """)
    con.commit()
    return con


class Collector(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__(name="collector")
        self.con = db_init()
        self.pending = {}
        self.batch = []

    def handle_line(self, line):
        m = LINE_RE.match(line)
        if not m:
            return
        rtype, ts, serial, rest = m.groups()
        if rtype == "EOE":
            self.finish(serial)
            return
        ev = self.pending.get(serial)
        if rtype == "SYSCALL":
            f = fields(rest)
            if not f.get("key", "").startswith(KEY_PREFIX):
                return
            f["_name"] = enriched(rest).get("SYSCALL")
            ev = self.pending.setdefault(serial, Event(ts, serial))
            ev.syscall = f
        elif ev is None:
            return  # SYSCALL is always the first record of a watched event
        if rtype == "CWD":
            ev.cwd = fields(rest).get("cwd")
        elif rtype == "PATH":
            ev.paths.append(fields(rest))
        elif rtype == "PROCTITLE":
            ev.proctitle = fields(rest).get("proctitle")
            self.finish(serial)

    def finish(self, serial):
        ev = self.pending.pop(serial, None)
        if ev and ev.syscall:
            row = classify(ev)
            if row:
                self.batch.append(row)

    def flush(self):
        now = time.time()
        for s in [s for s, e in self.pending.items() if now - e.born > 3]:
            self.finish(s)
        if not self.batch:
            return
        sql = f"INSERT OR IGNORE INTO events ({','.join(COLUMNS)}) VALUES ({','.join('?' * len(COLUMNS))})"
        self.con.executemany(sql, [[r.get(c) for c in COLUMNS] for r in self.batch])
        self.con.commit()
        self.batch.clear()

    def prune(self):
        self.con.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (MAX_ROWS,))
        self.con.commit()

    def run(self):
        fh, inode, buf, last_prune = None, None, "", 0
        while True:
            try:
                st = os.stat(LOG)
                if fh is None or st.st_ino != inode or st.st_size < fh.tell():
                    if fh:
                        rest = fh.read()  # drain rotated file
                        for line in (buf + rest).splitlines():
                            self.handle_line(line)
                        fh.close()
                    fh, inode, buf = open(LOG, "r", errors="replace"), st.st_ino, ""
                chunk = fh.read()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for line in lines:
                        self.handle_line(line)
                else:
                    time.sleep(0.5)
                self.flush()
                if time.time() - last_prune > 600:
                    self.prune()
                    last_prune = time.time()
            except FileNotFoundError:
                time.sleep(2)
            except Exception as exc:  # keep collecting no matter what
                print("collector error:", repr(exc), flush=True)
                time.sleep(2)


def watch_rules():
    """[(dir, key)] for our watches, from the live audit rules."""
    try:
        out = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=5).stdout
        return re.findall(r"-w (\S+) .*-k (" + KEY_PREFIX + r"\S+)", out)
    except Exception:
        return []


def watched_dirs():
    return [d for d, k in watch_rules() if k != KEY_PREFIX + "denied"]


def watched():
    """[{dir, key}] for folder watches (the panel's folder filter uses the key)."""
    return [dict(dir=d, key=k[len(KEY_PREFIX):]) for d, k in watch_rules() if k != KEY_PREFIX + "denied"]


def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def check_new_watch(raw, current):
    """Validated absolute directory path, or ValueError with a message for the panel."""
    if not isinstance(raw, str) or not raw.startswith("/") or len(raw) > 200:
        raise ValueError("Tam yol yazın, məsələn /var/www")
    if any(c.isspace() or ord(c) < 32 for c in raw):
        raise ValueError("Yolda boşluq və ya xüsusi simvol ola bilməz")
    path = os.path.realpath(raw)
    if not os.path.isdir(path):
        raise ValueError(f"Belə qovluq yoxdur: {path}")
    if path == "/":
        raise ValueError("Bütün sistemi (/) izləmək olmaz: hər saniyə minlərlə hadisə yaranar")
    for root in FORBIDDEN_ROOTS + (os.path.dirname(DB),):
        if _inside(path, root) or _inside(root, path):
            raise ValueError(f"{root} izlənə bilməz (sistem qovluğudur və ya panelin öz faylları oradadır)")
    for d in current:
        if _inside(path, d):
            raise ValueError(f"{path} artıq izlənir ({d} qovluğunun içindədir)")
        if _inside(d, path):
            raise ValueError(f"{path} artıq izlənən {d} qovluğunu əhatə edir. Əvvəlcə {d}-ni çıxarın")
    if len(current) >= MAX_WATCHES:
        raise ValueError(f"Ən çoxu {MAX_WATCHES} qovluq izlənə bilər")
    return path


def new_key(path, taken):
    base = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")[:20] or "dir"
    key, n = KEY_PREFIX + base, 2
    while key in taken or key == KEY_PREFIX + "denied":
        key, n = f"{KEY_PREFIX}{base[:17]}_{n}", n + 1
    return key


_rules_lock = threading.Lock()


def _save_rules(lines):
    tmp = RULES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    os.chmod(tmp, 0o640)
    os.replace(tmp, RULES_FILE)


def _auditctl(*args):
    r = subprocess.run(["auditctl", *args], capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip() or "auditctl failed")


def add_watch(raw):
    with _rules_lock:
        rules = watch_rules()
        path = check_new_watch(raw, [d for d, k in rules if k != KEY_PREFIX + "denied"])
        key = new_key(path, {k for _, k in rules})
        line = f"-w {path} -p wa -k {key}\n"
        with open(RULES_FILE, encoding="utf-8") as f:
            lines = f.readlines()
        last_w = max((i for i, l in enumerate(lines) if l.startswith("-w ")), default=len(lines) - 1)
        _save_rules(lines[:last_w + 1] + [line] + lines[last_w + 1:])
        try:
            _auditctl("-w", path, "-p", "wa", "-k", key)
        except Exception:
            _save_rules(lines)  # keep the file and the live rules in sync
            raise
        ROOTS.setdefault(key, []).append(path)
        print(f"[watch] added {path} ({key})", flush=True)
        return path


def remove_watch(raw):
    with _rules_lock:
        match = [(d, k) for d, k in watch_rules() if d == raw and k != KEY_PREFIX + "denied"]
        if not match:
            raise ValueError("Bu qovluq izlənmir")
        path, key = match[0]
        with open(RULES_FILE, encoding="utf-8") as f:
            lines = f.readlines()
        pattern = re.compile(r"^-w " + re.escape(path) + r" .*-k " + re.escape(key) + r"\s*$")
        _save_rules([l for l in lines if not pattern.match(l)])
        try:
            _auditctl("-W", path, "-p", "wa", "-k", key)
        except Exception:
            _save_rules(lines)
            raise
        ROOTS.pop(key, None)
        print(f"[watch] removed {path} ({key})", flush=True)
        return path


WATCH_LINE = re.compile(r"^-w (\S+) .*-k (" + KEY_PREFIX + r"\S+)\s*$")


def install_rules(template, add=(), remove=()):
    """Used by install.sh: writes RULES_FILE from the template but keeps the folders already chosen
    (in the panel or with --watch), then applies --watch / --unwatch. Prints the result."""
    with open(template, encoding="utf-8") as f:
        tpl = f.readlines()
    keep = None
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, encoding="utf-8") as f:
            keep = [l if l.endswith("\n") else l + "\n" for l in f if WATCH_LINE.match(l)]
    if keep is not None:
        first = next((i for i, l in enumerate(tpl) if WATCH_LINE.match(l)), len(tpl))
        tpl = [l for l in tpl if not WATCH_LINE.match(l)]
        tpl[first:first] = keep
    for raw in remove:
        path = os.path.realpath(raw)
        before = len(tpl)
        tpl = [l for l in tpl if not (WATCH_LINE.match(l) and WATCH_LINE.match(l).group(1) == path)]
        print(f"  - {path}" if len(tpl) < before else f"  ! {path} izlənmirdi")
    for raw in add:
        current = [(m.group(1), m.group(2)) for m in map(WATCH_LINE.match, tpl) if m]
        try:
            path = check_new_watch(raw, [d for d, _ in current])
        except ValueError as exc:
            print(f"  ! {raw}: {exc}")
            continue
        key = new_key(path, {k for _, k in current})
        last = max((i for i, l in enumerate(tpl) if WATCH_LINE.match(l)), default=len(tpl) - 1)
        tpl.insert(last + 1, f"-w {path} -p wa -k {key}\n")
        print(f"  + {path}")
    _save_rules(tpl)


def suggestions(current):
    out = []
    for d in SUGGESTED_DIRS:
        if os.path.isdir(d) and not any(_inside(d, c) or _inside(c, d) for c in current):
            out.append(d)
    return out


ROOTS = {}  # audit key -> [watched dir], filled at startup


def query_events(con, qs):
    where, args = [], []
    g = lambda k: (qs.get(k) or [""])[0]
    if g("after_id"):
        where.append("id > ?"); args.append(int(g("after_id")))
    if g("before_id"):
        where.append("id < ?"); args.append(int(g("before_id")))
    if g("action"):
        acts = [a for a in g("action").split(",") if a]
        if "denied" in acts:
            acts.remove("denied")
            cond = "success = 0" + (f" OR action IN ({','.join('?' * len(acts))})" if acts else "")
            where.append(f"({cond})"); args += acts
        elif acts:
            where.append(f"action IN ({','.join('?' * len(acts))})"); args += acts
    if g("user"):
        where.append("(COALESCE(auser,'sistem') = ? OR euser = ?)"); args += [g("user")] * 2
    if g("watch"):
        where.append("watch = ?"); args.append(g("watch"))
    if g("hidden") != "1":
        where.append("hidden = 0")
    if g("q"):
        like = f"%{g('q')}%"
        where.append("(path LIKE ? OR path2 LIKE ? OR exe LIKE ? OR cmd LIKE ?)"); args += [like] * 4
    if g("from"):
        where.append("ts >= ?"); args.append(float(g("from")))
    limit = max(1, min(int(g("limit") or 100), 500))  # -1 would mean "no limit" in SQLite
    sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "") + \
          " ORDER BY id DESC LIMIT ?"
    return [dict(r) for r in con.execute(sql, args + [limit])]


def query_stats(con, qs):
    hidden = (qs.get("hidden") or ["0"])[0] == "1"
    hf = "" if hidden else " AND hidden = 0"
    since = time.time() - 86400
    by_action = {r[0]: r[1] for r in con.execute(
        f"SELECT action, COUNT(*) FROM events WHERE success = 1{hf} GROUP BY action")}
    denied = con.execute(f"SELECT COUNT(*) FROM events WHERE success = 0{hf}").fetchone()[0]
    total = con.execute(f"SELECT COUNT(*) FROM events WHERE 1=1{hf}").fetchone()[0]
    users = [dict(user=r[0], n=r[1]) for r in con.execute(
        f"SELECT COALESCE(auser,'sistem') u, COUNT(*) n FROM events WHERE 1=1{hf} GROUP BY u ORDER BY n DESC LIMIT 8")]
    hours = [dict(h=int(r[0]), n=r[1]) for r in con.execute(
        f"SELECT CAST(ts/3600 AS INTEGER) h, COUNT(*) FROM events WHERE ts >= ?{hf} GROUP BY h", (since,))]
    top = [dict(path=r[0], n=r[1]) for r in con.execute(
        f"SELECT path, COUNT(*) n FROM events WHERE ts >= ?{hf} GROUP BY path ORDER BY n DESC LIMIT 6", (since,))]
    return dict(total=total, by_action=by_action, denied=denied, users=users, hours=hours,
                top_paths=top, now=time.time())


def is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def host_allowed(header):
    """Blocks DNS rebinding: a web page on another domain must not reach the panel via 127.0.0.1."""
    if not header:
        return False
    name = header.strip().lower()
    if name.startswith("["):  # [::1]:8088
        name = name[1:].split("]")[0]
    elif name.count(":") == 1:
        name = name.split(":")[0]
    allowed = {"127.0.0.1", "localhost", "::1"} | ALLOWED_HOSTS
    if not is_loopback(HOST) and HOST not in ("0.0.0.0", "::"):
        allowed.add(HOST.lower())
    return name in allowed


_fails = {}  # client ip -> [timestamps]
_fails_lock = threading.Lock()


def auth_locked(ip):
    now = time.time()
    with _fails_lock:
        recent = [t for t in _fails.get(ip, []) if t > now - AUTH_WINDOW]
        if recent:
            _fails[ip] = recent
        else:
            _fails.pop(ip, None)
        return len(recent) >= AUTH_MAX_FAILS


def auth_failed(ip):
    with _fails_lock:
        if len(_fails) > 10_000:
            _fails.clear()
        _fails.setdefault(ip, []).append(time.time())


def password_ok(header):
    if not header or not header.startswith("Basic "):
        return False
    try:
        _, _, given = base64.b64decode(header[6:], validate=True).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(given.encode(), PASSWORD.encode())


class Handler(BaseHTTPRequestHandler):
    con = None
    lock = threading.Lock()

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                         "form-action 'none'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def gate(self):
        """Host check and optional password. Returns True when the request may continue."""
        if not host_allowed(self.headers.get("Host")):
            self.send(421, b"unknown host", "text/plain")
            return False
        if not PASSWORD:
            return True
        ip = self.client_address[0]
        if auth_locked(ip):
            self.send(429, b"too many failed logins, try again in 15 minutes", "text/plain",
                      {"Retry-After": str(AUTH_WINDOW)})
            return False
        if password_ok(self.headers.get("Authorization")):
            return True
        if self.headers.get("Authorization"):
            auth_failed(ip)
        self.send(401, b"password required", "text/plain", {"WWW-Authenticate": 'Basic realm="AuditPulse"'})
        return False

    def do_GET(self):
        if not self.gate():
            return
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        try:
            if u.path == "/api/events":
                with self.lock:
                    data = query_events(self.con, qs)
            elif u.path == "/api/stats":
                with self.lock:
                    data = query_stats(self.con, qs)
            elif u.path == "/api/meta":
                w = watched()
                data = dict(host=os.uname().nodename, watched=w, can_edit=bool(PASSWORD),
                            suggestions=suggestions([x["dir"] for x in w]), max_watches=MAX_WATCHES)
            elif u.path in ("/", "/index.html"):
                with open(os.path.join(WEB, "index.html"), "rb") as f:
                    return self.send(200, f.read(), "text/html; charset=utf-8")
            else:
                return self.send(404, b"not found", "text/plain")
            self.send(200, json.dumps(data).encode(), "application/json")
        except (ValueError, sqlite3.Error):
            self.send(400, json.dumps(dict(error="invalid request")).encode(), "application/json")


def _same_origin(handler):
    """CSRF guard: the browser sends Basic auth to any site, so writes need our own header and origin."""
    if handler.headers.get("X-AuditPulse") != "1":
        return False
    origin = handler.headers.get("Origin")
    if origin:
        return host_allowed(urlparse(origin).netloc) and urlparse(origin).netloc == handler.headers.get("Host")
    return True


def do_POST(self):
    if not self.gate():
        return
    if urlparse(self.path).path != "/api/watches":
        return self.send(404, b"not found", "text/plain")
    reply = lambda code, **d: self.send(code, json.dumps(d).encode(), "application/json")
    if not PASSWORD:
        return reply(403, error="Qovluqları paneldən dəyişmək üçün əvvəlcə FA_PASSWORD təyin edin (README).")
    if not _same_origin(self):
        return reply(403, error="forbidden")
    try:
        size = int(self.headers.get("Content-Length") or 0)
        if size > 2048 or not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return reply(400, error="invalid request")
        body = json.loads(self.rfile.read(size) or b"{}")
        if not isinstance(body, dict):
            raise TypeError
    except (ValueError, TypeError):
        return reply(400, error="invalid request")
    action, path = body.get("action"), body.get("path")
    try:
        if action == "add":
            return reply(200, ok=True, path=add_watch(path))
        if action == "remove":
            return reply(200, ok=True, path=remove_watch(path))
        return reply(400, error="invalid request")
    except ValueError as exc:  # validation messages are written for the user
        return reply(400, error=str(exc))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"[watch] failed: {exc}", flush=True)
        return reply(500, error="Audit qaydası tətbiq olunmadı. Ətraflı: journalctl -u fileaudit")


Handler.do_POST = do_POST


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--install-rules":
        args, add, remove = sys.argv[3:], [], []
        while args:
            flag, value = args[0], (args[1] if len(args) > 1 else "")
            (add if flag == "--watch" else remove if flag == "--unwatch" else []).append(value)
            if flag not in ("--watch", "--unwatch") or not value:
                raise SystemExit(f"naməlum arqument: {flag}")
            args = args[2:]
        return install_rules(sys.argv[2], add, remove)
    if not is_loopback(HOST) and not PASSWORD:
        raise SystemExit(f"FA_HOST={HOST} opens the panel to the network: set FA_PASSWORD first "
                         "(in /etc/fileaudit.env). Refusing to start without a password.")
    for d, k in watch_rules():
        ROOTS.setdefault(k, []).append(d)
    Collector().start()
    Handler.con = db_connect()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"FileAudit dashboard on http://{HOST}:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
