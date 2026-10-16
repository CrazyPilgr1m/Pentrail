#!/usr/bin/env python3
"""pentrail - the pentest logbook.

Starts an engagement (VPN + a project folder laid out by methodology phase) and
then keeps the paperwork for you: a timestamped logbook, a Markdown working doc
per phase (scope, enum, foothold, privesc, lateral, report) whose auto blocks fill
themselves, finding files that become the report, and a scope guard.
`pentrail capture` records the shell you work in. It notes every command with its
time, stops commands aimed outside the scope, and reads the output of every
command that touches a target: ports, services, web paths, hostnames and leads,
each kept with the command that found it. For labs, engagements and bug bounty
programs you are authorized to test (HTB, OffSec, a scoped client engagement).

Pure Python 3, standard library only.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "1.2"                 # bump on every update (point release); see CHANGELOG.md
SCHEMA = 2                      # state.json layout version; _migrate() upgrades older files
HOME = Path.home()
CONFIG_FILE = Path(os.environ.get("PENTRAIL_CONFIG", HOME / ".config" / "pentrail" / "config.json"))
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local" / "state")) / "pentrail"
PID_FILE = STATE_DIR / "openvpn.pid"
LOG_FILE = STATE_DIR / "openvpn.log"
LAST_VPN_FILE = STATE_DIR / "last_vpn"
CURRENT_FILE = STATE_DIR / "current"
CAPTURE_MARKER = STATE_DIR / "capture.json"
HOOK_DIR = STATE_DIR / "hook"                 # rc files the capture shell loads (scope guard)
REDACT_FILE = CONFIG_FILE.parent / "redact"   # operator's own secrets, stored as hashes

DEFAULTS = {
    "base_dir": str(HOME / "pentests"),
    "vpn_dir": str(HOME / "vpn"),
    "default_vpn": "",        # fixed .ovpn; empty = last used, or pick from vpn_dir
    "connect_timeout": 30,    # seconds to wait for the tunnel
    "vpn_iface": "tun0",      # fallback if the interface is not in the log
    "stale_minutes": 25,      # nudge in 'next' when you've logged nothing for this long
    "termshot_cmd": "termshot",  # renderer for 'pentrail shot' terminal screenshots
    "web_tool": "feroxbuster",   # directory brute-forcer used in 'next' (feroxbuster/ffuf/gobuster)
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "src_repo": "",           # git checkout to pull from on 'pentrail update' (set by setup/update)
    "scope_guard": "strict",  # capture shell: strict = stop commands aimed outside scope, warn, off
    "scope_allow": "",        # extra hosts that are never targets (comma-separated), e.g. your VPS
    "author": "",             # tester name on the report
}
INT_KEYS = ("connect_timeout", "stale_minutes")
GUARD_MODES = ("strict", "warn", "off")

# Tools pentrail knows about, used by both 'doctor' (report) and 'setup' (install).
# Each row: command on $PATH, Debian/Kali apt package (None = not from apt), group.
#   core   - needed for the VPN + capture workflow itself
#   enum   - enumeration tools 'next' suggests; install the ones you use
#   extra  - optional, not installed from apt (see the note in TOOL_NOTES)
TOOLS = [
    ("openvpn",      "openvpn",       "core"),
    ("ip",           "iproute2",      "core"),
    ("ping",         "iputils-ping",  "core"),
    ("script",       "bsdutils",      "core"),
    ("termshot",     None,            "extra"),
    ("nmap",         "nmap",          "enum"),
    ("feroxbuster",  "feroxbuster",   "enum"),
    ("ffuf",         "ffuf",          "enum"),
    ("gobuster",     "gobuster",      "enum"),
    ("nikto",        "nikto",         "enum"),
    ("enum4linux-ng","enum4linux-ng", "enum"),
    ("smbclient",    "smbclient",     "enum"),
    ("snmpwalk",     "snmp",          "enum"),
    ("ldapsearch",   "ldap-utils",    "enum"),
    ("netexec",      "netexec",       "enum"),
    ("crackmapexec", "crackmapexec",  "enum"),
    ("hydra",        "hydra",         "enum"),
    ("hashcat",      "hashcat",       "enum"),
]
TOOL_NOTES = {
    "termshot": "github.com/homeport/termshot  (shot still saves text without it)",
}

def tools_in(group):
    return [(cmd, apt) for cmd, apt, g in TOOLS if g == group]

# Where directory/content wordlists usually live on Kali/Linux, and the filenames
# the 'next' web brute-force step wants (best first). Used by setup/doctor to find
# a usable wordlist when the configured one is missing.
WORDLIST_DIRS = [
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/share/wordlists/seclists/Discovery/Web-Content",
    "/usr/share/wordlists/dirbuster",
    "/usr/share/wordlists/dirb",
    "/usr/share/wordlists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wordlists/wfuzz/general",
    "/usr/share/wfuzz/wordlist/general",
    "~/wordlists",
    "~/.local/share/wordlists",
]
WORDLIST_NAMES = [
    "directory-list-2.3-medium.txt", "directory-list-2.3-small.txt",
    "raft-medium-directories.txt", "raft-small-directories.txt",
    "raft-large-directories.txt", "common.txt", "big.txt",
    "directory-list-lowercase-2.3-medium.txt",
]

def find_wordlists(limit=15):
    """Directory/content wordlists present in the known dirs, best first and
    de-duplicated by real path. Bounded: it only globs the known dirs, never the
    whole filesystem."""
    seen, out = set(), []
    def add(p):
        try:
            if not p.is_file():
                return
            rp = p.resolve()
        except OSError:
            return
        if rp not in seen:
            seen.add(rp); out.append(p)
    dirs = [Path(os.path.expanduser(d)) for d in WORDLIST_DIRS]
    dirs = [d for d in dirs if d.is_dir()]
    for name in WORDLIST_NAMES:               # preferred names first, in order
        for d in dirs:
            add(d / name)
            for sub in sorted(d.glob(f"*/{name}")):
                add(sub)
    for d in dirs:                            # then anything else list-shaped
        for pat in ("directory-list*.txt", "raft-*-directories*.txt", "*directories*.txt"):
            for f in sorted(d.glob(pat)):
                add(f)
    return out[:limit]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ----------------------------------------------------------------------------- output
_TTY = sys.stdout.isatty()
def _c(code): return code if _TTY else ""
R, G, Y, B, C, DIM, N = (_c(x) for x in
    ("\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[36m", "\033[2m", "\033[0m"))
def info(m): print(f"{B}[*]{N} {m}")
def ok(m):   print(f"{G}[+]{N} {m}")
def warn(m): print(f"{Y}[!]{N} {m}")
def err(m):  print(f"{R}[-]{N} {m}", file=sys.stderr)
def die(m, code=1):
    err(m); sys.exit(code)
def confirm(m):
    try:
        return input(f"{Y}[?]{N} {m} [y/N] ").strip().lower() in ("y", "j")
    except EOFError:
        return False

# ----------------------------------------------------------------------------- config
def load_config():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            if isinstance(data, dict):
                cfg.update(data)
            else:
                warn(f"Ignoring {CONFIG_FILE}: not a JSON object")
        except (json.JSONDecodeError, OSError) as e:
            warn(f"Could not read {CONFIG_FILE}: {e}")
    for k in ("base_dir", "vpn_dir"):
        cfg[k] = os.path.expanduser(cfg[k])
    for k in ("default_vpn", "src_repo"):
        cfg[k] = os.path.expanduser(cfg[k]) if cfg.get(k) else ""
    return cfg

def save_config(cfg):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2) + "\n")

def set_config(key, val):
    cfg = dict(load_config())
    cfg[key] = val
    save_config({k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS})
    CFG[key] = val

CFG = load_config()
SUDO = [] if os.geteuid() == 0 else ["sudo"]

def warn_if_root():
    """Least privilege: pentrail runs as your normal user and sudo's only the few
    steps that need root. Running the whole tool via sudo makes every file and the
    capture shell root-owned, so flag it."""
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        warn("Running under 'sudo pentrail'. This tool is meant to run as your normal "
             "user; it elevates only the VPN and /etc/hosts steps itself. As root it "
             "writes root-owned files in ~/pentests and opens a root capture shell.")
        warn(f"Re-run without sudo:  pentrail {' '.join(sys.argv[1:])}")

def _read(path, default=""):
    try:
        return path.read_text().strip()
    except OSError:
        return default

def _now():
    return f"{datetime.now():%Y-%m-%d %H:%M:%S}"

# ----------------------------------------------------------------------------- project state
def current_dir():
    d = _read(CURRENT_FILE)
    return Path(d) if d and Path(d).is_dir() else None

def require_engagement():
    d = current_dir()
    if not d:
        die("No active project - run 'pentrail new <name>' first")
    return d

def set_current(d):
    CURRENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_FILE.write_text(str(d))

def _atomic_write(path, text):
    """Write via a temp file + os.replace so a crash can't corrupt the target."""
    path = Path(path)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(text)
    os.replace(tmp, path)

def new_state():
    # hosts:    {ip, name, os, owned, added, ports[], aliases[]}  ('ip' may hold a domain)
    # names:    hostnames, vhosts and subdomains seen   {name, ip, by, added}
    # web:      web paths and URLs seen                 {host, url, status, note, by, added}
    # commands: what found things, for 'Found by'       {id, cmd, prog, ts, dur, rc, phase, file, hosts, via}
    return {"schema": SCHEMA, "target": "", "phase": "enum", "hosts": [], "vectors": [],
            "creds": [], "names": [], "web": [], "commands": [], "checks": {}, "dns": {}, "notes": [],
            "flags": [], "facts": {}, "focus": "", "ingested": {}}

def host_entry(ip, name="", os_=""):
    return {"ip": ip, "name": name, "os": os_, "owned": False, "added": _now(),
            "ports": [], "aliases": []}

def _migrate(st):
    """Bring an older state.json up to the current layout, in memory. Nothing is
    dropped: schema 1's plain list of hostnames becomes 'names' entries."""
    for k, v in new_state().items():
        st.setdefault(k, v)
    for h in st["hosts"]:
        for k, v in host_entry("").items():
            if k != "ip":
                h.setdefault(k, v)
    for n in st.pop("hostnames", None) or []:
        if isinstance(n, str) and not any(x.get("name") == n for x in st["names"]):
            st["names"].append({"name": n, "ip": "", "by": None, "added": ""})
    st["schema"] = SCHEMA
    return st

def load_state(d):
    st = new_state()
    f = d / "state.json"
    if f.exists():
        try:
            data = json.loads(f.read_text())
            if not isinstance(data, dict):
                raise json.JSONDecodeError("state.json is not a JSON object", "", 0)
            st.update(data)
        except json.JSONDecodeError:
            # never silently discard a corrupt state; back it up so a later save
            # can't overwrite the only copy, and tell the user.
            bad = f.with_name(f"state.bad.{datetime.now():%Y%m%d_%H%M%S}.json")
            try:
                f.replace(bad)
                warn(f"state.json was unreadable; kept a copy at {bad.name}. Starting fresh "
                     "state for this project (recover entries from that file if needed).")
            except OSError:
                pass
        except OSError:
            pass
    return _migrate(st)

def save_state(d, st, docs=True):
    """Persist state and refresh the auto blocks in the project's Markdown docs."""
    _atomic_write(d / "state.json", json.dumps(st, indent=2) + "\n")
    if docs:
        sync_docs(d, st)

def _env_value(d, key):
    m = re.search(rf'^(?:export\s+)?{key}="?(.*?)"?$', _read(d / ".env"), re.M)
    return m.group(1) if m else ""

def write_env(d, target, vip=None):
    if vip is None:
        vip = _env_value(d, "VPN_IP")
    (d / ".env").write_text(f'export TARGET="{target}"\nexport VPN_IP="{vip}"\nexport ENG="{d}"\n')

def current_target():
    d = current_dir()
    if not d:
        return ""
    return load_state(d).get("target") or _env_value(d, "TARGET")

def rel(d, p):
    """A path as shown in docs and messages: relative to the project folder."""
    try:
        return os.path.relpath(str(p), str(d))
    except ValueError:
        return str(p)

# ----------------------------------------------------------------------------- project layout
# One folder per methodology phase, each with its working doc. Captures, shots and
# their evidence go to the folder of the phase you are in.
PHASES = ("scope", "enum", "foothold", "privesc", "lateral", "report")
PHASE_DIRS = {p: f"{i}-{p}" for i, p in enumerate(PHASES)}
PHASE_ALIASES = {
    "recon": "enum", "scan": "enum", "scans": "enum", "scanning": "enum", "enumeration": "enum",
    "web": "enum", "exploit": "foothold", "initial": "foothold", "access": "foothold",
    "shell": "foothold", "user": "foothold", "pe": "privesc", "priv": "privesc", "root": "privesc",
    "escalation": "privesc", "pivot": "lateral", "movement": "lateral", "ad": "lateral",
    "reporting": "report", "findings": "report",
}
SUBDIRS = [*PHASE_DIRS.values(), "1-enum/scans", "5-report/findings", "loot"]

def phase_of(word):
    w = (word or "").lower()
    return w if w in PHASES else PHASE_ALIASES.get(w)

def phase_dir(d, phase):
    return d / PHASE_DIRS.get(phase, PHASE_DIRS["enum"])

def evidence_dir(d, phase):
    p = phase_dir(d, phase) / "evidence"
    p.mkdir(parents=True, exist_ok=True)
    return p

def scan_dirs(d):
    """Where nmap and friends write their files; 'scans/' is the pre-1.2 layout."""
    return [p for p in (d / "1-enum" / "scans", d / "scans") if p.is_dir()]

def evidence_files(d):
    out = []
    for p in [*(phase_dir(d, ph) / "evidence" for ph in PHASES), d / "evidence"]:
        if p.is_dir():
            out.extend(f for f in p.rglob("*") if f.is_file())
    return sorted(out)

def ensure_layout(d, scope_assets=()):
    """Create the phase folders and the working docs that are missing. Never
    moves or overwrites anything, so it is safe on projects from older versions."""
    for sub in SUBDIRS:
        (d / sub).mkdir(parents=True, exist_ok=True)
    try:                       # loot/ and state.json hold creds: keep it private
        os.chmod(d, 0o700)
    except OSError:
        pass
    ensure_docs(d, scope_assets)

# ----------------------------------------------------------------------------- logbook
def log_event(kind, text, d=None):
    """Append a timestamped, typed line to the project logbook."""
    d = d or current_dir()
    if not d:
        return
    f = d / "logbook.md"
    if not f.exists():
        f.write_text(f"# Logbook - {d.name}\n\n")
    with f.open("a") as fh:
        fh.write(f"- {datetime.now():%Y-%m-%d %H:%M:%S}  `{kind:<8}` {text}\n")

def cmd_log(args):
    d = require_engagement()
    f = d / "logbook.md"
    if not f.exists():
        info("Logbook is empty"); return
    lines = [l for l in f.read_text().splitlines() if l.startswith("- ")]
    n = args.n or len(lines)
    for l in lines[-n:]:
        m = re.search(r"`(\w+)", l)
        tag = m.group(1) if m else ""
        col = {"vector": C, "own": G, "pivot": Y, "note": B, "scope": R, "finding": G,
               "phase": Y}.get(tag, "")
        print(col + l + N if col else l)

# ----------------------------------------------------------------------------- helpers (VPN plumbing)
def iface():
    m = re.findall(r"TUN/TAP device (\S+) opened", _read(LOG_FILE))
    return m[-1] if m else CFG["vpn_iface"]

def _ip(args):
    try:
        return subprocess.run(["ip", *args], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""

def tun_ip(dev=None):
    dev = dev or iface()
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _ip(["-4", "-o", "addr", "show", "dev", dev]))
    return m.group(1) if m else ""

def tun_gw(dev=None):
    dev = dev or iface()
    m = re.search(r" via (\d+\.\d+\.\d+\.\d+)", _ip(["-4", "route", "show", "dev", dev]))
    return m.group(1) if m else ""

def our_pid():
    p = _read(PID_FILE)
    return int(p) if p.isdigit() else None

def process_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def vpn_running():
    return process_alive(our_pid())

def openvpn_pids():
    try:
        out = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, text=True).stdout
        return [int(x) for x in out.split()]
    except OSError:
        return []

def show_log(n=12):
    return "\n".join(_read(LOG_FILE).splitlines()[-n:])

def ping(host, count=1, wait=2, extra=None):
    cmd = ["ping", "-c", str(count), "-W", str(wait), *(extra or []), host]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def pick_vpn(arg=None):
    if arg:
        return arg
    if CFG["default_vpn"]:
        return CFG["default_vpn"]
    last = _read(LAST_VPN_FILE)
    if last:
        return last
    files = sorted(Path(CFG["vpn_dir"]).glob("*.ovpn")) if Path(CFG["vpn_dir"]).is_dir() else []
    if not files:
        die(f"No .ovpn files in {CFG['vpn_dir']} - put them there or pass a path: pentrail up <file.ovpn>")
    if len(files) == 1:
        return str(files[0])
    for i, f in enumerate(files, 1):
        print(f"  {i}) {f.name}")
    try:
        n = int(input("Pick a VPN file: "))
    except (ValueError, EOFError):
        die("Invalid choice")
    if not 1 <= n <= len(files):      # reject 0 and negatives (which would index from the end)
        die("Invalid choice")
    return str(files[n - 1])

LOG_HINTS = [
    (r"AUTH_FAILED|certificate verify failed|VERIFY ERROR",
     "Certificate/login rejected -> download a fresh .ovpn from the platform (regenerate)."),
    (r"TLS key negotiation failed|TLS handshake failed",
     "VPN server not answering -> try the TCP variant of your .ovpn or another server; some (wifi) networks block UDP."),
    (r"RESOLVE: Cannot resolve|Temporary failure in name resolution",
     "Cannot resolve the VPN server -> check your own internet/DNS."),
    (r"Network is unreachable",
     "No route to the VPN server -> check your own internet connection."),
    (r"Inactivity timeout|ping-restart",
     "Connection keeps dropping -> same .ovpn connected on another machine? They kick each other off."),
    (r"Cannot open TUN/TAP|TUNSETIFF|/dev/net/tun",
     "Cannot create a tun device -> 'sudo modprobe tun'; in a container/VM /dev/net/tun must be available."),
    (r"route add command failed|RTNETLINK answers: File exists",
     "Route conflict -> another VPN or your own network uses the same range. Stop other VPNs."),
    (r"Options error",
     "Error in the .ovpn file -> download it again."),
]
def log_hints():
    log = show_log(200)
    for pat, msg in LOG_HINTS:
        if re.search(pat, log):
            warn(msg)

# ----------------------------------------------------------------------------- VPN
def wait_for_tunnel():
    timeout = int(CFG["connect_timeout"])
    info(f"Waiting for tunnel (max {timeout}s) ...")
    for i in range(1, timeout + 1):
        time.sleep(1)
        if "Initialization Sequence Completed" in _read(LOG_FILE):
            dev = iface()
            ok(f"Connected - {dev}: {tun_ip(dev)}")
            return True
        if i >= 3 and not vpn_running():
            err("openvpn stopped while connecting. Last log lines:")
            print(show_log()); log_hints()
            return False
    err(f"No tunnel after {timeout}s. Last log lines:")
    print(show_log()); log_hints()
    warn("openvpn keeps retrying in the background - 'pentrail restart' or 'pentrail down' to stop.")
    return False

def stop_all_openvpn():
    subprocess.run([*SUDO, "pkill", "-x", "openvpn"])
    time.sleep(2)
    if openvpn_pids():
        subprocess.run([*SUDO, "pkill", "-9", "-x", "openvpn"])
    ok("openvpn processes stopped")

def vpn_up(arg=None):
    if not shutil.which("openvpn"):
        die("openvpn is not installed (sudo apt install openvpn)")
    ovpn = os.path.realpath(os.path.expanduser(pick_vpn(arg)))
    if not os.path.isfile(ovpn):
        die(f"VPN file not found: {ovpn}")
    if vpn_running():
        ok(f"VPN already running (pid {our_pid()}, {iface()}: {tun_ip()})")
        return True
    others = openvpn_pids()
    if others:
        warn(f"openvpn already running (pid: {' '.join(map(str, others))}). "
             "Two connections at once is the most common cause of a flaky VPN.")
        if confirm("Stop existing openvpn processes?"):
            stop_all_openvpn()
        else:
            die("Aborted")
    info(f"Connecting with {os.path.basename(ovpn)} ...")
    if SUDO:
        # openvpn needs root (tun device + routing table). Prime sudo best-effort so the
        # password prompt is up front, not buried once it daemonizes. Do NOT gate on it:
        # 'sudo -v' validates general sudo and ignores command-specific NOPASSWD rules,
        # so on a box that only grants NOPASSWD for openvpn it would fail. Let the real
        # 'sudo openvpn' call below authenticate (and fail cleanly) instead.
        info("openvpn needs root; you may be asked for your sudo password.")
        try:
            subprocess.run([*SUDO, "-v"])
        except OSError:
            pass
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_VPN_FILE.write_text(ovpn)
    PID_FILE.unlink(missing_ok=True)
    LOG_FILE.unlink(missing_ok=True)
    # --daemon detaches openvpn from this terminal: it keeps running as a root
    # background process after pentrail exits or the shell closes (persistent).
    if subprocess.run([*SUDO, "openvpn", "--cd", os.path.dirname(ovpn), "--config", ovpn,
                       "--daemon", "--writepid", str(PID_FILE), "--log", str(LOG_FILE)]).returncode != 0:
        die("openvpn could not start")
    connected = wait_for_tunnel()
    if connected:
        print(f"  {DIM}Runs as a background daemon - stays up after this terminal closes. "
              f"'pentrail down' stops it; 'pentrail watch' keeps it alive.{N}")
    return connected

def vpn_down():
    pid = our_pid()
    if process_alive(pid):
        info(f"Stopping VPN (pid {pid}) ...")
        subprocess.run([*SUDO, "kill", str(pid)])
        for _ in range(10):
            if not process_alive(pid):
                break
            time.sleep(1)
        if process_alive(pid):
            warn("Not responding, forcing")
            subprocess.run([*SUDO, "kill", "-9", str(pid)])
        ok("VPN stopped")
    elif openvpn_pids():
        warn(f"No pentrail-started VPN, but openvpn is running (pid: {' '.join(map(str, openvpn_pids()))})")
        if confirm("Stop all openvpn processes?"):
            stop_all_openvpn()
    else:
        info("No VPN running")
    PID_FILE.unlink(missing_ok=True)

def vpn_restart(arg=None):
    if not arg:
        arg = _read(LAST_VPN_FILE) or None
    vpn_down(); time.sleep(1); vpn_up(arg)

def vpn_status():
    if vpn_running():
        dev = iface()
        ok(f"VPN active - {os.path.basename(_read(LAST_VPN_FILE))}")
        print(f"    pid       : {our_pid()}")
        print(f"    interface : {dev}")
        print(f"    your IP   : {tun_ip(dev)}")
        print(f"    gateway   : {tun_gw(dev)}")
    else:
        warn("No VPN active (via pentrail)")
        if openvpn_pids():
            warn(f"Other openvpn processes: {' '.join(map(str, openvpn_pids()))}")
    d = current_dir()
    if d:
        print()
        project_summary(d, loglines=3)

def cmd_check(args):
    target = args.ip or current_target()
    problems = 0
    print("== VPN diagnosis ==")
    n = len(openvpn_pids())
    if n == 0:
        err("openvpn not running -> pentrail up"); problems += 1
    elif n > 1:
        err(f"{n} openvpn processes active (duplicate connection) -> pentrail restart"); problems += 1
    else:
        ok("openvpn running (1 process)")
    dev = iface(); vip = tun_ip(dev)
    if vip:
        ok(f"{dev} has IP {vip}")
    else:
        err(f"{dev} has no IP -> tunnel not established"); problems += 1
    if ping("1.1.1.1", wait=2):
        ok("Internet works")
    else:
        warn("No reply from 1.1.1.1 -> check your own network")
    gw = tun_gw(dev)
    if gw:
        if ping(gw, count=2, wait=2):
            ok(f"VPN gateway {gw} reachable")
        else:
            err(f"VPN gateway {gw} not responding -> tunnel stuck, pentrail restart"); problems += 1
    if target:
        m = re.search(r"dev (\S+)", _ip(["-4", "route", "get", target]))
        via = m.group(1) if m else ""
        if via == dev:
            ok(f"Route to {target} goes via {dev}")
        else:
            err(f"Route to {target} goes via '{via or 'none'}' instead of {dev} -> "
                "wrong VPN file/lab, or route conflict with your own network")
            problems += 1
        if ping(target, count=3, wait=2):
            ok(f"Target {target} responds to ping")
            try:
                mtu = int(_read(Path(f"/sys/class/net/{dev}/mtu"), "1500"))
            except ValueError:
                mtu = 1500
            if not ping(target, wait=2, extra=["-M", "do", "-s", str(mtu - 28)]) \
               and ping(target, wait=2, extra=["-M", "do", "-s", "1000"]):
                warn("Large packets don't arrive (MTU issue). Scans hanging? "
                     "Add 'mssfix 1200' (or 'tun-mtu 1200') to your .ovpn and pentrail restart.")
        else:
            warn(f"Target {target} does not respond to ping. Possible causes:")
            print("    - box not fully booted or expired -> start/reset it on the platform, wait 1-2 min")
            print("    - IP changed after a reset -> pentrail target <new-ip>")
            print("    - your .ovpn belongs to a different lab/region than the box")
            print("    - box blocks ICMP (many Windows boxes) - it may still be reachable")
    else:
        info("No target given (pentrail check <ip>) - target check skipped")
    recent = [l for l in show_log(200).splitlines()
              if re.search(r"ERROR|error|AUTH_FAILED|TLS Error|Inactivity timeout|restarting", l)]
    if recent:
        print(); warn("Recent messages in the openvpn log:")
        for l in recent[-5:]:
            print(f"    {l}")
        log_hints()
    print()
    ok("No VPN problems found") if problems == 0 else err(f"{problems} problem(s) found")

def cmd_watch(args):
    interval = args.interval
    if SUDO:
        subprocess.run([*SUDO, "-v"])   # prime sudo so unattended restarts work
    info(f"Watching VPN every {interval}s, restart after 3 failed checks (Ctrl+C to stop)")
    fails = 0
    while True:
        if SUDO:
            subprocess.run([*SUDO, "-n", "-v"], stderr=subprocess.DEVNULL)
        healthy = vpn_running() and bool(tun_ip())
        if healthy:
            gw = tun_gw()
            if gw and not ping(gw, count=2, wait=3):
                healthy = False
        if healthy:
            if fails > 0:
                ok(f"{datetime.now():%H:%M:%S} VPN healthy again")
            fails = 0
        else:
            fails += 1
            warn(f"{datetime.now():%H:%M:%S} VPN unhealthy ({fails}/3)")
        if fails >= 3:
            warn(f"{datetime.now():%H:%M:%S} restarting VPN ...")
            log_event("vpn", "auto-restarted by watch")
            vpn_restart(); fails = 0
        time.sleep(interval)


def vpn_configured(arg=None):
    """True when 'up' has a .ovpn to use without asking (it would stop otherwise)."""
    if arg or CFG["default_vpn"] or _read(LAST_VPN_FILE):
        return True
    vd = Path(CFG["vpn_dir"])
    return vd.is_dir() and any(vd.glob("*.ovpn"))

# ----------------------------------------------------------------------------- scope
# The scope lives in 0-scope/scope.md, a doc you edit (or paste a program's scope
# into). pentrail reads the '## In scope' and '## Out of scope' sections: one asset
# per line, the first word of the line is the asset, the rest is a comment.
SCOPE_DOC = "0-scope/scope.md"

# Words that look like hostnames but are files ("notes.md", "scan.txt").
FILE_EXTS = frozenset("""
    txt log md json xml yml yaml csv tsv html htm xhtml php phtml asp aspx jsp js mjs ts css
    py pyc sh bash zsh ps1 psm1 bat cmd exe dll so dylib c h cpp hpp go rs rb pl pm java
    class jar war ear zip gz tgz tar bz2 xz 7z rar iso img bin elf deb rpm apk pdf doc
    docx xls xlsx ppt pptx odt rtf png jpg jpeg gif svg ico bmp webp bak old orig swp tmp
    conf cfg ini env key pem crt cer der csr pfx p12 pub ovpn lst list dic pcap pcapng
    cap sql db sqlite sqlite3 mdb kdbx vhd vhdx vmdk ova msi lnk vbs hta eml msg nse
    rule rules out nmap gnmap cs vb lua tf hcl toml lock map wasm md5 sha1 sha256
""".split())
# Endings accepted as a real domain in a command line (plus every two-letter country
# code). A scope entry with any other ending is still recognised exactly.
COMMON_TLDS = frozenset("""
    com net org io co dev app ai me info biz xyz online site tech cloud store shop gov edu
    mil int arpa pro name mobi asia tel travel jobs aero coop museum eu global group network
    systems solutions services digital agency company media news live blog web world email
    link click space website host hosting security bank finance money health care law tools
    software codes run page art design studio one top club vip work ltd inc llc gmbh online
    local lan home corp internal intranet localdomain test example htb thm lab box vl offsec
""".split())
LAB_TLDS = ("htb", "thm", "local", "lab", "box", "vl", "offsec", "lan", "corp", "internal")
# Never a target, so never stopped: where you fetch tools and packages from.
ALWAYS_ALLOW = ("github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
                "pypi.org", "pythonhosted.org", "kali.org", "debian.org", "ubuntu.com",
                "docker.io", "docker.com", "npmjs.org", "npmjs.com", "go.dev", "golang.org",
                "crates.io", "rubygems.org", "nist.gov", "mitre.org", "exploit-db.com")
SELF_NAMES = ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")
SSH_LIKE = ("ssh", "scp", "sftp", "rsync", "ssh-copy-id", "mosh", "telnet", "sshpass")
PLACEHOLDERS = ("fuzz", "fuzz1", "fuzz2", "fuzz3", "w1", "w2", "w3", "*")

def _ip_obj(s):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None

_DOMAIN_FULL = re.compile(r"(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}")

def parse_asset(tok):
    """One scope entry: IP, CIDR, range (10.0.0.1-50), domain, *.domain or URL.
    Returns a dict with 'kind' (net|range|host|wild), 'value' and 'path', or None."""
    t = (tok or "").strip().strip("`'\"<>").rstrip(",;").rstrip(".")
    low = t.lower()
    if not low:
        return None
    if "://" in low:
        try:
            u = urlsplit(low)
            host = u.hostname or ""
        except ValueError:
            return None
        a = parse_asset(host) if host else None
        if not a:
            return None
        path = (u.path or "").rstrip("*")
        a["path"] = "" if path in ("", "/") else path
        a["raw"] = t
        return a
    if low.startswith("*."):
        dom = low[2:]
        return {"kind": "wild", "value": dom, "path": "", "raw": t} if _DOMAIN_FULL.fullmatch(dom) else None
    if "/" in low:
        try:
            net = ipaddress.ip_network(low, strict=False)
        except ValueError:
            return None
        return {"kind": "net", "net": net, "value": str(net), "path": "", "raw": t}
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})", low)
    if m:
        lo = _ip_obj(m.group(1))
        hi = _ip_obj(m.group(2)) if "." in m.group(2) else \
            _ip_obj(m.group(1).rsplit(".", 1)[0] + "." + m.group(2))
        if lo is None or hi is None or int(hi) < int(lo):
            return None
        return {"kind": "range", "lo": int(lo), "hi": int(hi), "value": low, "path": "", "raw": t}
    ip = _ip_obj(low)
    if ip is not None:
        return {"kind": "net", "net": ipaddress.ip_network(low), "value": low, "path": "", "raw": t}
    m = re.fullmatch(r"([^:]+):(\d{1,5})", low)          # host:port
    if m:
        return parse_asset(m.group(1))
    if _DOMAIN_FULL.fullmatch(low):
        return {"kind": "host", "value": low, "path": "", "raw": t}
    return None

def read_scope(d):
    """(in_entries, out_entries) parsed from 0-scope/scope.md; empty if absent."""
    text = re.sub(r"<!--.*?-->", "", _read(d / SCOPE_DOC), flags=re.S)
    inc, exc, cur = [], [], None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            m = re.match(r"#{1,6}\s*(in|out)[\s_-]*(?:of[\s_-]*)?scope\b", s, re.I)
            cur = (inc if m.group(1).lower() == "in" else exc) if m else None
            continue
        if cur is None or not s:
            continue
        if s.startswith("|"):                       # a table row: the first cell
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not cells or re.fullmatch(r":?-{2,}:?", cells[0] or "--"):
                continue
            s = cells[0]
        s = re.sub(r"^(?:[-*+]|\d+[.)])\s+", "", s)
        s = re.sub(r"^\[[ xX]\]\s+", "", s)
        a = parse_asset(s.split()[0]) if s else None
        if a:
            cur.append(a)
    return inc, exc

def etc_hosts():
    out = []
    for line in _read(Path("/etc/hosts")).splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and _ip_obj(parts[0]) is not None:
            out.append((parts[0], [n.lower() for n in parts[1:]]))
    return out

def _plausible_tld(tld):
    return (len(tld) == 2 and tld.isalpha() and tld not in FILE_EXTS) or tld in COMMON_TLDS

class Scope:
    """The project scope, plus what pentrail knows about hostnames: host aliases,
    names seen with an IP, DNS answers (state 'dns') and /etc/hosts. A name that
    resolves into the in-scope IPs is in scope; an out-of-scope name that resolves
    into them turns that IP into a conflict you have to settle."""
    def __init__(self, d=None, st=None):
        self.inc, self.exc = read_scope(d) if d else ([], [])
        st = st or {}
        self.ips_of = {}                    # name -> set of IPs it points at
        for h in st.get("hosts", []):
            for a in h.get("aliases", []):
                self._add(a, h["ip"])
        for n in st.get("names", []):
            self._add(n.get("name"), n.get("ip"))
        for name, rec in (st.get("dns") or {}).items():
            for ip in rec.get("ips", []):
                self._add(name, ip)
        if self.defined:
            for ip, names in etc_hosts():
                for n in names:
                    self._add(n, ip)
        self.domain = str((st.get("facts") or {}).get("domain", "")).lower()
        extra = [x.strip().lower() for x in str(CFG.get("scope_allow", "")).split(",") if x.strip()]
        self.allow = list(ALWAYS_ALLOW) + extra
        self.looked_up = {}                 # DNS answers fetched by this object
        self._own = None
        self._conf = None

    def _add(self, name, ip):
        if name and ip and _ip_obj(ip) is not None:
            self.ips_of.setdefault(name.lower().rstrip("."), set()).add(ip)

    def learn(self, name, ips):
        for ip in ips:
            self._add(name, ip)
        self._conf = None

    @property
    def defined(self):
        return bool(self.inc or self.exc)

    def has_ip_scope(self, which=None):
        es = self.inc + self.exc if which is None else which
        return any(e["kind"] in ("net", "range") for e in es)

    def own_ips(self):
        if self._own is None:
            ips = {"127.0.0.1", "::1", "0.0.0.0"}
            if os.environ.get("VPN_IP"):
                ips.add(os.environ["VPN_IP"])
            ips.update(re.findall(r"inet6?\s+([0-9a-fA-F.:]+)/", _ip(["-o", "addr"])))
            self._own = ips
        return self._own

    @staticmethod
    def _hit(e, host, ip, path=""):
        """True/False, or None when the host matches but the entry is limited to a
        path the command did not name."""
        k = e["kind"]
        if k == "net":
            hit = ip is not None and ip.version == e["net"].version and ip in e["net"]
        elif k == "range":
            hit = ip is not None and ip.version == 4 and e["lo"] <= int(ip) <= e["hi"]
        elif k == "host":
            hit = host == e["value"]
        else:
            hit = host.endswith("." + e["value"])
        if hit and e.get("path"):
            return path.startswith(e["path"]) if path else None
        return hit

    def listed(self, host, path=""):
        """'out' / 'in' / None from the scope entries alone (no DNS, no aliases)."""
        host = (host or "").lower().rstrip(".")
        ip = _ip_obj(host)
        if any(self._hit(e, host, ip, path) is True for e in self.exc):
            return "out"
        if any(self._hit(e, host, ip, path) is not False for e in self.inc):
            return "in"
        return None

    def entry_for(self, host):
        """The scope line that decides a host (for messages)."""
        host = host.lower().rstrip(".")
        ip = _ip_obj(host)
        for e in (*self.exc, *self.inc):
            if self._hit(e, host, ip) is not False:
                return e["raw"]
        return ""

    def _exact_in(self, ip):
        return any(e["kind"] == "net" and e["net"].num_addresses == 1 and ip in e["net"] for e in self.inc)

    def conflict_ips(self):
        """{ip: [out-of-scope names resolving to it]}, for IPs that are in scope only
        through a range. Listing such an IP on its own under In scope settles it."""
        if self._conf is None:
            self._conf = {}
            for name, ips in self.ips_of.items():
                if self.listed(name) != "out":
                    continue
                for ip in ips:
                    o = _ip_obj(ip)
                    if self.listed(ip) == "in" and not self._exact_in(o):
                        self._conf.setdefault(ip, []).append(name)
        return self._conf

    def verdict(self, host, path=""):
        """'in' | 'out' | 'conflict' | 'unknown' (not listed) | 'self' | 'allow' | 'none'."""
        if not self.defined:
            return "none"
        host = (host or "").lower().rstrip(".")
        ip = _ip_obj(host)
        if host in SELF_NAMES or (ip is not None and (ip.is_loopback or str(ip) in self.own_ips())):
            return "self"
        listed = self.listed(host, path)
        if ip is not None:
            if listed == "in" and not self._exact_in(ip) and str(ip) in self.conflict_ips():
                return "conflict"
            if listed:
                return listed
        else:
            if listed == "out":
                return "out"
            via = [self.listed(x) for x in self.ips_of.get(host, ())]
            if listed == "in":
                return "conflict" if "out" in via else "in"
            if "out" in via:
                return "out"
            if via and all(v == "in" for v in via):
                return "in"             # every address it resolves to is in scope
            if "in" in via:
                return "conflict"       # partly inside the scope: traffic may go either way
            if self.domain and (host == self.domain or host.endswith("." + self.domain)) \
                    and self.has_ip_scope(self.inc):
                return "in"             # the AD/DNS domain of an in-scope lab network
        if any(host == a or host.endswith("." + a) for a in self.allow):
            return "allow"
        return "unknown"

    def why(self, host):
        """Why a host got its verdict, when DNS or a conflict decided it."""
        host = host.lower().rstrip(".")
        if _ip_obj(host) is not None:
            names = self.conflict_ips().get(host)
            return f"out-of-scope {', '.join(sorted(names))} resolves to it" if names else ""
        ips = sorted(self.ips_of.get(host, ()))
        outs = [x for x in ips if self.listed(x) == "out"]
        if outs:
            return f"resolves to {', '.join(outs)}, out of scope by {self.entry_for(outs[0])}"
        ins = [x for x in ips if self.listed(x) == "in"]
        if ins and self.listed(host) is None:
            rest = [x for x in ips if x not in ins]
            if rest:
                return f"resolves to {', '.join(ins)} inside the scope, but also to {', '.join(rest)} outside it"
            return f"resolves to {', '.join(ins)} in {self.entry_for(ins[0])}"
        return ""

    def net_conflicts(self, net, excluded=()):
        return sorted(ip for ip in self.conflict_ips()
                      if _ip_obj(ip).version == net.version and _ip_obj(ip) in net
                      and not any(_ip_obj(ip) in x for x in excluded if x.version == net.version))

    def net_verdict(self, net, excluded=()):
        """For a whole network in a command (nmap 10.10.10.0/24). 'excluded' are the
        networks the command leaves out (nmap --exclude)."""
        if not self.defined:
            return "none"
        lo, hi = int(net[0]), int(net[-1])
        for e in self.exc:
            if e["kind"] == "net" and e["net"].version == net.version and net.overlaps(e["net"]) \
                    and not any(e["net"].subnet_of(x) for x in excluded if x.version == net.version):
                return "out"
            if e["kind"] == "range" and net.version == 4 and lo <= e["hi"] and hi >= e["lo"]:
                return "out"
        for e in self.inc:
            if (e["kind"] == "net" and e["net"].version == net.version and net.subnet_of(e["net"])) or \
                    (e["kind"] == "range" and net.version == 4 and e["lo"] <= lo and hi <= e["hi"]):
                return "conflict" if self.net_conflicts(net, excluded) else "in"
        return "unknown"

    def covers_subdomains(self, parent):
        """A FUZZ.<parent> style target is fine when a wildcard covers <parent>."""
        if any(e["kind"] == "wild" and (parent == e["value"] or parent.endswith("." + e["value"]))
               for e in self.inc):
            return True
        return parent in self.ips_of and self.verdict(parent) == "in"

    def out_under(self, parent):
        return [e["raw"] for e in self.exc
                if e["kind"] in ("host", "wild") and e["value"].endswith("." + parent)]

    def knows(self, name):
        return name in self.ips_of or any(
            self._hit(e, name, None) is not False for e in (*self.inc, *self.exc)
            if e["kind"] in ("host", "wild"))

    def lookup(self, names, timeout=2.0):
        """Resolve names this scope cannot judge yet, and learn the answers."""
        want = sorted({n for n in names if n and _ip_obj(n) is None and n not in self.ips_of})
        if not want or not self.has_ip_scope():
            return {}
        found = resolve_names(want, timeout)
        for n, ips in found.items():
            self.learn(n, ips)
        self.looked_up.update(found)
        return found

    def summary(self, n=4):
        def short(es):
            vals = [e["raw"] for e in es]
            return ", ".join(vals[:n]) + (f" (+{len(vals) - n})" if len(vals) > n else "")
        s = f"in: {short(self.inc) or '-'}"
        return s + (f"   out: {short(self.exc)}" if self.exc else "")

def resolve_names(names, timeout=3.0, limit=200):
    """{name: [ip, ...]} from the system resolver (/etc/hosts, then DNS), looked up
    in parallel. Names that take longer than 'timeout' in total are left out (and
    tried again later); names that do not resolve map to []."""
    import socket
    import threading
    res, lock, gate = {}, threading.Lock(), threading.Semaphore(24)
    def one(n):
        with gate:
            try:
                ips = sorted({i[4][0] for i in socket.getaddrinfo(n, None, proto=socket.IPPROTO_TCP)})
            except (OSError, UnicodeError, ValueError):
                ips = []
        with lock:
            res[n] = ips
    threads = [threading.Thread(target=one, args=(n,), daemon=True) for n in list(names)[:limit]]
    for t in threads:
        t.start()
    deadline = time.time() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.time()))
    with lock:
        return dict(res)

def scope_conflicts(scope):
    """(conflicts, notes): where the scope contradicts itself, directly or through
    DNS. Out of scope always wins; conflicts are what you should settle with the
    client or program."""
    conflicts, notes = [], []
    for e in scope.inc:
        for x in scope.exc:
            covered = False
            if e["kind"] in ("host", "wild") and x["kind"] in ("host", "wild") and not x.get("path"):
                covered = (x["kind"] == "host" and e["kind"] == "host" and e["value"] == x["value"]) or \
                    (x["kind"] == "wild" and (e["value"] == x["value"] or e["value"].endswith("." + x["value"])))
            elif e["kind"] == "net" and x["kind"] == "net" and e["net"].version == x["net"].version:
                covered = e["net"].subnet_of(x["net"])
            elif e["kind"] in ("net", "range") and x["kind"] in ("net", "range"):
                elo, ehi = (int(e["net"][0]), int(e["net"][-1])) if e["kind"] == "net" else (e["lo"], e["hi"])
                xlo, xhi = (int(x["net"][0]), int(x["net"][-1])) if x["kind"] == "net" else (x["lo"], x["hi"])
                covered = xlo <= elo and ehi <= xhi
            if covered:
                conflicts.append(f"{e['raw']} is listed in scope, but {x['raw']} is out of scope: "
                                 f"treated as out of scope.")
    for ip, names in sorted(scope.conflict_ips().items()):
        conflicts.append(f"{ip} is in scope through {scope.entry_for(ip)}, but out-of-scope "
                         f"{', '.join(sorted(names))} resolves to it. Ask before testing it; then list "
                         f"{ip} under In scope (or Out of scope).")
    ip_scope = scope.has_ip_scope(scope.inc)
    for name, ips in sorted(scope.ips_of.items()):
        if scope.listed(name) is None and scope.verdict(name) == "conflict":
            ins = sorted(x for x in ips if scope.listed(x) == "in")
            rest = sorted(x for x in ips if x not in ins)
            conflicts.append(f"{name} resolves to {', '.join(ins)} inside the scope, but also to "
                             f"{', '.join(rest)} outside it: requests may go either way. List the "
                             f"name or those addresses under In scope or Out of scope.")
        if scope.listed(name) != "in":
            continue
        outs = sorted(x for x in ips if scope.listed(x) == "out")
        if outs:
            conflicts.append(f"{name} is in scope, but resolves to {', '.join(outs)}, which is out of "
                             f"scope ({scope.entry_for(outs[0])}): commands on {name} are stopped.")
        elif ip_scope:
            elsewhere = sorted(x for x in ips if scope.listed(x) is None)
            if elsewhere:
                notes.append(f"{name} resolves to {', '.join(elsewhere)}, outside your IP scope: "
                             f"test it by name, not by IP.")
    return conflicts, notes

def resolved_into_scope(scope):
    """Names that are in scope only because they resolve into the in-scope IPs."""
    out = []
    for name, ips in sorted(scope.ips_of.items()):
        if scope.listed(name) is None and scope.verdict(name) == "in":
            ins = sorted(x for x in ips if scope.listed(x) == "in")
            out.append((name, ins, scope.entry_for(ins[0]) if ins else ""))
    return out

# --- which hosts does a command point at -----------------------------------------
WRAPPERS = ("sudo", "doas", "env", "time", "nohup", "timeout", "nice", "stdbuf", "command",
            "exec", "builtin", "noglob", "scope-ok", "proxychains", "proxychains4", "rlwrap")
WRAPPER_VALUE_OPTS = {"sudo": ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"),
                      "doas": ("-u", "-C"), "timeout": ("-s", "-k"), "nice": ("-n",),
                      "stdbuf": ("-i", "-o", "-e"), "proxychains": ("-f",), "proxychains4": ("-f",)}
INTERPRETERS = ("python", "python2", "python3", "perl", "ruby", "node", "php", "bash", "sh",
                "zsh", "pwsh")

def _words(cmd):
    try:
        return shlex.split(cmd, comments=False)
    except ValueError:
        return cmd.split()

def prog_of(cmd):
    """The program a command line runs: 'sudo nmap ...' -> nmap, 'python3 x.py' -> x.
    Only the first command of a pipeline counts."""
    words = _words(re.split(r"\|\||&&|[|;&]", cmd or "", maxsplit=1)[0])
    i, last = 0, ""
    while i < len(words):
        w = words[i]
        base = os.path.basename(w)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1; continue
        if base in WRAPPERS:
            last, i = base, i + 1
            vals = WRAPPER_VALUE_OPTS.get(base, ())
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in vals else 1
            if base == "timeout" and i < len(words) and re.match(r"^\d", words[i]):
                i += 1
            while base == "env" and i < len(words) and "=" in words[i]:
                i += 1
            continue
        if base in INTERPRETERS and i + 1 < len(words):
            j = i + 1
            while j < len(words) and words[j].startswith("-") and words[j] not in ("-m", "-c"):
                j += 1
            if j + 1 < len(words) and words[j] == "-m":
                return words[j + 1].lower()
            if j < len(words) and words[j] != "-c":
                return re.sub(r"\.(py|pl|rb|js|php|sh)$", "", os.path.basename(words[j]).lower())
            return base
        return re.sub(r"\.(py|pl|rb|sh)$", "", base.lower())
    return last

_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

def expand_vars(line, values):
    """Fill in $VAR / ${VAR} from 'values' (no command substitution, ever)."""
    def sub(m):
        v = values.get(m.group(1) or m.group(2))
        return v if v is not None else m.group(0)
    return _VAR_REF.sub(sub, line)

def project_env(d):
    st = load_state(d)
    return {"TARGET": st.get("target") or _env_value(d, "TARGET"),
            "VPN_IP": _env_value(d, "VPN_IP"), "ENG": str(d)}

_URL_IN = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://(?:[^\s/@'\"]*@)?(\[[0-9a-fA-F:.]+\]|[^\s/:'\"<>|;,()?#]+)"
                     r"(?::\d{1,5})?([/?#][^\s'\"<>|;]*)?", re.I)
_IP_IN = re.compile(r"(?<![\w.:/])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2})(?!\d)|-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})(?![\d.]))?(?![\w.])")
_DOM_IN = re.compile(r"(?<![\w.\-/\\~$%{])((?:[a-z0-9_*](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-]|\.[a-z0-9])", re.I)
_HEADER_ARG = re.compile(r"""(?:-H|--header)(?:\s+|=)(?:'[^']*'|"[^"]*"|\S+)|\bHost:\s*\S+""", re.I)

def _placeholder(host):
    first, _, rest = host.partition(".")
    if rest and (first in PLACEHOLDERS or "fuzz" in first):
        return rest, True
    return host, False

# Arguments that name hosts a scanner must skip (nmap/masscan --exclude, naabu -eh).
_EXCLUDE_ARG = re.compile(r"(?:--exclude(?:-hosts?|-ips?)?|-eh|-exclude-hosts)(?:\s+|=)(\S+)")
_EXCLUDE_FILE = re.compile(r"(?:--excludefile|--exclude-file|-ef)(?:\s+|=)(\S+)")

def hosts_in_command(cmd, cwd=None, scope=None):
    """The hosts a command line points at, as dicts {host, path, net, range,
    header, placeholder, excluded}. Hosts inside a request header (-H 'Host: x')
    are marked 'header' (they do not decide where traffic goes); hosts after
    --exclude are marked 'excluded'."""
    prog = prog_of(cmd)
    headers = [m.span() for m in _HEADER_ARG.finditer(cmd)]
    excl = [m.span(1) for m in _EXCLUDE_ARG.finditer(cmd)]
    out, seen = [], set()
    def add(pos, host, **kw):
        key = (host, kw.get("path", ""))
        if key in seen:
            return
        seen.add(key)
        e = {"host": host, "path": "", "net": None, "range": None, "placeholder": False,
             "header": any(a <= pos < b for a, b in headers),
             "excluded": any(a <= pos < b for a, b in excl)}
        e.update(kw)
        out.append(e)
    for m in _EXCLUDE_FILE.finditer(cmd):                 # nmap --excludefile list.txt
        f = Path(os.path.join(cwd or os.getcwd(), m.group(1)))
        for line in (_read(f).splitlines() if f.is_file() else []):
            a = parse_asset(line.split("#")[0].strip())
            if a and a["kind"] == "net":
                add(-1, a["value"], net=a["net"], excluded=True)
    buf = list(cmd)
    def blank(a, b):
        buf[a:b] = " " * (b - a)
    for m in _URL_IN.finditer(cmd):
        host = m.group(1).strip("[]").lower().rstrip(".")
        if "$" not in host and "{" not in host:
            host, ph = _placeholder(host)
            add(m.start(), host, path=m.group(2) or "", placeholder=ph)
        blank(*m.span())
    text = "".join(buf)
    for m in _IP_IN.finditer(text):
        ip, cidr, rng = m.groups()
        if _ip_obj(ip) is None:
            continue
        if cidr:
            try:
                add(m.start(), m.group(0), net=ipaddress.ip_network(f"{ip}/{cidr}", strict=False))
            except ValueError:
                pass
        elif rng:
            a = parse_asset(m.group(0))
            if a:
                add(m.start(), m.group(0), range=(a["lo"], a["hi"]))
        else:
            add(m.start(), ip)
        blank(*m.span())
    text = "".join(buf)
    for m in _DOM_IN.finditer(text):
        name = m.group(1).lower().rstrip(".")
        pos = m.start()
        if pos and text[pos - 1] == "@" and prog not in SSH_LIKE:
            continue                                   # an e-mail address, not a host
        if not (scope and scope.knows(name)):
            if not _plausible_tld(name.rsplit(".", 1)[-1]):
                continue
            if cwd and os.path.exists(os.path.join(cwd, name)):
                continue                               # a file in the current folder
        name, ph = _placeholder(name)
        add(pos, name, placeholder=ph)
    return out

# Commands that only work on local text and files; an IP in 'echo' or 'grep' is not
# traffic. A pipeline is judged per part: 'echo x | nc host 80' still checks nc.
LOCAL_CMDS = frozenset("""
    echo printf grep egrep fgrep rg cat less more head tail vi vim nvim nano emacs code subl
    gedit mousepad sed awk cut sort uniq wc ls ll la cd pwd cp mv rm mkdir rmdir touch chmod
    chown tee jq yq base64 xxd od hexdump file strings man which type history alias unalias
    export unset source column tr diff cmp find locate tree du df stat basename dirname
    realpath readlink date sleep true false clear reset exit pentrail md5sum sha1sum
    sha256sum gzip gunzip zip unzip tar 7z xclip xsel
""".split())

def guard_verdicts(scope, cmd, cwd=None, dns=True):
    """[(target, verdict, why)] for what a command points at, plus advice notes.
    Names the scope cannot judge yet are looked up in DNS first (when the scope
    has IPs or ranges), so a name inside an in-scope range is let through."""
    notes, hits = [], []
    for part in (p for p in re.split(r"\|\||&&|[|;&\n]", cmd) if p.strip()):
        if prog_of(part) not in LOCAL_CMDS:
            hits += hosts_in_command(part, cwd, scope)
    excluded = []
    for h in hits:
        if h["excluded"]:
            try:
                excluded.append(h["net"] if h["net"] is not None else ipaddress.ip_network(h["host"]))
            except ValueError:
                pass
    targets = [h for h in hits if not h["header"] and not h["excluded"]]
    if dns:
        scope.lookup([h["host"] for h in targets if h["net"] is None and not h["range"]
                      and not h["placeholder"] and scope.verdict(h["host"]) in ("unknown", "in")])
    res = []
    for h in targets:
        if h["net"] is not None or h["range"]:
            nets = [h["net"]] if h["net"] is not None else list(ipaddress.summarize_address_range(
                ipaddress.ip_address(h["range"][0]), ipaddress.ip_address(h["range"][1])))
            vs = {scope.net_verdict(n, excluded) for n in nets}
            v = next((x for x in ("out", "unknown", "conflict") if x in vs), "in" if "in" in vs else "none")
            conf = sorted({ip for n in nets for ip in scope.net_conflicts(n, excluded)})
            why = ""
            if v == "conflict":
                why = (f"contains {', '.join(conf)}, where out-of-scope "
                       f"{', '.join(sorted({x for ip in conf for x in scope.conflict_ips()[ip]}))} resolves"
                       f" - leave it out: --exclude {','.join(conf)}")
            res.append((h["host"], v, why))
            continue
        v = scope.verdict(h["host"], h["path"])
        if h["placeholder"]:
            if v != "out" and scope.covers_subdomains(h["host"]):
                v = "in"
            outs = scope.out_under(h["host"])
            if outs:
                notes.append(f"{', '.join(outs)} is out of scope: keep it out of your wordlist")
            res.append((f"FUZZ.{h['host']}", v, ""))
            continue
        res.append((h["host"], v, scope.why(h["host"])))
    return res, notes

def _save_lookups(d, st, scope):
    """Keep DNS answers the guard fetched, so the next check does not ask again."""
    if scope.looked_up:
        for n, ips in scope.looked_up.items():
            st["dns"][n] = {"ips": ips, "ts": _now()}
        save_state(d, st)

GUARD_TEXT = {"strict": "stops commands aimed outside the scope",
              "warn": "reports commands aimed outside the scope, does not stop them",
              "off": "does not check commands"}

def _live_capture():
    """The marker of the capture this shell runs in, if any."""
    if not os.environ.get("PENTRAIL_CAPTURE"):
        return None
    m = _read_marker()
    return m if m and process_alive(m.get("pid")) else None

def guard_mode():
    """The scope guard in effect: the running capture's own mode ('capture --warn',
    or 'scope guard' typed inside it), else the setting (config scope_guard)."""
    m = _live_capture()
    if m and m.get("guard") in GUARD_MODES:
        return m["guard"]
    mode = CFG.get("scope_guard", "strict")
    return mode if mode in GUARD_MODES else "strict"

def scope_gate(d, st, line, values=None, cwd=None):
    """Apply the scope guard to a command line. Returns (allowed, message lines).
    Used by the capture shell before each command and by 'shot' before it runs one.
    Blocks and overrides go to the logbook, so you have the trail if asked."""
    scope = Scope(d, st)
    mode = guard_mode()
    if not scope.defined or mode == "off":
        return True, []
    stripped = line.strip()
    override = stripped == "scope-ok" or stripped.startswith("scope-ok ") or \
        os.environ.get("PENTRAIL_SCOPE_OK") == "1"
    env = project_env(d)
    env.update(os.environ)
    env.update(values or {})
    expanded = expand_vars(stripped, env)
    res, notes = guard_verdicts(scope, expanded, cwd)
    _save_lookups(d, st, scope)
    msgs = [f"note: {n}" for n in notes]
    msgs += [f"{t}: {why}" for t, v, why in res if why and v == "in"]
    bad = [(t, v, why) for t, v, why in res if v in ("out", "unknown", "conflict")]
    if not bad:
        return True, msgs
    what = ", ".join(f"{t} ({VERDICT_TEXT[v]}{': ' + why if why else ''})" for t, v, why in bad)
    if override:
        log_event("scope", f"override: {expanded}  [{what}]", d)
        return True, msgs + [f"scope override for {what}: logged"]
    if mode == "warn":                    # informative: say it, log it, let it run
        log_event("scope", f"warned: {expanded}  [{what}]", d)
        return True, msgs + [f"out of scope (guard warn, running it): {what}. Logged."]
    log_event("scope", f"blocked: {expanded}  [{what}]", d)
    hint = ("  a conflict: ask the client or program, then list the IP under In scope or Out of scope"
            if any(v == "conflict" for _, v, _ in bad) else
            "  belongs in scope?  pentrail scope add <host>")
    return False, msgs + [f"BLOCKED: {what}. Not run.", f"  scope -> {scope.summary()}",
                          hint + "     run once anyway:  scope-ok <command>"]

def scope_append(d, which, values):
    """Add assets under '## In scope' or '## Out of scope' in scope.md. Returns
    the ones that were new."""
    ensure_docs(d)
    f = d / SCOPE_DOC
    lines = f.read_text().splitlines()
    inc, exc = read_scope(d)
    have = {(e["value"], e.get("path", "")) for e in (inc if which == "in" else exc)}
    head = re.compile(r"#{1,6}\s*%s[\s_-]*(?:of[\s_-]*)?scope\b" % which, re.I)
    idx = next((i for i, l in enumerate(lines) if head.match(l.strip())), None)
    if idx is None:
        lines += ["", "## In scope" if which == "in" else "## Out of scope"]
        idx = len(lines) - 1
    end = idx + 1
    while end < len(lines) and not lines[end].lstrip().startswith("#"):
        end += 1
    while end > idx + 1 and not lines[end - 1].strip():
        end -= 1
    added = []
    for v in values:
        a = parse_asset(v)
        if a and (a["value"], a.get("path", "")) not in have:
            have.add((a["value"], a.get("path", "")))
            added.append(v)
    lines[end:end] = [f"- {v}" for v in added]
    f.write_text("\n".join(lines) + "\n")
    return added

VERDICT_TEXT = {"in": "in scope", "out": "OUT of scope", "unknown": "not in scope",
                "conflict": "CONFLICT", "self": "your own machine",
                "allow": "tooling host (never a target)", "none": "no scope set"}

def resolve_all(d, st, scope=None, timeout=5.0):
    """Look up every name pentrail knows (found names, hostnames in the scope, host
    entries) and store the answers. Hosts get the names that point at them as
    aliases. Returns {name: [ips]}."""
    scope = scope or Scope(d, st)
    names = {n["name"] for n in st["names"]} | set(st["dns"]) | \
        {e["value"] for e in scope.inc + scope.exc if e["kind"] == "host"} | \
        {h["ip"] for h in st["hosts"] if _ip_obj(h["ip"]) is None}
    found = resolve_names(sorted(names), timeout, limit=1000)
    for n, ips in found.items():
        st["dns"][n] = {"ips": ips, "ts": _now()}
        scope.learn(n, ips)
        for ip in ips:
            h = _find_host(st, ip)
            if h and n != h["ip"] and n not in h["aliases"]:
                h["aliases"].append(n)
    return found

def cmd_scope(args):
    d = require_engagement()
    st = load_state(d)
    act, rest = (args.action or "show").lower(), list(args.rest or [])
    if act in ("add", "in", "out", "exclude"):
        which = "out" if act in ("out", "exclude") else "in"
        if not rest:
            die(f"Usage: pentrail scope {act} <ip|range|domain|*.domain|url> [...]")
        bad = [v for v in rest if not parse_asset(v)]
        if bad:
            die(f"Not an IP, range, domain or URL: {', '.join(bad)}")
        added = scope_append(d, which, rest)
        if added:
            log_event("scope", f"{'in' if which == 'in' else 'out of'} scope: {', '.join(added)}")
            ok(f"{'In' if which == 'in' else 'Out of'} scope: {', '.join(added)}  ({SCOPE_DOC})")
            scope = Scope(d, st)                 # where do the new names point?
            names = [a["value"] for a in map(parse_asset, added) if a["kind"] == "host"]
            for nm, ips in resolve_names(names, timeout=3.0).items() if scope.has_ip_scope() else ():
                st["dns"][nm] = {"ips": ips, "ts": _now()}
                scope.learn(nm, ips)
            save_state(d, st)                    # refresh the resolved/conflict blocks
            for c in scope_conflicts(scope)[0]:
                warn(c)
        else:
            info("Already listed.")
        return
    if act == "check":
        if not rest:
            die("Usage: pentrail scope check <host|url ...>")
        scope = Scope(d, st)
        if not scope.defined:
            info(f"No scope set yet ({SCOPE_DOC}): nothing is blocked.")
            return
        res, notes = guard_verdicts(scope, " ".join(rest), os.getcwd())
        _save_lookups(d, st, scope)
        if not res:
            info("No host, IP or URL found in that.")
        for t, v, why in res:
            col = {"in": G, "out": R, "unknown": Y, "conflict": R}.get(v, DIM)
            print(f"  {col}{VERDICT_TEXT[v]:<16}{N} {t}" + (f"  {DIM}{why}{N}" if why else ""))
        for n in notes:
            print(f"  {DIM}note: {n}{N}")
        return
    if act == "resolve":
        scope = Scope(d, st)
        if not scope.defined:
            info(f"No scope set yet ({SCOPE_DOC})."); return
        found = resolve_all(d, st, scope)
        save_state(d, st)
        for n, ips in sorted(found.items()):
            v = scope.verdict(n)
            col = {"in": G, "out": R, "unknown": Y, "conflict": R}.get(v, DIM)
            print(f"  {col}{VERDICT_TEXT[v]:<16}{N} {n:<36} {', '.join(ips) or DIM + 'no answer' + N}")
        info(f"{len(found)} name(s) looked up; answers kept in state.json, see {SCOPE_DOC}")
        _print_conflicts(scope)
        return
    if act == "guard":
        live = _live_capture()
        if not rest:
            info(f"Scope guard: {guard_mode()} - {GUARD_TEXT[guard_mode()]}"
                 + (" (this capture)" if live and live.get("guard") else ""))
            print(f"    setting: {CFG.get('scope_guard', 'strict')}   modes: strict | warn | off")
            return
        mode = rest[0].lower()
        if mode not in GUARD_MODES:
            die("Usage: pentrail scope guard strict|warn|off")
        if live:                              # inside a capture: this capture only, right away
            live["guard"] = mode
            _write_marker(live)
            log_event("scope", f"guard -> {mode} (capture {live.get('label')})")
            ok(f"Scope guard for this capture: {mode} - {GUARD_TEXT[mode]}")
            print(f"    {DIM}the setting stays {CFG.get('scope_guard', 'strict')} "
                  f"('pentrail config scope_guard {mode}' to keep it){N}")
        else:
            set_config("scope_guard", mode)
            log_event("scope", f"guard -> {mode}")
            ok(f"Scope guard: {mode} - {GUARD_TEXT[mode]}  (setting, used by every capture)")
        return
    if act != "show":
        die("Usage: pentrail scope [add|out|check|resolve|guard] ...")
    scope = Scope(d, st)
    live = _live_capture()
    print(f"{B}Scope{N} ({SCOPE_DOC})   guard: {guard_mode()}"
          + (" (this capture)" if live and live.get("guard") else ""))
    if not scope.defined:
        info("No scope set yet: nothing is blocked and everything parsed is logged.")
        print(f"    add assets with 'pentrail scope add <ip|range|domain|*.domain|url>' "
              f"or edit {SCOPE_DOC}")
        return
    for e in scope.inc:
        print(f"  {G}in {N}  {e['raw']}")
    for e in scope.exc:
        print(f"  {R}out{N}  {e['raw']}")
    res = resolved_into_scope(scope)
    if res:
        print(f"\n{B}Resolved into the scope{N} ({len(res)})")
        for name, ips, entry in res[:15]:
            print(f"  {G}in {N}  {name:<36} {DIM}-> {', '.join(ips)} ({entry}){N}")
        if len(res) > 15:
            print(f"  {DIM}... {len(res) - 15} more in {SCOPE_DOC}{N}")
    _print_conflicts(scope)

def _print_conflicts(scope):
    conflicts, notes = scope_conflicts(scope)
    if conflicts:
        print(f"\n{R}Conflicts{N} ({len(conflicts)}) - out of scope wins until you settle them:")
        for c in conflicts:
            print(f"  {R}!{N} {c}")
    if notes:
        print(f"\n{DIM}Notes:{N}")
        for x in notes[:10]:
            print(f"  {DIM}- {x}{N}")

# ----------------------------------------------------------------------------- project: new / use / resume / list
def _target_of(a):
    """The concrete host an asset gives you to work on (None for ranges)."""
    if a["kind"] == "host":
        return a["value"]
    if a["kind"] == "wild":
        return a["value"]
    if a["kind"] == "net" and a["net"].num_addresses == 1:
        return str(a["net"].network_address)
    return None

def cmd_new(args):
    name = args.name
    if name in (".", "..") or not re.match(r"^[A-Za-z0-9._-]+$", name):
        die("Name may only contain letters, digits and . _ - (and not '.' or '..')")
    assets = []
    for t in args.targets or []:
        a = parse_asset(t)
        if not a:
            die(f"Not an IP, range, domain or URL: {t}")
        assets.append((t, a))
    d = Path(CFG["base_dir"]) / name
    existed = (d / SCOPE_DOC).exists()
    if d.is_dir():
        info(f"Folder exists, reusing: {d}")
    d.mkdir(parents=True, exist_ok=True)
    set_current(d)

    # Scaffold everything to disk BEFORE touching the VPN, so a VPN that cannot come
    # up never leaves a half-made project. The tunnel IP goes into .env afterwards.
    ensure_layout(d, [t for t, _ in assets])
    if existed and assets:
        scope_append(d, "in", [t for t, _ in assets])
    st = load_state(d)
    target = next((x for x in (_target_of(a) for _, a in assets) if x), None) or st.get("target", "")
    if target and not _find_host(st, target):
        st["hosts"].append(host_entry(target, name if _ip_obj(target) else ""))
    st["target"] = target
    save_state(d, st)
    write_env(d, target, None)
    log_event("new", f"session started - target {target or '?'}"
              + (f", scope: {', '.join(t for t, _ in assets)}" if assets else ""))

    vip = ""
    if args.no_vpn:
        info("VPN skipped (--no-vpn).")
    elif not vpn_configured():
        warn(f"No .ovpn found in {CFG['vpn_dir']}, so no VPN was started. "
             "'pentrail up <file.ovpn>' when you need one, or pass --no-vpn.")
    else:
        if not vpn_running() and not vpn_up():
            warn("VPN not connected - see above, or use 'pentrail check' and 'pentrail restart'")
        vip = tun_ip()
        if vip:
            write_env(d, target, vip)
    if target and vip and _ip_obj(target):
        ok(f"Target {target} reachable") if ping(target, count=2, wait=2) else \
            warn(f"Target {target} not responding to ping (yet) - 'pentrail check' for diagnosis")
    print()
    ok(f"Project ready: {d}")
    print(f"    {DIM}0-scope/scope.md  1-enum/enum.md  2-foothold/  3-privesc/  4-lateral/  "
          f"5-report/report.md{N}")
    if not assets:
        print(f"    {Y}no scope yet{N}: pentrail scope add <ip|range|domain|*.domain>")
    print(f'    cd "{d}" && source .env      then: pentrail capture recon')

def resolve_project(name):
    """A project by name under base_dir, or a path to a project folder."""
    p = Path(os.path.expanduser(name))
    if p.is_dir() and ((p / "state.json").exists() or (p / "logbook.md").exists()):
        return p
    d = Path(CFG["base_dir"]) / name
    return d if d.is_dir() else None

def _projects():
    base = Path(CFG["base_dir"])
    if not base.is_dir():
        return []
    return sorted(d for d in base.iterdir()
                  if (d / "state.json").exists() or (d / "logbook.md").exists())

def latest_project():
    def mtime(d):
        f = d / "logbook.md"
        return f.stat().st_mtime if f.exists() else d.stat().st_mtime
    return max(_projects(), key=mtime, default=None)

def project_summary(d, loglines=6):
    st = load_state(d)
    owned = sum(1 for h in st["hosts"] if h["owned"])
    openp = [p for p in st["vectors"] if p["status"] in ("open", "working")]
    dom = st.get("facts", {}).get("domain")
    info(f"Project {B}{d.name}{N}   target: {st.get('target') or '-'}   phase: {st.get('phase')}"
         + (f"   domain: {dom}" if dom else ""))
    sc = Scope(d, st)
    print(f"    scope  : {sc.summary() + '   guard: ' + guard_mode() if sc.defined else Y + 'not set' + N + ' (pentrail scope add ...)'}")
    if st.get("focus"):
        print(f"    focus  : {Y}{st['focus']}{N}")
    if st["hosts"]:
        nports = sum(len(h["ports"]) for h in st["hosts"])
        print(f"    hosts  : {len(st['hosts'])} ({owned} owned), {nports} open port(s), "
              f"{len(st['web'])} web path(s), {len(st['names'])} name(s)")
    print(f"    vectors: {len(openp)} open/working of {len(st['vectors'])}"
          + (f"   creds: {len(_norm_creds(st))}" if st.get("creds") else "")
          + (f"   findings: {len(list_findings(d))}" if list_findings(d) else ""))
    for p in [p for p in st["vectors"] if p["status"] == "working"][:5]:
        print(f"      {C}working{N} #{p['id']} {p['desc']}")
    facts = {k: v for k, v in st.get("facts", {}).items() if k != "domain"}
    if facts:
        print("    facts  : " + ", ".join(f"{k}={v}" for k, v in facts.items()))
    lines = [l for l in _read(d / "logbook.md").splitlines() if l.startswith("- ")]
    if lines and loglines:
        print("    last activity:")
        for l in lines[-loglines:]:
            print(f"      {DIM}{l[2:]}{N}")

def cmd_use(args):
    d = resolve_project(args.name)
    if not d:
        die(f"No project '{args.name}' in {CFG['base_dir']} - run 'pentrail new {args.name}'")
    set_current(d)
    ensure_layout(d)
    st = load_state(d)
    save_state(d, st)
    ok(f"Active project: {d.name} (target: {st.get('target') or '-'})")
    print(f'    cd "{d}" && source .env')

def cmd_resume(args):
    if args.name:
        d = resolve_project(args.name)
        if not d:
            die(f"No project '{args.name}' (see 'pentrail list')")
    else:
        d = current_dir() or latest_project()
        if not d:
            die("No project to resume. Start one with 'pentrail new <name>'.")
    set_current(d)
    ensure_layout(d)
    save_state(d, load_state(d))
    ok(f"Resumed {d.name}")
    log_event("resume", "session resumed")
    if vpn_running():
        ok(f"VPN already up ({iface()}: {tun_ip()})")
    elif vpn_configured():
        info("Reconnecting VPN ...")
        vpn_up()
    print()
    project_summary(d)
    print(f'\n    cd "{d}" && source .env')

def cmd_list(args):
    cur = current_dir()
    projs = _projects()
    if not projs:
        info("No projects yet - 'pentrail new <name>'"); return
    for d in projs:
        st = load_state(d)
        mark = f"{G}*{N}" if cur and d == cur else " "
        owned = sum(1 for h in st["hosts"] if h["owned"])
        openp = sum(1 for p in st["vectors"] if p["status"] in ("open", "working"))
        print(f" {mark} {d.name:<18} target {st.get('target') or '-':<15} {st.get('phase', ''):<9}"
              f"{len(st['hosts'])} host(s), {owned} owned, {openp} open vector(s), "
              f"{len(list_findings(d))} finding(s)")

def cmd_phase(args):
    d = require_engagement()
    st = load_state(d)
    if not args.name:
        for p in PHASES:
            mark = f"{G}>{N}" if p == st.get("phase") else " "
            print(f" {mark} {p:<9} {PHASE_DIRS[p]}/{DOC_FILES.get(p, '')}")
        print(f"\n{DIM}Set it with 'pentrail phase <name>'; 'pentrail capture <phase>' sets it too.{N}")
        return
    p = phase_of(args.name)
    if not p:
        die(f"Unknown phase '{args.name}'. Phases: {', '.join(PHASES)}")
    st["phase"] = p
    save_state(d, st)
    log_event("phase", p)
    ok(f"Phase: {p}  (captures and shots now go to {PHASE_DIRS[p]}/)")

def cmd_docs(args):
    d = require_engagement()
    ensure_layout(d)
    st = load_state(d)
    sync_docs(d, st)
    print(f"{B}Working docs{N} ({d.name}) - auto blocks refreshed, your own text untouched")
    for p in PHASES:
        f = phase_dir(d, p) / DOC_FILES[p]
        print(f"  {p:<9} {rel(d, f)}")
    fs = list_findings(d)
    print(f"  findings  5-report/findings/ ({len(fs)})")
    print(f"  notes     {NOTES_DOC} ({len(st['notes'])})")
    print(f"  logbook   logbook.md")

# ----------------------------------------------------------------------------- hosts & lateral movement
def _find_host(st, key):
    k = (key or "").lower()
    return next((h for h in st["hosts"] if h["ip"].lower() == k or (h.get("name") or "").lower() == k
                 or k in [a.lower() for a in h.get("aliases", [])]), None)

def _keys(h):
    return {h["ip"], *h.get("aliases", [])}

def _canon(st, addr):
    """The tracked host an address or name belongs to (its 'ip'), else the address."""
    h = _find_host(st, addr) if addr else None
    return h["ip"] if h else addr

def _ensure_host(st, addr, name=""):
    h = _find_host(st, addr)
    if not h:
        h = host_entry(addr, name)
        st["hosts"].append(h)
    elif name and not h.get("name"):
        h["name"] = name
    return h

def cmd_target(args):
    d = require_engagement()
    st = load_state(d)
    h = _find_host(st, args.ip)
    if h:
        ip = h["ip"]
    else:
        a = parse_asset(args.ip)
        ip = _target_of(a) if a and a["kind"] in ("net", "host") else None
        if not ip:
            die(f"Give an IP or hostname, or the name of a known host (see 'pentrail hosts'). Unknown: {args.ip}")
        st["hosts"].append(host_entry(ip, args.name or ""))
        v = Scope(d, st).verdict(ip)
        if v in ("out", "unknown"):
            warn(f"{ip} is {VERDICT_TEXT[v]} - 'pentrail scope add {ip}' if it should be")
    st["target"] = ip
    save_state(d, st)
    write_env(d, ip)
    log_event("target", f"active box -> {ip}")
    ok(f"Active box: {ip}  (re-run 'source .env' in open shells)")

def _ports_short(h, n=6):
    ps = [f"{p['port']}/{p['service'] or '?'}" for p in sorted(h["ports"], key=lambda p: p["port"])]
    return " ".join(ps[:n]) + (f" +{len(ps) - n}" if len(ps) > n else "")

def show_host(d, st, h):
    flag = f"{G}OWNED{N}" if h["owned"] else f"{DIM}not owned{N}"
    print(f"{B}{h['ip']}{N} {h.get('name', '')} {h.get('os', '')} [{flag}]")
    names = sorted(set(h.get("aliases", [])) | {n["name"] for n in st["names"] if n.get("ip") == h["ip"]})
    if names:
        print(f"  names: {', '.join(names)}")
    if h["ports"]:
        print(f"\n  {B}Ports{N}")
        for p in sorted(h["ports"], key=lambda p: p["port"]):
            print(f"    {G}{p['port']:>5}/{p['proto']}{N} {p['service']:<14} {p.get('version', '')}"
                  f"  {DIM}{src_str(st, p.get('by'))}{N}")
    web = [w for w in st["web"] if w["host"] in _keys(h)]
    if web:
        print(f"\n  {B}Web{N} ({len(web)})")
        for w in web[:40]:
            print(f"    {w.get('status') or '   '} {w['url']}  {DIM}{w.get('note', '')}{N}")
        if len(web) > 40:
            print(f"    {DIM}... {len(web) - 40} more in 1-enum/enum.md{N}")
    vs = [v for v in st["vectors"] if v.get("host") in _keys(h)]
    if vs:
        print(f"\n  {B}Leads{N}")
        for v in vs:
            print(f"    #{v['id']:<3} {STATUS_COL.get(v['status'], '')}{v['status']:<8}{N} [{v.get('type')}] {v['desc']}")
    L = _note_links(d, st)
    ns = [n for n in st["notes"] if n.get("host") == h["ip"] or h["ip"] in _mentions(n, L)]
    if ns:
        print(f"\n  {B}Notes{N}")
        for n in ns:
            print(f"    N{n['id']:<3} {DIM}{n['ts'][5:16]}{N} {n['text']}"
                  + (f" {DIM}(on {n.get('host') or 'project'}){N}" if n.get("host") != h["ip"] else ""))

def cmd_hosts(args):
    d = require_engagement()
    st = load_state(d)
    if getattr(args, "ip", None):
        h = _find_host(st, args.ip)
        if not h:
            die(f"Unknown host {args.ip} (see 'pentrail hosts')")
        return show_host(d, st, h)
    if not st["hosts"]:
        info("No hosts yet - captures add them, or 'pentrail host add <ip> [name]'"); return
    for h in st["hosts"]:
        flag = f"{G}OWNED{N}" if h["owned"] else f"{DIM}-{N}"
        tgt = f"  {C}<- target{N}" if h["ip"] == st.get("target") else ""
        print(f"  {h['ip']:<16} {h.get('name', ''):<14} {h.get('os', '')[:10]:<10} [{flag}] "
              f"{_ports_short(h)}{tgt}")
    pivots = [l for l in _read(d / "logbook.md").splitlines() if "`pivot" in l]
    if pivots:
        print(f"\n{B}Lateral movement{N}:")
        for l in pivots:
            m = re.search(r"`pivot\s*`\s*(.*)$", l)
            print(f"  {l[2:21]}  {m.group(1) if m else ''}")
    print(f"\n{DIM}Details of one host: pentrail hosts <ip|name>{N}")

def cmd_host(args):
    d = require_engagement()
    st = load_state(d)
    action = args.action
    if action not in ("add", "own", "rm", "del", "remove"):
        args.ip = action
        return cmd_hosts(args)
    if action == "add":
        if not args.ip:
            die("Usage: pentrail host add <ip> [name] [os]")
        if _find_host(st, args.ip):
            info(f"Host {args.ip} already tracked")
        else:
            st["hosts"].append(host_entry(args.ip, args.name or "", args.os or ""))
            log_event("host", f"added {args.ip} {args.name or ''}".strip())
            ok(f"Host {args.ip} added")
    elif action == "own":
        if not args.ip:
            die("Usage: pentrail host own <ip>")
        h = _ensure_host(st, args.ip, args.name or "")
        h["owned"] = True
        log_event("own", f"foothold / compromised {h['ip']} {h.get('name', '')}".strip())
        ok(f"Marked {h['ip']} as owned")
        if st.get("phase") in ("scope", "enum"):
            print(f"    {DIM}next phase? pentrail phase foothold  (or privesc){N}")
    else:
        h = _find_host(st, args.ip) if args.ip else None
        if not h:
            die("Usage: pentrail host rm <ip|name>")
        st["hosts"] = [x for x in st["hosts"] if x is not h]
        log_event("host", f"removed {h['ip']} {h.get('name', '')}".strip())
        ok(f"Removed host {h['ip']}")
    save_state(d, st)

def cmd_pivot(args):
    d = require_engagement()
    st = load_state(d)
    if not _find_host(st, args.dst):
        st["hosts"].append(host_entry(args.dst))
        ok(f"New host {args.dst} added")
    log_event("pivot", f"{args.src} -> {args.dst}" + (f" ({args.via})" if args.via else ""))
    save_state(d, st)
    ok(f"Lateral movement logged: {args.src} -> {args.dst}")

def cmd_names(args):
    d = require_engagement()
    st = load_state(d)
    names = sorted(st["names"], key=lambda n: n["name"])
    if args.plain:
        for n in names:
            print(n["name"])
        return
    if not names:
        info("No hostnames or subdomains yet; captures add the ones they see in scope."); return
    for n in names:
        print(f"  {n['name']:<40} {n.get('ip') or '':<16} {DIM}{src_str(st, n.get('by'))}{N}")
    print(f"\n{B}{len(names)} name(s){N}. One per line for other tools: pentrail names --plain")

# ----------------------------------------------------------------------------- attack vectors (leads)
VALID_STATUS = ("open", "working", "dead", "done")
STATUS_COL = {"open": Y, "working": C, "dead": DIM, "done": G}
STATUS_ORDER = {"working": 0, "open": 1, "done": 2, "dead": 3}

def _next_pid(st):
    return max((p["id"] for p in st["vectors"]), default=0) + 1

# Suggested vector types; any string is allowed, these are just the common ones.
PATH_TYPES = ["web", "sqli", "lfi", "rfi", "rce", "upload", "xxe", "ssrf", "deserial",
              "cred", "default-cred", "brute", "smb", "snmp", "nfs", "ftp",
              "kernel", "privesc", "suid", "sudo", "cron", "lateral", "misc"]

def add_vector(d, st, desc, host="", status="open", sig=None, ptype="misc", by=None,
               excerpt="", url="", sev=""):
    """Add an attack vector if not already present (deduped by signature)."""
    sig = sig or desc
    if any(p.get("sig") == sig for p in st["vectors"]):
        return None
    pid = _next_pid(st)
    st["vectors"].append({"id": pid, "host": host, "desc": desc, "status": status,
                          "type": ptype, "sig": sig, "added": _now(), "by": by,
                          "excerpt": excerpt[:1500], "url": url, "sev": sev})
    log_event("vector", f"#{pid} [{ptype}] {desc}" + (f" on {host}" if host else ""), d)
    return pid

USAGE_VECTOR = ('Usage: pentrail vector add "<desc>" [-t <type>]   |   '
                "pentrail vector <status> <id>   (status: open|working|dead|done)   |   vector rm <id>")

def cmd_vector(args):
    """One command for leads: no args lists them, 'add', a status verb, or 'rm'."""
    d = require_engagement()
    st = load_state(d)
    verb = (args.action or "").lower()
    rest = list(args.rest or [])
    if not verb or verb not in ("add", "rm", "del", "remove", *VALID_STATUS) and not verb.isdigit():
        return _list_vectors(st, verb or None)
    if verb.isdigit() and rest and rest[0] in VALID_STATUS:      # 'vector 3 working'
        verb, rest = rest[0], [verb]
    if verb == "add":
        desc = " ".join(rest)
        if not desc:
            die(USAGE_VECTOR)
        ptype = (args.type or "misc").lower()
        pid = add_vector(d, st, desc, host=st.get("target", ""), ptype=ptype)
        save_state(d, st)
        ok(f"Attack vector #{pid} added [{ptype}]") if pid else info("Already tracked")
        return
    if not rest or not rest[0].isdigit():
        die(USAGE_VECTOR)
    pid = int(rest[0])
    p = next((p for p in st["vectors"] if p["id"] == pid), None)
    if not p:
        die(f"No attack vector #{pid}")
    if verb in ("rm", "del", "remove"):
        st["vectors"] = [x for x in st["vectors"] if x["id"] != pid]
        log_event("vector", f"#{pid} removed ({p['desc']})")
        ok(f"Removed vector #{pid}")
    else:
        p["status"] = verb
        log_event("vector", f"#{pid} -> {verb}  ({p['desc']})")
        ok(f"#{pid} set to {verb}")
    save_state(d, st)

def _list_vectors(st, want=None):
    paths = st["vectors"]
    if not paths:
        info("No attack vectors yet. They appear from 'pentrail capture' / 'pentrail ingest', "
             "or add one with 'pentrail vector add \"<desc>\" -t <type>'.")
        return
    if want:
        paths = [p for p in paths if p.get("type", "misc") == want]
        if not paths:
            info(f"No '{want}' attack vectors. Types in use: "
                 + ", ".join(sorted({p.get('type', 'misc') for p in st['vectors']})))
            return
    for p in sorted(paths, key=lambda p: (STATUS_ORDER.get(p["status"], 1), p["id"])):
        col = STATUS_COL.get(p["status"], "")
        host = f" {DIM}[{p['host']}]{N}" if p.get("host") else ""
        fnd = f" {G}-> {p['finding']}{N}" if p.get("finding") else ""
        print(f"  {col}#{p['id']:<3} {p['status']:<8}{N} {C}{p.get('type', 'misc'):<11}{N} {p['desc']}{host}{fnd}")
    openc = sum(1 for p in paths if p["status"] in ("open", "working"))
    label = f"'{want}' " if want else ""
    print(f"\n{B}{len(paths)} {label}attack vectors{N}, {openc} still worth trying. "
          f"{DIM}Confirmed one? pentrail finding <id>{N}")
def cred_kind(secret):
    """Classify a secret so hashes and passwords can be separated later."""
    s = (secret or "").strip()
    if not s:
        return "username"
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return "ntlm"
    if s.startswith("$") or re.fullmatch(r"[0-9a-fA-F]{40,}", s):
        return "hash"
    return "password"

def cred_entry(user="", secret="", host="", src="manual", kind=None):
    return {"user": user, "secret": secret, "kind": kind or cred_kind(secret),
            "host": host, "src": src, "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"}

def cred_sig(c):
    return f"{c.get('user','').lower()}|{c.get('secret','')}|{c.get('kind','')}"

def cred_str(c):
    if c["kind"] == "username":
        return c["user"]
    return f"{c['user']}:{c['secret']}" if c["user"] else c["secret"]

def _norm_creds(st):
    """Tolerate older string-form creds, upgrade them to dicts in memory."""
    out = []
    for c in st.get("creds", []):
        if isinstance(c, dict):
            out.append(c)
        else:  # legacy "key=value" or "user:pass" string
            txt = str(c)
            if "=" in txt and txt.split("=", 1)[0].lower() in ("user", "username", "login"):
                out.append(cred_entry(user=txt.split("=", 1)[1], src="legacy"))
            elif ":" in txt:
                u, s = txt.split(":", 1); out.append(cred_entry(user=u, secret=s, src="legacy"))
            else:
                out.append(cred_entry(secret=txt.replace("password=", "").replace("pass=", ""), src="legacy"))
    st["creds"] = out
    return out

def add_cred(st, c):
    """Add a structured credential if new. Returns True when added."""
    _norm_creds(st)
    if any(cred_sig(x) == cred_sig(c) for x in st["creds"]):
        return False
    st["creds"].append(c)
    return True

def cmd_creds(args):
    d = require_engagement()
    st = load_state(d)
    creds = _norm_creds(st)
    what = getattr(args, "what", None)

    # plain, pipe-friendly sub-lists: pentrail creds users > users.txt
    if what in ("users", "passwords", "hashes"):
        if what == "users":
            vals = [c["user"] for c in creds if c.get("user")]
        elif what == "passwords":
            vals = [c["secret"] for c in creds if c["kind"] == "password"]
        else:
            vals = [c["secret"] for c in creds if c["kind"] in ("hash", "ntlm")]
        seen = set()
        for v in vals:
            if v not in seen:
                seen.add(v); print(v)
        return
    if what == "export":
        return _creds_export(d, creds, args.rest[0] if args.rest else None)

    if not creds:
        info("No credentials yet. Captured automatically, or add one with "
             "'pentrail cred add <user>:<secret>'  (user:pass, user:hash, or just a hash).")
        return
    for i, c in enumerate(creds, 1):
        host = f" {DIM}@{c['host']}{N}" if c.get("host") else ""
        print(f"  {i:>2}. {C}{c['kind']:<9}{N} {cred_str(c)}{host}")
    u = len({c['user'] for c in creds if c.get('user')})
    h = sum(1 for c in creds if c['kind'] in ('hash', 'ntlm'))
    print(f"\n{B}{len(creds)} credential(s){N}: {u} user(s), {h} hash(es). "
          "Build lists with 'pentrail creds users|passwords|hashes', "
          "or 'pentrail creds export'.")

def _creds_export(d, creds, dest=None):
    out = Path(dest) if dest else (d / "loot")
    out.mkdir(parents=True, exist_ok=True)
    users = sorted({c["user"] for c in creds if c.get("user")})
    pws = sorted({c["secret"] for c in creds if c["kind"] == "password"})
    hashes = sorted({c["secret"] for c in creds if c["kind"] in ("hash", "ntlm")})
    wrote = []
    for name, vals in (("users.txt", users), ("passwords.txt", pws), ("hashes.txt", hashes)):
        if vals:
            (out / name).write_text("\n".join(vals) + "\n")
            wrote.append(f"{out/name} ({len(vals)})")
    if not wrote:
        info("Nothing to export yet."); return
    for w in wrote:
        ok(w)
    tgt = current_target() or "<target>"
    print(f"\n{B}Use them (authorized targets only):{N}")
    if users and pws:
        print(f"  spray : netexec smb {tgt} -u {out/'users.txt'} -p {out/'passwords.txt'} --no-bruteforce")
        print(f"  brute : hydra -L {out/'users.txt'} -P {out/'passwords.txt'} {tgt} ssh")
    if hashes:
        print(f"  crack : hashcat -m 1000 {out/'hashes.txt'} <wordlist>   # 1000=NTLM, 0=raw-MD5")
        print(f"  pth   : netexec smb {tgt} -u <user> -H {out/'hashes.txt'}")
    log_event("creds", f"exported to {out}")

def cmd_cred(args):
    if args.action in (None, "list", "users", "passwords", "hashes", "export"):
        args.what = None if args.action == "list" else args.action
        return cmd_creds(args)
    d = require_engagement()
    st = load_state(d)
    if args.action in ("rm", "del", "remove"):
        creds = _norm_creds(st)
        if not args.rest or not args.rest[0].isdigit():
            die("Usage: pentrail cred rm <n>   (n from 'pentrail creds')")
        n = int(args.rest[0])
        if not (1 <= n <= len(creds)):
            die(f"No credential #{n} (see 'pentrail creds')")
        gone = creds.pop(n - 1)
        save_state(d, st)
        log_event("cred", f"removed {cred_str(gone)}")
        ok(f"Removed credential #{n}: {cred_str(gone)}")
        return
    if args.action != "add" or not args.rest:
        die("Usage: pentrail cred add <user>:<secret> [host]  |  pentrail cred rm <n>")
    val = args.rest[0]
    host = args.rest[1] if len(args.rest) > 1 else current_target()
    if ":" in val:
        user, secret = val.split(":", 1)
        c = cred_entry(user=user, secret=secret, host=host)
    else:
        c = cred_entry(secret=val, host=host)   # hash-only or lone password
    if c["secret"] and _sha(c["secret"]) in load_redacts():
        info("That value is on your redact list (your own secret); not storing.")
        return
    if add_cred(st, c):
        save_state(d, st)
        log_event("cred", f"{cred_str(c)} [{c['kind']}] (manual)")
        ok(f"Stored {c['kind']}: {cred_str(c)}")
    else:
        info("Already stored")

def cmd_flag(args):
    d = require_engagement()
    st = load_state(d)
    st.setdefault("flags", [])
    value = " ".join(args.value) if args.value else ""
    if not value:
        if not st["flags"]:
            info("No flags yet. Record one with 'pentrail flag user <value>'."); return
        for f in st["flags"]:
            print(f"  {f['name']:<6} {f['value']}  {DIM}{f.get('host','')} {f.get('added','')}{N}")
        return
    tgt = current_target()
    st["flags"].append({"name": args.name, "value": value, "host": tgt,
                        "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
    h = _find_host(st, tgt) if tgt else None
    owned_msg = ""
    if h and not h["owned"] and args.name.lower() in ("user", "root", "system", "admin"):
        h["owned"] = True
        owned_msg = f", {tgt} marked owned"
    save_state(d, st)
    log_event("flag", f"{args.name} on {tgt or '?'}: {value}")
    ok(f"Flag '{args.name}' stored{owned_msg}")

def cmd_set(args):
    """Project facts you want to keep handy: domain, dc-ip, base-dn, url, ..."""
    d = require_engagement()
    st = load_state(d)
    st.setdefault("facts", {})
    if not args.key:
        if not st["facts"]:
            info("No facts yet. Set one with 'pentrail set domain blackfield.local'."); return
        for k, v in st["facts"].items():
            print(f"  {k:<12} {v}")
        return
    if not args.value:
        print(st["facts"].get(args.key, ""))
        return
    val = " ".join(args.value)
    st["facts"][args.key] = val
    save_state(d, st)
    log_event("fact", f"{args.key} = {val}")
    ok(f"{args.key} = {val}")

def cmd_focus(args):
    """What you are working on right now, shown on the home screen and in status."""
    d = require_engagement()
    st = load_state(d)
    if not args.text:
        cur = st.get("focus")
        info(f"Current focus: {cur}") if cur else info("No focus set. 'pentrail focus \"LDAP enum\"'.")
        return
    st["focus"] = " ".join(args.text)
    save_state(d, st)
    log_event("focus", st["focus"])
    ok(f"Focus: {st['focus']}")
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
INTERESTING = re.compile(
    r"admin|login|logon|upload|backup|dev|test|api|config|\.git|phpmyadmin|"
    r"wp-admin|wp-login|dashboard|console|cgi-bin|robots|\.bak|\.old|\.zip|\.sql|"
    r"private|secret|portal|manage|backup|password|credential|\.env|server-status|"
    r"phpinfo|setup|install|register|user", re.I)

def strip_ansi(text):
    return ANSI.sub("", text)

# --- redaction of the operator's OWN secrets --------------------------------
# You register your own credentials once; pentrail stores only their SHA-256 and
# scrubs them to [REDACTED] in anything it captures, so your login to a tool is
# never written to the logbook or evidence. Hashes only: the values stay secret.
SECRET_TOKEN = re.compile(r"[^\s\"'`=:%@<>(){}\[\],;|&]+")

def _sha(s):
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()

def load_redacts():
    try:
        return {h for h in REDACT_FILE.read_text().split() if h}
    except OSError:
        return set()

def redact_text(text, hashes=None):
    """Replace any token whose hash is on the operator's redact list. Returns
    (clean_text, count). Works on delimiter-separated occurrences."""
    hashes = load_redacts() if hashes is None else hashes
    if not hashes:
        return text, 0
    n = 0
    def repl(m):
        nonlocal n
        if _sha(m.group(0)) in hashes:
            n += 1
            return "[REDACTED]"
        return m.group(0)
    return SECRET_TOKEN.sub(repl, text), n

def cmd_redact(args):
    REDACT_FILE.parent.mkdir(parents=True, exist_ok=True)
    cur = load_redacts()
    act = args.action
    if act == "add":
        if not args.rest:
            die("Usage: pentrail redact add <value> [value...]   (your own creds/tokens)")
        added = 0
        for v in args.rest:
            if len(v) < 6:
                warn(f"'{v}' is short and may redact unrelated text; adding anyway.")
            h = _sha(v)
            if h not in cur:
                cur.add(h); added += 1
        REDACT_FILE.write_text("\n".join(sorted(cur)) + "\n")
        try:
            os.chmod(REDACT_FILE, 0o600)
        except OSError:
            pass
        ok(f"Stored {added} secret(s) as hashes (the values themselves are never written).")
        ok("From now on these are scrubbed to [REDACTED] in captures and never logged.")
    elif act == "list":
        info(f"{len(cur)} secret(s) on the redact list  ({REDACT_FILE})")
        print(f"{DIM}Stored as SHA-256 hashes only; the values are not kept.{N}")
    elif act in ("clear", "clean", "reset"):
        REDACT_FILE.unlink(missing_ok=True)
        ok("Redact list cleared.")
    else:
        die("Usage: pentrail redact add <value...> | list | clear")

# Smart tagging: recognisable signals in tool output -> a typed attack vector.
# (regex, type, description). Patterns are deliberately specific to avoid noise.
VULN_SIGNS = [
    (r"root:.*?:0:0:.*?:/root", "lfi", "LFI / path traversal: /etc/passwd contents in a response"),
    (r"\[boot loader\]|\\WINDOWS\\|\[fonts\]", "lfi", "LFI: Windows system file contents in a response"),
    (r"error in your SQL syntax|SQL syntax.*?MySQL|mysql_fetch|mysqli?_\w+\(\)|ORA-\d{5}|"
     r"SQLSTATE\[|Unclosed quotation mark|PostgreSQL.*?ERROR|Microsoft OLE DB Provider for SQL",
     "sqli", "SQL error reflected: possible SQLi"),
    (r"uid=\d+\([^)]+\)\s+gid=\d+", "rce", "command execution confirmed (id output seen)"),
    (r"nt authority\\system|whoami.*?\n.*?\\", "rce", "command execution on Windows (whoami output)"),
    (r"Anonymous FTP login allowed|230 Login successful.*anonymous", "ftp", "anonymous FTP login allowed"),
    (r"ms17-010|EternalBlue", "smb", "SMB MS17-010 (EternalBlue) flagged by a script"),
    (r"smb-vuln-\S+:\s*\n\s*VULNERABLE", "smb", "SMB vulnerability flagged by nmap"),
    (r"NULL session|Allowing null session", "smb", "SMB null session allowed"),
    (r"\b(anonymous|guest)\b.*\bbind\b|LDAP.*anonymous", "misc", "anonymous LDAP bind possible"),
    (r"\.git/HEAD|ref:\s*refs/heads", "web", "exposed .git repository"),
    (r"server-status|/phpinfo\.php|phpinfo\(\)", "web", "info-disclosure page exposed"),
    (r"(?:sudo\s+-l|may run the following).*\(ALL(?:\s*:\s*ALL)?\)\s*(?:NOPASSWD:)?\s*ALL",
     "sudo", "sudo rights allow running anything (sudo -l)"),
    (r"NOPASSWD:", "sudo", "passwordless sudo entry seen (sudo -l)"),
    (r"-rws|\brwsr-xr-x\b", "suid", "SUID binary seen: check GTFOBins"),
    (r"CVE-\d{4}-\d{3,}", "misc", "CVE referenced in output"),
    (r"default credentials|admin:admin|admin:password|credentials are valid", "default-cred",
     "default/weak credentials indicated"),
]

def web_type(path):
    p = path.lower()
    if "upload" in p:
        return "upload", "upload point"
    if ".git" in p:
        return "web", "exposed .git"
    if any(k in p for k in ("login", "admin", "signin", "logon")):
        return "web", "auth surface"
    return "web", ""

# When a pentrail command runs *inside* a capture, 'script' records its own output
# too. We bracket that output with an invisible APC sentinel (ESC _ ... ESC \, which
# terminals do not display) so the capture parser can drop it - otherwise viewing your
# logbook/vectors/creds during a capture would be re-ingested as findings, and repeat
# captures would keep re-logging the same data. See main() and _strip_capture_echo.
CAP_BEGIN = "\x1b_pentrail\x1b\\"
CAP_END = "\x1b_/pentrail\x1b\\"
_CAP_ECHO_RE = re.compile(re.escape(CAP_BEGIN) + r".*?" + re.escape(CAP_END), re.S)

def _strip_capture_echo(text):
    """Remove pentrail's own recorded output (sentinel-bracketed) before parsing, so
    a capture never re-ingests what you merely viewed with pentrail during it."""
    text = _CAP_ECHO_RE.sub("", text)
    return text.replace(CAP_BEGIN, "").replace(CAP_END, "")   # drop any unpaired stray
def parse_intel(text):
    """Built-in rules: pull leads out of tool output. Returns a dict of findings."""
    text = strip_ansi(text)
    web, ports, hosts, creds, vulns, facts = {}, {}, set(), [], [], {}

    # dir brute-forcers: gobuster, ffuf, dirsearch, feroxbuster, dirb
    for m in re.finditer(r"(/[^\s'\"]*?)\s*\(Status:\s*(\d{3})\)", text):       # gobuster/dirb
        web[m.group(1)] = int(m.group(2))
    for m in re.finditer(r"(/[^\s'\"]*?)\s*\[Status:\s*(\d{3})", text):          # ffuf
        web.setdefault(m.group(1), int(m.group(2)))
    for m in re.finditer(r"^(\d{3})\s+GET\s+.*?\s(https?://\S+)", text, re.M):   # feroxbuster
        path = re.sub(r"^https?://[^/]+", "", m.group(2)) or "/"
        web.setdefault(path, int(m.group(1)))
    for m in re.finditer(r"^\[(\d{3})\]\s+(/\S+)", text, re.M):                  # dirsearch
        web.setdefault(m.group(2), int(m.group(1)))

    # nmap open ports
    for m in re.finditer(r"^(\d+)/(?:tcp|udp)\s+open\s+(\S+)", text, re.M):
        ports[int(m.group(1))] = m.group(2)
    for m in re.finditer(r"(\d+)/open/(?:tcp|udp)//([^/]*)/", text):
        ports.setdefault(int(m.group(1)), m.group(2) or "unknown")

    # hostnames (*.htb / *.local and the like) - candidates for /etc/hosts
    for m in re.finditer(r"\b([a-z0-9][a-z0-9.-]*\.(?:htb|local|lab|box|thm))\b", text, re.I):
        hosts.add(m.group(1).lower())

    # credentials seen in output (your own lab data), as structured entries
    def _add(c):
        if c not in creds:
            creds.append(c)
    # secretsdump / pwdump:  user:rid:lm:nt:::
    for m in re.finditer(r"^(\S+?):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::", text, re.M):
        _add({"user": m.group(1), "secret": m.group(2), "kind": "ntlm"})
    # user:pass style hits (hydra / netexec), line by line so nothing crosses lines
    for line in text.splitlines():
        if ":::" in line:            # a secretsdump line, already handled above
            continue
        m = re.search(r"(?:valid|found|success|login)\b.*?\b([A-Za-z0-9._\\-]{2,}):([^/\s]\S{2,})", line, re.I)
        # skip URL/host:port noise ("...found at http://10.10.10.5:8080/admin")
        if m and "/" not in m.group(2) and m.group(1).lower() not in (
                "http", "https", "ftp", "ftps", "ssh", "smb", "ldap", "mysql", "mssql", "rdp"):
            _add({"user": m.group(1), "secret": m.group(2), "kind": cred_kind(m.group(2))})
    # labelled user=/password= - stop the value at a delimiter so comma/semicolon-joined
    # pairs don't swallow the next field ("username=admin,password=Secret1")
    for m in re.finditer(r"\b(user(?:name)?|login)\s*[:=]\s*([^\s,;|]{2,})", text, re.I):
        _add({"user": m.group(2), "secret": "", "kind": "username"})
    for m in re.finditer(r"\b(pass(?:word)?|pwd|passwd|secret)\s*[:=]\s*([^\s,;|]{3,})", text, re.I):
        _add({"user": "", "secret": m.group(2), "kind": cred_kind(m.group(2))})

    # project facts (domain especially) from common tools
    for pat in (r"(?:DNS[_ ]?Domain[_ ]?Name|Domain(?: Name)?)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9.-]+)",
                r"defaultNamingContext:\s*((?:DC=[^,\s]+,?)+)"):
        m = re.search(pat, text, re.I)
        if m:
            val = m.group(1)
            if val.upper().startswith("DC="):
                val = ".".join(re.findall(r"DC=([^,\s]+)", val, re.I))
            facts["domain"] = val.lower().strip(".")
            break

    # smart tagging: vulnerability-type signals
    for pat, vtype, desc in VULN_SIGNS:
        m = re.search(pat, text, re.I)
        if m:
            token = re.sub(r"\s+", " ", m.group(0))[:30].lower()
            vulns.append((vtype, desc, f"vuln:{vtype}:{token}"))

    return {"web": web, "ports": ports, "hosts": sorted(hosts),
            "creds": creds[:50], "vulns": vulns, "facts": facts}

# ----------------------------------------------------------------------------- reading a capture
# The capture shell marks every command with two invisible APC sequences (terminals
# do not display them): B carries start time, folder, the command line and the
# values of the variables it uses; E carries the exit code and end time. That lets
# pentrail tie every piece of output to the command that produced it.
_MARK_RE = re.compile(r"\x1b_pentrail:(B|E):([^\x1b]*)\x1b\\")
_ESC_SEQ = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"     # OSC (window titles)
    r"|\x1b[P^_X][^\x1b]*\x1b\\"             # DCS / PM / APC / SOS strings
    r"|\x1b\[[0-?]*[ -/]*[@-~]"              # CSI: colours, cursor movement
    r"|\x1b[()][A-Za-z0-9]|\x1b[=>78DEHMNOZc]")

def strip_markers(text):
    return _MARK_RE.sub("", text).replace(CAP_BEGIN, "").replace(CAP_END, "")

def clean_terminal(text):
    """Terminal recording -> plain text: escapes removed, progress bars collapsed
    (keep what is left after the last carriage return), backspaces applied."""
    text = _ESC_SEQ.sub("", text).replace("\r\n", "\n")
    out = []
    for line in text.split("\n"):
        if "\r" in line:
            parts = [p for p in line.split("\r") if p.strip()]
            line = parts[-1] if parts else ""
        while "\x08" in line:
            new = re.sub(r"[^\x08]\x08", "", line, count=1)
            if new == line:
                line = line.replace("\x08", "")
                break
            line = new
        out.append(line)
    return "\n".join(out)

def _decode_begin(payload):
    try:
        raw = base64.b64decode(payload).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return None
    parts = raw.split("\x1f")
    if len(parts) < 3:
        return None
    try:
        ts = float(parts[0])
    except ValueError:
        ts = time.time()
    values = dict(p.split("=", 1) for p in parts[3:] if "=" in p)
    return {"typed": parts[2], "ts": ts, "cwd": parts[1], "values": values,
            "rc": None, "end": None, "out": "", "marked": True}

def split_segments(text):
    """Split a recording into command segments. Without markers (another shell,
    or 'capture --plain') the text is split at recognisable prompt lines instead."""
    segs, cur, pos, found = [], None, 0, False
    for m in _MARK_RE.finditer(text):
        found = True
        chunk = text[pos:m.start()]
        if cur:
            cur["out"] += chunk
        if m.group(1) == "B":
            if cur:
                segs.append(cur)
            cur = _decode_begin(m.group(2))
        elif cur:
            rc, _, end = m.group(2).partition(":")
            cur["rc"] = int(rc) if rc.lstrip("-").isdigit() else None
            try:
                cur["end"] = float(end)
            except ValueError:
                pass
            segs.append(cur)
            cur = None
        pos = m.end()
    if cur:
        cur["out"] += text[pos:]
        segs.append(cur)
    if found:
        return segs
    clean = clean_terminal(text)
    return [{"typed": c, "ts": None, "cwd": None, "values": {}, "rc": None, "end": None,
             "out": out, "marked": False, "clean": True} for c, out in split_prompts(clean)]

# Local prompts, for recordings without markers: Kali's two-line zsh prompt, the
# classic user@host:dir$ and [user@host dir]$.
_PROMPT = re.compile(r"^(?:└─[$#]|\(?[\w.-]*\)?\s*[\w.-]+@[\w.-]+:[^\s$#]*\s?[$#]"
                     r"|\[[\w.-]+@[\w.-]+[^\]]*\][$#])\s+(\S.*)$")

def split_prompts(text):
    """[(command or None, output)] split at prompt lines."""
    out, cmd, buf = [], None, []
    for line in text.split("\n"):
        m = _PROMPT.match(line)
        if m:
            if buf or cmd:
                out.append((cmd, "\n".join(buf)))
            cmd, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    if buf or cmd:
        out.append((cmd, "\n".join(buf)))
    return out

# --- turning output into findings ---------------------------------------------------
NMAP_REPORT = re.compile(r"^Nmap scan report for (?:(\S+) \(([\d.]+|[0-9a-f:]+)\)|(\S+))\s*$", re.I)
NMAP_PORT = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:[ \t]+(\S.*?))?\s*$")
NMAP_GREP = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.*)$")
NMAP_GREP_PORT = re.compile(r"(\d+)/open/(tcp|udp)/[^/]*/([^/]*)/[^/]*/([^/]*)/")
BARE_NAME = re.compile(r"^\s*((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\.?\s*$", re.I)
URL_ANY = re.compile(r"https?://[^\s'\"<>\])}]+", re.I)
SUBDOMAIN_TOOLS = ("subfinder", "amass", "assetfinder", "findomain", "dnsx", "puredns",
                   "shuffledns", "chaos", "gobuster", "ffuf", "dnsrecon", "dnsenum", "massdns")
URL_TOOLS = ("httpx", "katana", "gospider", "hakrawler", "gau", "waybackurls", "feroxbuster",
             "urlfinder", "dirsearch")

def _url_host(url):
    try:
        u = urlsplit(url)
        return (u.hostname or "").lower(), u
    except ValueError:
        return "", None

def _norm_url(url):
    host, u = _url_host(url)
    if not u or not host:
        return url
    default = {"http": 80, "https": 443}.get(u.scheme)
    port = f":{u.port}" if u.port and u.port != default else ""
    path = u.path or "/"
    return f"{u.scheme}://{host}{port}{path}" + (f"?{u.query}" if u.query else "")

def _cmd_context(cmd, scope):
    """What a command line tells the parser: its program, the hosts it targets,
    the URL template (-u http://x/FUZZ) and a Host: header template."""
    prog = prog_of(cmd) if cmd else ""
    hosts = []
    if cmd:
        for h in hosts_in_command(cmd, None, scope):
            if h["header"] or h["net"] is not None or h["range"]:
                continue
            v = scope.verdict(h["host"]) if not h["placeholder"] else "in"
            if v in ("in", "none", "conflict") and h["host"] not in hosts and not h["placeholder"]:
                hosts.append(h["host"])
    url = None
    m = URL_ANY.search(cmd or "")
    if m:
        url = m.group(0).rstrip("'\"")
    hh = re.search(r"Host:\s*([^\s'\"]+)", cmd or "", re.I)
    return {"cmd": cmd, "prog": prog, "hosts": hosts, "url": url,
            "host_header": hh.group(1).lower() if hh else None}

def _join(base, word):
    """ffuf/wfuzz: put the fuzzed word into the URL template; gobuster: base + path."""
    if base and "FUZZ" in base:
        return base.replace("FUZZ", word.lstrip("/") if base.split("FUZZ")[0].endswith("/") else word)
    if base:
        return base.rstrip("/") + "/" + word.lstrip("/")
    return word if word.startswith("/") else "/" + word

def analyze(text, ctx):
    """Findings in one command's (clean) output. Hosts are left unresolved where
    the output does not name one; apply_findings() decides with the command's
    targets and the scope."""
    F = {"ports": [], "web": [], "names": [], "hosts": [], "vulns": [], "creds": [], "facts": {}}
    prog, base = ctx["prog"], ctx["url"]
    cur = None                                      # host of the current nmap report block
    ffuf_status = None
    for line in text.split("\n"):
        s = line.strip()
        if not s:
            continue
        m = NMAP_REPORT.match(s)
        if m:
            name, ip, bare = m.groups()
            cur = (ip or bare).lower()
            F["hosts"].append((cur, "", ""))
            if name:
                F["names"].append((name.lower(), cur))
            continue
        m = NMAP_PORT.match(s)
        if m:
            F["ports"].append((cur, int(m.group(1)), m.group(2), m.group(3), (m.group(4) or "").strip()))
            continue
        m = NMAP_GREP.match(s)
        if m:
            F["hosts"].append((m.group(1), "", ""))
            if m.group(2):
                F["names"].append((m.group(2).lower(), m.group(1)))
            for pm in NMAP_GREP_PORT.finditer(m.group(3)):
                F["ports"].append((m.group(1), int(pm.group(1)), pm.group(2), pm.group(3) or "unknown",
                                   pm.group(4).replace("|", "/")))
            continue
        m = re.match(r"^(?:Open\s+)?(\d+\.\d+\.\d+\.\d+):(\d{1,5})$", s) if prog in ("rustscan", "naabu") \
            else re.match(r"^Discovered open port (\d+)/(tcp|udp) on (\S+)", s)
        if m:
            if prog in ("rustscan", "naabu"):
                F["ports"].append((m.group(1), int(m.group(2)), "tcp", "", ""))
            else:
                F["ports"].append((m.group(3), int(m.group(1)), m.group(2), "", ""))
            continue
        m = re.search(r"Did not follow redirect to https?://([^/\s:]+)", s) or \
            re.search(r"commonName=([^\s/,]+)", s) or re.search(r"DNS_(?:Computer|Tree)_Name:\s*(\S+)", s)
        if m and not m.group(1).startswith("*"):
            F["names"].append((m.group(1).lower().rstrip("."), cur))
        for dm in re.finditer(r"DNS:([^\s,]+)", s):
            if not dm.group(1).startswith("*"):
                F["names"].append((dm.group(1).lower(), cur))
        m = re.match(r"^\|?\s*Service Info:.*?OS: ([^;,]+)", s) or re.match(r"^OS details: (.+)$", s)
        if m and cur:
            F["hosts"].append((cur, "", m.group(1).strip()))
        # directory brute-forcers
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d{3})\)", s)                        # gobuster dir
        if m:
            F["web"].append((None, _join(base, m.group(1)), int(m.group(2)), "")); continue
        m = re.match(r"^\[Status: (\d{3}), Size: (\d+)", s)                        # ffuf -v header
        if m:
            ffuf_status = int(m.group(1)); continue
        m = re.match(r"^\| URL \| (\S+)", s)                                       # ffuf -v URL
        if m:
            F["web"].append((None, m.group(1), ffuf_status, "")); continue
        m = re.match(r"^(\S+)\s+\[Status: (\d{3}), Size: (\d+)", s)               # ffuf
        if m:
            word = m.group(1)
            if ctx["host_header"] and "fuzz" in ctx["host_header"]:
                F["names"].append((ctx["host_header"].replace("fuzz", word.lower()), None))
            else:
                F["web"].append((None, _join(base, word), int(m.group(2)), ""))
            continue
        m = re.match(r"^(\d{3})\s+(?:GET|POST|HEAD|PUT|OPTIONS|PATCH|DELETE)\s+.*?\s(https?://\S+)", s)  # feroxbuster
        if m:
            F["web"].append((None, m.group(2), int(m.group(1)), "")); continue
        m = re.match(r"^\[\d\d:\d\d:\d\d\]\s+(\d{3})\s+-\s+\S+\s+-\s+(\S+)", s) or \
            re.match(r"^\[(\d{3})\]\s+(/\S+)", s)                                    # dirsearch
        if m:
            F["web"].append((None, m.group(2) if "://" in m.group(2) else _join(base, m.group(2)),
                             int(m.group(1)), "")); continue
        m = re.match(r"^\+ (https?://\S+) \(CODE:(\d{3})", s)                       # dirb
        if m:
            F["web"].append((None, m.group(1), int(m.group(2)), "")); continue
        m = re.match(r"^==> DIRECTORY: (https?://\S+)", s)
        if m:
            F["web"].append((None, m.group(1), None, "directory")); continue
        m = re.match(r'^\d{9}:\s+(\d{3})\s+\d+ L\s+\d+ W\s+\d+ Ch\s+"(.*)"', s)     # wfuzz
        if m:
            F["web"].append((None, _join(base, m.group(2)), int(m.group(1)), "")); continue
        # names: vhost / dns brute-force and subdomain tools
        m = re.match(r"^Found:\s+(\S+)(?:\s+(?:\(?Status:\s*(\d{3}))?)?", s)       # gobuster vhost/dns
        if m and "." in m.group(1) and not m.group(1).startswith("/"):
            F["names"].append((m.group(1).lower(), None)); continue
        m = re.match(r"^(\S+) \(FQDN\) --> \w+ --> (\S+) \((IPAddress|FQDN)\)", s)  # amass
        if m:
            F["names"].append((m.group(1).lower(), m.group(2) if m.group(3) == "IPAddress" else None))
            if m.group(3) == "FQDN":
                F["names"].append((m.group(2).lower(), None))
            continue
        m = re.match(r"^([a-z0-9][\w.-]*\.[a-z]{2,})\s+\[(\d+\.\d+\.\d+\.\d+)\]$", s, re.I)  # dnsx
        if m:
            F["names"].append((m.group(1).lower(), m.group(2))); continue
        m = BARE_NAME.match(s)
        if m and prog in SUBDOMAIN_TOOLS:
            F["names"].append((m.group(1).lower(), None)); continue
        # probes and fingerprints
        m = re.match(r"^(https?://\S+)\s+\[(\d{3})[^\]]*\]\s*(.*)$", s)              # httpx / whatweb
        if m:
            F["web"].append((None, m.group(1), int(m.group(2)),
                             re.sub(r"\s+", " ", m.group(3).replace("[", "").replace("]", ";"))[:160]))
            continue
        m = re.match(r"^(?:\[[\d:\-TZ. ]+\]\s+)?\[([\w.:/-]+)\]\s+\[(\w+)\]\s+\[(info|low|medium|high|critical)\]\s+(\S+)(.*)$",
                     s, re.I)                                                         # nuclei
        if m:
            tid, sev, where = m.group(1), m.group(3).lower(), m.group(4)
            vt = next((t for t in ("sqli", "lfi", "rce", "xss", "ssrf", "xxe", "upload", "default-login")
                       if t in tid.lower()), "web")
            vt = "default-cred" if vt == "default-login" else vt
            F["vulns"].append((_url_host(where)[0] or None, vt, f"{tid} ({sev}) at {where}{m.group(5)[:80]}",
                               f"nuclei:{tid}:{where}", s, "working" if sev in ("medium", "high", "critical") else "open",
                               sev))
            continue
        m = re.match(r"^\+ (?:(?:GET|POST|OPTIONS|HEAD)\s+)?(/\S*?):\s+(.+)$", s)   # nikto
        if m and prog == "nikto":
            F["web"].append((None, _join(base, m.group(1)), None, m.group(2)[:120])); continue
        m = re.match(r"^(?:< )?HTTP/[\d.]+ (\d{3})", s) or re.search(r"awaiting response\.\.\. (\d{3})", s)
        if m and prog in ("curl", "wget", "http", "https") and base:
            F["web"].append((None, base, int(m.group(1)), "")); base = None
    if prog in ("curl", "wget", "http", "https") and base and text.strip():
        F["web"].append((None, base, None, ""))                     # requested, status not shown
    if prog in URL_TOOLS:
        for um in URL_ANY.finditer(text):
            F["web"].append((None, um.group(0).rstrip(".,"), None, ""))
    gen = parse_intel(text)                                          # the general rules
    F["creds"], F["facts"] = gen["creds"], gen["facts"]
    for h in gen["hosts"]:
        F["names"].append((h, None))
    for vtype, desc, sig in gen["vulns"]:
        mm = None
        for pat, vt, dsc in VULN_SIGNS:
            if dsc == desc:
                mm = re.search(pat, text, re.I)
                break
        F["vulns"].append((None, vtype, desc, sig, _excerpt(text, mm.start() if mm else 0), "working", ""))
    return F

def _excerpt(text, pos, before=2, after=6):
    lines = text.split("\n")
    upto = text[:pos].count("\n")
    return "\n".join(lines[max(0, upto - before):upto + after + 1])[:1200].strip("\n")

def add_command(st, seg, phase, file_rel, hosts, cmd=None):
    """Record the command that found something (or touched a target); returns its id."""
    cmd = cmd if cmd is not None else seg.get("cmd")
    ts = seg.get("ts")
    stamp = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else _now()
    for c in st["commands"]:
        if c["cmd"] == cmd and c["ts"] == stamp:
            for h in hosts:
                if h not in c["hosts"]:
                    c["hosts"].append(h)
            return c["id"]
    cid = max((c["id"] for c in st["commands"]), default=0) + 1
    dur = int(seg["end"] - ts) if ts and seg.get("end") else None
    st["commands"].append({"id": cid, "cmd": cmd, "prog": prog_of(cmd), "ts": stamp, "dur": dur,
                           "rc": seg.get("rc"), "phase": phase, "file": file_rel,
                           "hosts": list(hosts), "via": ""})
    return cid

def src_str(st, cid, width=70):
    """'Found by' text: the command and when."""
    c = next((c for c in st.get("commands", []) if c["id"] == cid), None) if cid else None
    if not c:
        return ""
    cmd = c["cmd"] if len(c["cmd"]) <= width else c["cmd"][:width - 1] + "…"
    return f"{cmd}  ({c['ts'][:16]})"

def apply_findings(d, st, F, ctx, scope, seg, phase, file_rel, n):
    """Merge one command's findings into state. Only what is in scope is kept; every
    item remembers the command that found it. Counts go into 'n'."""
    default = _canon(st, ctx["hosts"][0]) if ctx["hosts"] else (st.get("target") or "")
    cid = None
    def by():
        nonlocal cid
        if cid is None:
            cid = add_command(st, seg, phase, file_rel, ctx["hosts"], ctx["cmd"])
        return cid
    def keep(host):
        if not host:
            return False
        v = scope.verdict(host)
        if v in ("in", "none", "conflict"):
            return True
        if v in ("out", "unknown"):
            n["skipped"] += 1
        return False

    if ctx["cmd"] and ctx["hosts"]:
        by()                                   # a command against a target is worth recording
    for addr, name, os_ in F["hosts"]:
        if keep(addr):
            h = _ensure_host(st, addr, name)
            if os_ and not h.get("os"):
                h["os"] = os_[:40]
    for addr, port, proto, svc, ver in F["ports"]:
        addr = addr or default
        if not keep(addr):
            continue
        h = _ensure_host(st, _canon(st, addr))
        p = next((x for x in h["ports"] if x["port"] == port and x["proto"] == proto), None)
        if not p:
            h["ports"].append({"port": port, "proto": proto, "service": svc or "", "version": ver,
                               "by": by(), "added": _now()})
            n["ports"] += 1
        elif ver and len(ver) > len(p.get("version", "")):
            p.update({"service": svc or p["service"], "version": ver, "by": by()})
    names = []
    for name, ip in F["names"]:
        name = name.strip(".").lower()
        if not BARE_NAME.match(name) or name.rsplit(".", 1)[-1] in FILE_EXTS:
            continue
        ip = ip if ip and _ip_obj(ip) else None
        if ip:
            scope.learn(name, [ip])
        names.append((name, ip))
    # a name the scope cannot place yet may resolve into an in-scope range: ask DNS
    # before deciding (only when the scope has IPs or ranges)
    known = {x["name"] for x in st["names"]}
    for nm, ips in scope.lookup([nm for nm, ip in names if not ip and nm not in known
                                 and scope.verdict(nm) in ("unknown", "in")][:150], timeout=3.0).items():
        st["dns"][nm] = {"ips": ips, "ts": _now()}
    for name, ip in names:
        v = scope.verdict(name)
        if v == "none" and not (name.endswith(LAB_TLDS) or ctx["prog"] in SUBDOMAIN_TOOLS
                                or (scope.domain and name.endswith(scope.domain))):
            continue
        if v not in ("in", "none", "conflict"):
            if v in ("out", "unknown"):
                n["skipped"] += 1
            if v == "out" and scope.ips_of.get(name):
                # not a finding, but where an out-of-scope name points matters:
                # inside an in-scope range it makes that IP a conflict
                st["dns"][name] = {"ips": sorted(scope.ips_of[name]), "ts": _now()}
            continue
        ip = ip or next(iter(sorted(scope.ips_of.get(name, ()))), None)
        e = next((x for x in st["names"] if x["name"] == name), None)
        if not e:
            st["names"].append({"name": name, "ip": ip or "", "by": by(), "added": _now()})
            n["names"] += 1
        elif ip and not e.get("ip"):
            e["ip"] = ip
        if ip:
            h = _find_host(st, ip)
            if h and name not in h["aliases"] and name != h["ip"]:
                h["aliases"].append(name)
    for addr, url, status, note in F["web"]:
        host, _ = _url_host(url) if "://" in url else (addr or default, None)
        if not keep(host):
            continue
        url = _norm_url(url) if "://" in url else url
        host = _ensure_host(st, host)["ip"]
        w = next((x for x in st["web"] if x["host"] == host and x["url"] == url), None)
        if w:
            if status and not w.get("status"):
                w["status"] = status
            continue
        st["web"].append({"host": host, "url": url, "status": status, "note": note,
                          "by": by(), "added": _now()})
        n["web"] += 1
        path = urlsplit(url).path if "://" in url else url
        if INTERESTING.search(path) and (status is None or status < 500):
            wtype, hint = web_type(path)
            desc = f"web: {url} ({status or '?'})" + (f" - {hint}" if hint else "")
            if add_vector(d, st, desc, host=host, sig=f"web:{host}:{path}", ptype=wtype, by=by(),
                          url=url, excerpt=f"{status or ''} {url}"):
                n["vectors"] += 1
    for addr, vtype, desc, sig, excerpt, status, sev in F["vulns"]:
        host = _canon(st, addr) if addr else default
        if not keep(host):
            continue
        if add_vector(d, st, desc, host=host, status=status, sig=f"{sig}:{host}", ptype=vtype,
                      by=by(), excerpt=excerpt, url=ctx["url"] or "", sev=sev):
            n["vectors"] += 1
    _norm_creds(st)
    for c in F["creds"]:
        if "[REDACTED]" in c.get("user", "") or "[REDACTED]" in c.get("secret", ""):
            continue    # a redacted operator secret; never store
        c.setdefault("host", default); c.setdefault("src", file_rel)
        c.setdefault("added", _now())
        c["by"] = by()
        if add_cred(st, c):
            n["creds"] += 1
            log_event("cred", f"{cred_str(c)} [{c['kind']}] (from {file_rel})", d)
    st.setdefault("facts", {})
    for k, v in F["facts"].items():
        if v and not st["facts"].get(k):
            st["facts"][k] = v
            n["facts"] += 1
            log_event("fact", f"{k} = {v} (from {file_rel})", d)

def new_counts():
    return {k: 0 for k in ("ports", "web", "names", "vectors", "creds", "facts", "skipped", "cmds", "blocked")}

def ingest_recording(d, st, raw, phase, file_rel, quiet=False):
    """Parse a recording (or any tool output): redact, drop pentrail's own output,
    split into commands, read each one, and merge what is in scope into state."""
    text = _strip_capture_echo(raw)
    text, nred = redact_text(text)
    if nred and not quiet:
        warn(f"Redacted {nred} token(s) matching your redact list (not parsed, not stored).")
    scope = Scope(d, st)
    env = project_env(d)
    n = new_counts()
    for seg in split_segments(text):
        typed = seg.get("typed")
        if typed and re.match(r"^\s*(pentrail|exit|clear|cd|ls|ll|pwd)\b", typed):
            continue
        values = dict(env, **seg.get("values", {}))
        seg["cmd"] = expand_vars(typed, values).strip() if typed else None
        if seg["cmd"] and seg["cmd"].startswith("scope-ok "):
            seg["cmd"] = seg["cmd"][9:]
        out = seg["out"] if seg.get("clean") else clean_terminal(seg["out"])
        ctx = _cmd_context(seg["cmd"], scope)
        if seg["cmd"]:
            n["cmds"] += 1
        apply_findings(d, st, analyze(out, ctx), ctx, scope, seg, phase, file_rel, n)
    save_state(d, st)
    return n

def report_counts(n, where="", quiet=False):
    bits = [f"{n[k]} {label}" for k, label in (("ports", "port(s)"), ("web", "web path(s)"),
            ("names", "hostname(s)"), ("vectors", "lead(s)"), ("creds", "credential(s)"),
            ("facts", "fact(s)")) if n[k]]
    if quiet:
        return bits
    if bits:
        print(f"\n{B}New:{N} " + ", ".join(bits) + (f"  -> {where}" if where else ""))
    else:
        info("Nothing new - everything was already logged." if n["cmds"] else "No leads parsed.")
    if n["skipped"]:
        print(f"{DIM}    {n['skipped']} item(s) outside the scope were not logged{N}")
    return bits

def cmd_ingest(args):
    d = require_engagement()
    f = Path(args.file)
    if not f.is_file():
        die(f"File not found: {f}")
    st = load_state(d)
    log_event("ingest", f"parsed {f.name}")
    n = ingest_file(d, st, f)
    report_counts(n, "1-enum/enum.md")

def ingest_file(d, st, f, quiet=False):
    """A saved tool output. nmap files carry their own command line ('as: nmap ...'),
    which becomes the 'Found by' command; anything else is credited to the file."""
    text = f.read_text(errors="replace")
    ts, cmd = f.stat().st_mtime, f"(file) {rel(d, f)}"
    m = re.search(r"^# Nmap \S+ scan initiated (.+?) as: (.+)$", text, re.M)
    if m:
        cmd = m.group(2).strip()
        try:
            ts = datetime.strptime(m.group(1).strip(), "%a %b %d %H:%M:%S %Y").timestamp()
        except ValueError:
            pass
    if text.lstrip().startswith("<?xml") and "<nmaprun" in text:
        text = _nmap_xml_as_text(text)
    if _MARK_RE.search(text):
        return ingest_recording(d, st, text, st.get("phase", "enum"), rel(d, f), quiet)
    seg = {"typed": cmd, "ts": ts, "cwd": None, "values": {}, "rc": None, "end": None,
           "out": text, "marked": True}
    scope, n = Scope(d, st), new_counts()
    seg["cmd"] = cmd
    ctx = _cmd_context(cmd if not cmd.startswith("(file)") else "", scope)
    ctx["cmd"] = cmd
    apply_findings(d, st, analyze(clean_terminal(text), ctx), ctx, scope, seg,
                   st.get("phase", "enum"), rel(d, f), n)
    st["ingested"][rel(d, f)] = f.stat().st_mtime
    save_state(d, st)
    return n

def _nmap_xml_as_text(xml_text):
    """nmap -oX -> the normal-output lines the parser reads."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return xml_text
    out = []
    for h in root.iter("host"):
        addr = next((a.get("addr") for a in h.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        name = next((n.get("name") for n in h.iter("hostname")), None)
        out.append(f"Nmap scan report for {name} ({addr})" if name else f"Nmap scan report for {addr}")
        for p in h.iter("port"):
            st_ = p.find("state")
            if st_ is None or st_.get("state") != "open":
                continue
            s = p.find("service")
            svc = s.get("name", "unknown") if s is not None else "unknown"
            ver = " ".join(x for x in ((s.get("product") if s is not None else ""),
                                       (s.get("version") if s is not None else "")) if x)
            out.append(f"{p.get('portid')}/{p.get('protocol')} open {svc} {ver}".rstrip())
    return "\n".join(out)

def auto_ingest_scans(d, st, quiet=True):
    """Read new or changed files in 1-enum/scans/ (and the old scans/)."""
    total = new_counts()
    for sd in scan_dirs(d):
        for f in sorted(sd.iterdir()):
            if not f.is_file() or f.suffix in (".png", ".jpg"):
                continue
            key = rel(d, f)
            if st["ingested"].get(key) == f.stat().st_mtime:
                continue
            n = ingest_file(d, st, f, quiet=True)
            for k in total:
                total[k] += n[k]
            if not quiet:
                info(f"read {key}")
    return total

# ----------------------------------------------------------------------------- capture
def _read_marker():
    try:
        return json.loads(CAPTURE_MARKER.read_text())
    except (OSError, json.JSONDecodeError):
        return None

def _write_marker(m):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURE_MARKER.write_text(json.dumps(m))

# Shell hooks loaded by the capture shell. They print the B/E markers around each
# command and, before it runs, ask 'pentrail _hook check' whether every host in it
# is in scope; a blocked command never runs. 'scope-ok <cmd>' runs one anyway (logged).
_PREFILTER = r"[0-9]\.[0-9]|[A-Za-z0-9_-]\.[A-Za-z]|\$|@|://"

ZSH_HOOK = r"""
# pentrail capture hook (zsh) - generated by pentrail, rewritten on every capture
zmodload zsh/datetime 2>/dev/null
typeset -ga __pt_bin __pt_v
__pt_bin=(@BIN@)
typeset -g __pt_on=0 __pt_seen=0 __pt_t0=0
__pt_collect() {
  emulate -L zsh
  local b=$1 v
  __pt_v=()
  while [[ $b =~ '\$\{?([A-Za-z_][A-Za-z0-9_]*)' ]]; do
    v=$match[1]
    (( ${+parameters[$v]} )) && __pt_v+=("$v=${(P)v}")
    b=${b[$MEND+1,-1]}
  done
}
__pt_accept() {
  emulate -L zsh
  setopt extendedglob
  local line=$BUFFER out rc=0
  if [[ $line =~ '@PRE@' && ${line##[[:space:]]#} != pentrail(|[[:space:]]*) ]]; then
    __pt_collect "$line"
    out=$("${__pt_bin[@]}" _hook check -- "$line" "${__pt_v[@]}" 2>/dev/null); rc=$?
    [[ -n $out ]] && { zle -I; print -r -- "$out" }
    if (( rc == 3 )); then        # blocked: keep it in history (arrow up to edit), run nothing
      print -s -- "$line"
      BUFFER=""
      zle .accept-line
      return 0
    fi
  fi
  zle __pt_orig_accept_line -- "$@"
}
__pt_preexec() {
  emulate -L zsh
  __pt_on=1; __pt_t0=${EPOCHSECONDS:-0}
  [[ $1 =~ '@PRE@' ]] && __pt_seen=1 || __pt_seen=0
  __pt_collect "$1"
  local enc
  enc=$(print -rn -- "$__pt_t0"$'\x1f'"$PWD"$'\x1f'"$1"${__pt_v:+$'\x1f'}"${(pj:\x1f:)__pt_v}" | base64 -w0 2>/dev/null)
  print -rn -- $'\e_pentrail:B:'"$enc"$'\e\\'
}
__pt_precmd() {
  local rc=$?
  (( __pt_on )) || return 0
  __pt_on=0
  print -rn -- $'\e_pentrail:E:'"$rc:${EPOCHSECONDS:-0}"$'\e\\'
  if (( __pt_seen || ${EPOCHSECONDS:-0} - __pt_t0 >= 10 )); then
    "${__pt_bin[@]}" _hook end
  fi
}
scope-ok() { PENTRAIL_SCOPE_OK=1 "$@" }
zle -A accept-line __pt_orig_accept_line 2>/dev/null || zle -A .accept-line __pt_orig_accept_line
zle -N accept-line __pt_accept
autoload -Uz add-zsh-hook
precmd_functions=(__pt_precmd ${precmd_functions:#__pt_precmd})
add-zsh-hook preexec __pt_preexec
"""

BASH_HOOK = r"""
# pentrail capture hook (bash) - generated by pentrail, rewritten on every capture
[ -r ~/.bashrc ] && . ~/.bashrc
__pt_bin=(@BIN@)
__pt_on=0; __pt_armed=0; __pt_block=0; __pt_seen=0; __pt_t0=0; __pt_hist=''
__pt_v=()
__pt_collect() {
  local b=$1 v re='\$\{?([A-Za-z_][A-Za-z0-9_]*)'
  __pt_v=()
  while [[ $b =~ $re ]]; do
    v=${BASH_REMATCH[1]}
    [[ -n ${!v+x} ]] && __pt_v+=("$v=${!v}")
    b=${b#*"${BASH_REMATCH[0]}"}
  done
}
__pt_end() {
  local rc=$?
  __pt_armed=0
  if [ "$__pt_on" = 1 ]; then
    __pt_on=0
    printf '\033_pentrail:E:%s:%s\033\\' "$rc" "${EPOCHSECONDS:-0}"
    if [ "$__pt_seen" = 1 ] || [ $(( ${EPOCHSECONDS:-0} - __pt_t0 )) -ge 10 ]; then
      "${__pt_bin[@]}" _hook end
    fi
  fi
  __pt_block=0
  return $rc
}
__pt_arm() { __pt_hist=$(HISTTIMEFORMAT= builtin history 1); __pt_armed=1; }
__pt_debug() {
  [ -n "${COMP_LINE-}" ] && return 0
  case ${FUNCNAME[1]-} in __pt_*) return 0;; esac
  case $BASH_COMMAND in __pt_end*|__pt_arm*) return 0;; esac
  [ "$__pt_block" = 1 ] && return 1
  [ "$__pt_armed" = 1 ] || return 0
  __pt_armed=0
  local line h re='^[[:space:]]*[0-9]+\*?[[:space:]]+(.*)$' pre='@PRE@' out rc enc
  h=$(HISTTIMEFORMAT= builtin history 1)
  if [ "$h" != "$__pt_hist" ] && [[ $h =~ $re ]]; then line=${BASH_REMATCH[1]}; else line=$BASH_COMMAND; fi
  __pt_seen=0
  __pt_collect "$line"
  if [[ $line =~ $pre ]]; then
    __pt_seen=1
    case $line in
      pentrail|pentrail\ *) ;;
      *) out=$("${__pt_bin[@]}" _hook check -- "$line" "${__pt_v[@]}" 2>/dev/null); rc=$?
         [ -n "$out" ] && printf '%s\n' "$out"
         if [ "$rc" = 3 ]; then __pt_block=1; return 1; fi ;;
    esac
  fi
  __pt_t0=${EPOCHSECONDS:-0}
  enc=$( { printf '%s\037%s\037%s' "$__pt_t0" "$PWD" "$line"; for v in "${__pt_v[@]}"; do printf '\037%s' "$v"; done; } | base64 -w0)
  printf '\033_pentrail:B:%s\033\\' "$enc"
  __pt_on=1
  return 0
}
scope-ok() { PENTRAIL_SCOPE_OK=1 "$@"; }
PROMPT_COMMAND="__pt_end${PROMPT_COMMAND:+;$PROMPT_COMMAND};__pt_arm"
shopt -s extdebug
trap '__pt_debug' DEBUG
"""

def _hook_bin():
    return " ".join(shlex.quote(x) for x in (sys.executable, "-I", "-S", str(Path(__file__).resolve())))

def capture_shell(env, plain=False):
    """(extra 'script' args, env) to start the user's shell with the hook loaded.
    zsh and bash get the hook; other shells (or --plain) record without it."""
    shell = env.get("SHELL") or "/bin/sh"
    name = os.path.basename(shell)
    if plain or name not in ("zsh", "bash"):
        return [], env, False
    HOOK_DIR.mkdir(parents=True, exist_ok=True)
    body = (ZSH_HOOK if name == "zsh" else BASH_HOOK).replace("@BIN@", _hook_bin()).replace("@PRE@", _PREFILTER)
    if name == "zsh":
        zd = HOOK_DIR / "zsh"
        zd.mkdir(exist_ok=True)
        # load the user's own zsh files first: restore their ZDOTDIR, source, then hook
        (zd / ".zshenv").write_text(
            '__pt_hookdir=$ZDOTDIR\nZDOTDIR=${PENTRAIL_ZDOTDIR:-$HOME}\n'
            '[[ -r $ZDOTDIR/.zshenv ]] && source $ZDOTDIR/.zshenv\n'
            '__pt_userdot=$ZDOTDIR\nZDOTDIR=$__pt_hookdir\n')
        (zd / ".zprofile").write_text('[[ -r $__pt_userdot/.zprofile ]] && source $__pt_userdot/.zprofile\n')
        (zd / ".zshrc").write_text('ZDOTDIR=$__pt_userdot\n[[ -r $ZDOTDIR/.zshrc ]] && source $ZDOTDIR/.zshrc\n' + body)
        env = dict(env, PENTRAIL_ZDOTDIR=os.environ.get("ZDOTDIR", str(HOME)), ZDOTDIR=str(zd))
        return [], env, True
    rc = HOOK_DIR / "bashrc"
    rc.write_text(body)
    return ["-c", f"exec {shlex.quote(shell)} --rcfile {shlex.quote(str(rc))} -i"], env, True

def capture_catchup(quiet=True, wait=False):
    """Read the running capture's recording up to the last finished command and
    record what is new. Called after each command by the shell hook, and before
    any pentrail command run inside the capture, so lookups are current."""
    m = _read_marker()
    if not m or not process_alive(m.get("pid")):
        return None
    f, d = Path(m["file"]), Path(m["eng"])
    start = int(m.get("parsed", 0))
    data = b""
    for _ in range(25 if wait else 1):          # the E marker may still be in flight
        try:
            data = f.read_bytes()
        except OSError:
            return None
        if data.rfind(b"\x1b_pentrail:E:") >= start:
            break
        time.sleep(0.02)
    last = data.rfind(b"\x1b_pentrail:E:")
    close = data.find(b"\x1b\\", last) if last >= start else -1
    if close < 0:
        return None
    end = close + 2
    m["parsed"] = end
    _write_marker(m)
    st = load_state(d)
    return ingest_recording(d, st, data[start:end].decode("utf-8", "replace"),
                            m.get("phase", "enum"), rel(d, f), quiet=True), d

def hook_main(argv):
    """Entry point for the capture shell hook ('pentrail _hook check|end')."""
    if not argv:
        return 0
    if argv[0] == "check":
        rest = argv[1:]
        if rest and rest[0] == "--":
            rest = rest[1:]
        if not rest:
            return 0
        line, values = rest[0], dict(a.split("=", 1) for a in rest[1:] if "=" in a)
        d = current_dir()
        if not d:
            return 0
        allowed, msgs = scope_gate(d, load_state(d), line, values, os.getcwd())
        if msgs:
            col = "\033[31m" if not allowed else "\033[33m"
            print(CAP_BEGIN + "\n".join(f"{col}[pentrail]\033[0m {m}" for m in msgs) + CAP_END)
        return 0 if allowed else 3
    if argv[0] == "end":
        res = capture_catchup(quiet=True, wait=True)
        if res:
            n, d = res
            bits = report_counts(n, quiet=True)
            if bits:
                print(f"\033[2m[pentrail] +{', +'.join(bits)} -> docs updated\033[0m")
        return 0
    return 0

def cmd_capture(args):
    d = require_engagement()
    if not shutil.which("script"):
        die("'script' missing (sudo apt install bsdutils)")
    inside = os.environ.get("PENTRAIL_CAPTURE")
    if inside:
        die(f"You're inside capture '{inside}'. Type 'exit' to close it, then run "
            f"'pentrail capture {args.label or ''}'.".rstrip())
    st = load_state(d)
    phase = phase_of(args.label) if args.label else None
    if phase and phase != st.get("phase"):
        st["phase"] = phase
        save_state(d, st)
        log_event("phase", phase)
    phase = phase or st.get("phase", "enum")
    lbl = re.sub(r"[^A-Za-z0-9._-]", "-", args.label) if args.label else phase

    # A capture running in another shell/tab: close it so this one replaces it.
    m = _read_marker()
    if m and process_alive(m.get("pid")):
        info(f"Closing previous capture '{m.get('label')}' (pid {m['pid']}) ...")
        try:
            os.kill(m["pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            warn("A capture from another user owns that pid; leaving it alone.")
        for _ in range(12):
            if not process_alive(m["pid"]):
                break
            time.sleep(0.5)

    f = evidence_dir(d, phase) / f"{d.name}_{datetime.now():%Y-%m-%d_%H%M%S}_{lbl}.log"
    env = dict(os.environ, PENTRAIL_CAPTURE=lbl, **project_env(d))
    extra, env, hooked = capture_shell(env, getattr(args, "plain", False))
    scope = Scope(d, st)
    info(f"Recording '{lbl}' (phase {phase}) to {rel(d, f)}")
    guard = getattr(args, "guard", None) or guard_mode()
    if hooked and scope.defined:
        print(f"    scope guard {guard}: {GUARD_TEXT[guard]}"
              + (" (this capture)" if getattr(args, "guard", None) else ""))
        print(f"    {scope.summary()}")
        print(f"    {DIM}switch while you work: pentrail scope guard strict|warn|off{N}")
    elif hooked:
        print(f"    {Y}no scope set{N}: nothing is blocked (pentrail scope add <host>)")
    else:
        print(f"    {Y}plain recording{N}: no scope guard and no per-command tracking "
              f"({'--plain' if getattr(args, 'plain', False) else 'needs bash or zsh'})")
    print(f"{DIM}    work as usual; type 'exit' when done. $TARGET is set. "
          f"'pentrail shot --last' screenshots what you just ran.{N}")
    log_event("capture", f"started {lbl} ({rel(d, f)})")
    started = _now()

    sys.stdout.flush()
    proc = subprocess.Popen(["script", "-q", "-f", *extra, str(f)], env=env)
    _write_marker({"pid": proc.pid, "label": lbl, "file": str(f), "eng": str(d),
                   "phase": phase, "parsed": 0, "guard": getattr(args, "guard", None)})
    proc.wait()
    m2 = _read_marker() or {}
    start = int(m2.get("parsed", 0)) if m2.get("pid") == proc.pid else 0
    if m2.get("pid") == proc.pid:
        CAPTURE_MARKER.unlink(missing_ok=True)

    data = f.read_bytes() if f.exists() else b""
    tail = data[start:].decode("utf-8", "replace")
    # the saved evidence: your own secrets scrubbed, invisible markers removed
    raw = data.decode("utf-8", "replace")
    clean, nred = redact_text(raw)
    saved = strip_markers(clean)
    if saved != raw:
        f.write_text(saved)
    if nred:
        warn(f"Scrubbed {nred} of your own secret(s) from {f.name} before saving.")
    ok(f"Recording saved: {rel(d, f)}")
    st = load_state(d)
    log_event("capture", f"ended {lbl} ({rel(d, f)})")
    n = ingest_recording(d, st, tail, phase, rel(d, f))
    auto_ingest_scans(d, st)
    cmds = sum(1 for c in st["commands"] if c.get("file") == rel(d, f))
    blocked = sum(1 for l in _read(d / "logbook.md").splitlines()
                  if "`scope   ` blocked" in l and l[2:21] >= started)
    info(f"{cmds} command(s) on targets recorded" + (f", {blocked} blocked by the scope guard" if blocked else ""))
    report_counts(n, f"{PHASE_DIRS['enum']}/enum.md")

def _shot_save(d, label, display, source, phase, cmd=None):
    """Render text to a PNG via termshot, save text + png as evidence, log, redact,
    and parse for leads. Shared by 'shot <cmd>' and 'shot --last'."""
    ts = datetime.now()
    label = re.sub(r"[^A-Za-z0-9._-]", "-", label or "shot")[:24]
    base = f"{d.name}_{ts:%Y-%m-%d_%H%M%S}_{label}"
    ev = evidence_dir(d, phase)
    png, txt = ev / f"{base}.png", ev / f"{base}.txt"
    display, nred = redact_text(strip_markers(display))
    if nred:
        warn(f"Redacted {nred} of your own secret(s) from the shot.")
    txt.write_text(display)
    renderer = CFG.get("termshot_cmd", "termshot")
    made = False
    if shutil.which(renderer):
        try:
            subprocess.run([renderer, "-f", str(png), "--", "cat", str(txt)],
                           capture_output=True, text=True, timeout=60)
            made = png.exists()
        except (OSError, subprocess.TimeoutExpired) as e:
            warn(f"{renderer} failed: {e}")
        if not made:
            warn(f"{renderer} produced no image; kept the text evidence.")
    else:
        warn(f"'{renderer}' not installed: saved text evidence only. For PNG screenshots "
             "install termshot (github.com/homeport/termshot), or point "
             "'pentrail config termshot_cmd <cmd>' at another renderer.")
    log_event("shot", f"{source} -> {rel(d, png if made else txt)}")
    ok(f"Saved: {rel(d, png if made else txt)}")
    st = load_state(d)
    if cmd:
        seg = {"typed": cmd, "cmd": cmd, "ts": ts.timestamp(), "values": {}, "rc": None,
               "end": None, "out": display, "marked": True}
        scope, n = Scope(d, st), new_counts()
        ctx = _cmd_context(cmd, scope)
        apply_findings(d, st, analyze(clean_terminal(display), ctx), ctx, scope, seg, phase,
                       rel(d, png if made else txt), n)
        save_state(d, st)
    else:
        n = ingest_recording(d, st, display, phase, rel(d, png if made else txt), quiet=True)
    report_counts(n)

def _shot_last(d, args):
    """Screenshot recent output of the active capture (the task you just ran)."""
    m = _read_marker()
    if not (m and process_alive(m.get("pid"))):
        die("'shot --last' screenshots recent output during a capture. Start 'pentrail "
            "capture' first, or use 'pentrail shot <command>'. (A tool cannot read your "
            "terminal scrollback on its own, so there must be a capture recording it.)")
    cap = Path(m["file"])
    data = strip_markers(cap.read_text(errors="replace")) if cap.exists() else ""
    if args.last and args.last > 0:
        chunk = "\n".join(data.splitlines()[-args.last:])
    else:                                   # everything since the previous screenshot
        chunk = data[m.get("shot_offset", 0):]
    lines = chunk.splitlines()
    while lines and re.search(r"pentrail\s+shot", lines[-1]):   # drop this invocation
        lines.pop()
    chunk = "\n".join(lines).strip("\n")
    if not chunk.strip():
        die("Nothing new in the capture to screenshot yet.")
    m["shot_offset"] = len(data)            # next --last starts here
    _write_marker(m)
    _shot_save(d, args.label or m.get("label", "snap"), chunk,
               f"capture {m.get('label', '')} tail", m.get("phase", "enum"))

def cmd_shot(args):
    """Terminal screenshot as evidence: run a command and shoot its output, or
    shoot the recent output of an active capture with --last."""
    d = require_engagement()
    if getattr(args, "last", None) is not None:
        return _shot_last(d, args)
    cmd = list(args.command or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        die("Usage: pentrail shot [-l label] <command ...>   |   pentrail shot --last [lines]")
    st = load_state(d)
    line = " ".join(shlex.quote(c) for c in cmd)
    allowed, msgs = scope_gate(d, st, line, cwd=os.getcwd())
    for m in msgs:
        (warn if allowed else err)(m)
    if not allowed:
        sys.exit(3)
    info(f"Running: {' '.join(cmd)}")
    env = dict(os.environ, FORCE_COLOR="1", CLICOLOR_FORCE="1")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    except FileNotFoundError:
        die(f"Command not found: {cmd[0]}")
    except OSError as e:
        die(f"Could not run {cmd[0]}: {e}")
    raw = (proc.stdout or "") + (proc.stderr or "")
    if raw:
        print(raw if raw.endswith("\n") else raw + "\n", end="")
    _shot_save(d, args.label or cmd[0], f"$ {' '.join(cmd)}\n{raw}", " ".join(cmd),
               st.get("phase", "enum"), cmd=" ".join(cmd))

# ----------------------------------------------------------------------------- working docs
# Each phase folder has a Markdown doc you write in. Blocks between
#   <!-- pentrail:auto NAME -->  and  <!-- pentrail:end NAME -->
# are filled by pentrail from state.json whenever something changes; everything
# outside them is yours and never touched.
DOC_FILES = {"scope": "scope.md", "enum": "enum.md", "foothold": "foothold.md",
             "privesc": "privesc.md", "lateral": "lateral.md", "report": "report.md"}
AUTO_NOTE = ("<!-- pentrail fills the blocks between 'pentrail:auto' and 'pentrail:end' "
             "markers; edits inside them are overwritten. Write anywhere else. -->")

def _auto(name):
    return f"<!-- pentrail:auto {name} -->\n<!-- pentrail:end {name} -->"

SCOPE_TEMPLATE = """# Scope - {name}

<!-- One asset per line under the right heading; text after the asset is a comment.
     Forms: 10.10.10.5 | 10.10.10.0/24 | 10.10.10.1-50 | app.example.com | *.example.com
            | https://example.com/api
     *.example.com covers the subdomains, not example.com itself: list that too if it is in.
     pentrail reads this file. In a capture, commands aimed at hosts outside the scope are
     stopped before they run, and only in-scope results are logged. -->

## In scope
{in_lines}
## Out of scope

## Rules of engagement
- Client / program:
- Testing window:
- Rate limits:
- Test accounts:
- Not allowed:
- Contact:
{derived}"""

SCOPE_DERIVED = """
## Resolved into the scope
<!-- Names that point into your in-scope IPs or ranges, found by captures and by
     'pentrail scope resolve'. Not wanted? List the name under Out of scope. -->
<!-- pentrail:auto resolved -->
<!-- pentrail:end resolved -->

## Scope conflicts
<!-- Where the scope contradicts itself, directly or through DNS. Out of scope wins
     until you settle it with the client or program. -->
<!-- pentrail:auto conflicts -->
<!-- pentrail:end conflicts -->
"""

ENUM_TEMPLATE = """# Enumeration - {name}

{note}

## Overview
{overview}

<!-- pentrail:hosts - a section per host is added above this line -->

## Hostnames & subdomains
{names}

## Commands run
{commands}

## Notes

"""

HOST_SECTION = """## {title}
<!-- pentrail:host {addr} -->

### Ports & services
{ports}

### Web
{web}

### Hostnames
{names}

### Leads
{leads}

### Checklist
{checklist}

### Logged notes
{notes}

### Notes

"""

PHASE_TITLES = {"foothold": "Foothold", "privesc": "Privilege escalation", "lateral": "Lateral movement"}

PHASE_TEMPLATE = """# {title} - {name}

{note}

## Summary
<!-- One or two sentences: what you achieved in this phase and on which host. -->

## Steps
<!-- Numbered steps someone else can follow. The commands pentrail recorded in this
     phase are listed under 'Commands run'; copy the ones that matter. -->

## Result
<!-- What you ended up with, and the proof (add screenshots with 'pentrail shot'). -->
{extra}
## Notes

## Commands run
{commands}

## Evidence
{evidence}
"""

REPORT_TEMPLATE = """# Penetration test report - {name}

{meta}

## Executive summary
<!-- For the reader who stops here: what was tested, the most serious issues, and what to
     fix first. Two or three short paragraphs. -->

## Scope
{scope}

## Methodology
<!-- Your approach. The default text below is yours to change. -->
Testing followed these phases: scoping, enumeration, foothold, privilege escalation, lateral
movement and reporting. Every command was recorded with its time, and the evidence referenced
in this report is kept with the project.

## Findings overview
{summary}

## Findings
{findings}

## Walkthrough
{path}

## Conclusion & recommendations
<!-- Overall security posture and the recommended next steps, most important first. -->

## Appendix
{appendix}
"""

FINDING_TEMPLATE = """# {fid} - {title}

| Field | Value |
|---|---|
| Severity | {sev} |
| CVSS | |
| Asset | {asset} |
| Weakness | {cwe} |
| Status | open |
| Found | {found} |

## Summary
<!-- What the issue is and where, in one or two sentences anyone understands. -->

## Steps to reproduce
{steps}

## Impact
<!-- What this means for the client or program. -->

## Remediation
<!-- How to fix it; link vendor advisories where they exist. -->

## Evidence
{evidence}
"""

BLOCK_RE = re.compile(r"(<!-- pentrail:auto (?P<name>[^>]*?) -->\n)(?P<body>.*?)(<!-- pentrail:end (?P=name) -->)", re.S)

def set_blocks(text, blocks):
    """Replace the bodies of the named auto blocks; leaves everything else alone."""
    def sub(m):
        name = m.group("name").strip()
        if name not in blocks:
            return m.group(0)
        body = blocks[name].rstrip("\n")
        return m.group(1) + (body + "\n" if body else "") + m.group(4)
    return BLOCK_RE.sub(sub, text)

def get_block(text, name):
    m = re.search(r"<!-- pentrail:auto %s -->\n(.*?)<!-- pentrail:end %s -->"
                  % (re.escape(name), re.escape(name)), text, re.S)
    return m.group(1) if m else None

def _cell(s):
    return str(s or "").replace("|", "\\|").replace("\n", " ")

def ensure_docs(d, scope_assets=()):
    """Write the doc templates that are missing (never overwrites)."""
    name = d.name
    make = {
        "scope": lambda: SCOPE_TEMPLATE.format(
            name=name, in_lines="".join(f"- {a}\n" for a in scope_assets), derived=SCOPE_DERIVED),
        "enum": lambda: ENUM_TEMPLATE.format(
            name=name, note=AUTO_NOTE, overview=_auto("overview"), names=_auto("names"),
            commands=_auto("commands enum")),
        "report": lambda: REPORT_TEMPLATE.format(
            name=name, meta=_auto("meta"), scope=_auto("scope"), summary=_auto("findings-summary"),
            findings=_auto("findings"), path=_auto("walkthrough"), appendix=_auto("appendix")),
    }
    for p in PHASE_TITLES:
        make[p] = (lambda p=p: PHASE_TEMPLATE.format(
            title=PHASE_TITLES[p], name=name, note=AUTO_NOTE,
            extra=("\n## Host chain\n" + _auto("chain") + "\n") if p == "lateral" else "",
            commands=_auto(f"commands {p}"), evidence=_auto(f"evidence {p}")))
    for p, fn in make.items():
        f = phase_dir(d, p) / DOC_FILES[p]
        if not f.exists():
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(fn())
    (d / "5-report" / "findings").mkdir(parents=True, exist_ok=True)
    if not (d / NOTES_DOC).exists():
        (d / NOTES_DOC).write_text(NOTES_TEMPLATE.format(name=name))

def _add_notes_block(text, addr):
    """Give a host section made before notes existed its 'Logged notes' block, just
    above its own Notes heading (nothing of yours moves)."""
    start = text.find(f"<!-- pentrail:host {addr} -->")
    nxt = text.find("\n## ", start)
    end = nxt if nxt >= 0 else len(text)
    at = text.find("\n### Notes", start, end)
    at = at + 1 if at >= 0 else end
    return text[:at] + "### Logged notes\n" + _auto(f"notes {addr}") + "\n\n" + text[at:]

def _write_if_changed(f, old, new):
    if new != old:
        tmp = f.with_name(f.name + f".tmp.{os.getpid()}")
        tmp.write_text(new)
        os.replace(tmp, f)

def _src_md(st, cid):
    c = next((c for c in st["commands"] if c["id"] == cid), None) if cid else None
    if not c:
        return ""
    cmd = c["cmd"] if len(c["cmd"]) <= 90 else c["cmd"][:89] + "…"
    return f"`{cmd}` ({c['ts'][:16]})"

def render_ports(st, h):
    if not h["ports"]:
        return "_none yet_"
    rows = ["| Port | Service | Version | Found by |", "|---|---|---|---|"]
    for p in sorted(h["ports"], key=lambda p: (p["proto"], p["port"])):
        rows.append(f"| {p['port']}/{p['proto']} | {_cell(p['service'])} | {_cell(p.get('version'))} | "
                    f"{_cell(_src_md(st, p.get('by')))} |")
    return "\n".join(rows)

def render_web(st, host):
    h = _find_host(st, host)
    keys = _keys(h) if h else {host}
    ws = sorted((w for w in st["web"] if w["host"] in keys), key=lambda w: w["url"])
    if not ws:
        return "_none yet_"
    return "\n".join(f"- `{w.get('status') or '-'}` {w['url']}" + (f" - {w['note']}" if w.get("note") else "")
                     + (f" <sub>{_src_md(st, w.get('by'))}</sub>" if w.get("by") else "") for w in ws)

def render_host_names(st, h):
    names = sorted(set(h.get("aliases", [])) | {n["name"] for n in st["names"] if n.get("ip") == h["ip"]})
    return "\n".join(f"- {n}" for n in names) if names else "_none yet_"

def render_leads(st, host):
    h = _find_host(st, host)
    keys = _keys(h) if h else {host}
    vs = sorted((v for v in st["vectors"] if v.get("host") in keys),
                key=lambda v: (STATUS_ORDER.get(v["status"], 1), v["id"]))
    if not vs:
        return "_none yet_"
    return "\n".join(f"- **#{v['id']}** `{v['status']}` [{v.get('type', 'misc')}] {v['desc']}"
                     + (f" -> **{v['finding']}**" if v.get("finding") else "")
                     + (f" <sub>{_src_md(st, v.get('by'))}</sub>" if v.get("by") else "") for v in vs)

def render_checklist(st, h, old_body):
    """Enumeration steps for this host's open services, ticked when pentrail saw
    the step run. Ticks you set by hand are kept."""
    ticked = set(re.findall(r"^- \[[xX]\] (.+)$", old_body or "", re.M))
    items = enum_steps(st, h)
    if not items:
        return "_appears once ports are known_"
    return "\n".join(f"- [{'x' if done or text in ticked else ' '}] {text}" for text, done in items)

def render_overview(st):
    if not st["hosts"]:
        return "_no hosts yet: run a scan inside 'pentrail capture'_"
    rows = ["| Host | Name | OS | Open ports | Web | Leads | Owned |", "|---|---|---|---|---|---|---|"]
    for h in st["hosts"]:
        web = sum(1 for w in st["web"] if w["host"] in _keys(h))
        leads = sum(1 for v in st["vectors"] if v.get("host") in _keys(h) and v["status"] in ("open", "working"))
        rows.append(f"| {h['ip']} | {_cell(h.get('name'))} | {_cell(h.get('os'))} | {_cell(_ports_short(h, 8))} "
                    f"| {web} | {leads} | {'yes' if h['owned'] else ''} |")
    return "\n".join(rows)

def render_names(st):
    if not st["names"]:
        return "_none yet_"
    rows = ["| Name | IP | Found by |", "|---|---|---|"]
    for n in sorted(st["names"], key=lambda n: n["name"]):
        rows.append(f"| {n['name']} | {n.get('ip') or ''} | {_cell(_src_md(st, n.get('by')))} |")
    return "\n".join(rows)

def render_commands(st, phase=None):
    cs = [c for c in st["commands"] if phase is None or c.get("phase") == phase]
    if not cs:
        return "_none yet_"
    rows = ["| Time | Host | Command | Exit | Recording |", "|---|---|---|---|---|"]
    for c in cs:
        rows.append(f"| {c['ts'][:16]} | {_cell(', '.join(c.get('hosts', [])[:2]))} | `{_cell(c['cmd'])}` | "
                    f"{'' if c.get('rc') is None else c['rc']} | {_cell(c.get('file'))} |")
    return "\n".join(rows)

def render_evidence(d, phase):
    ev = phase_dir(d, phase) / "evidence"
    files = sorted(f for f in ev.rglob("*") if f.is_file()) if ev.is_dir() else []
    if not files:
        return "_none yet_"
    out = []
    for f in files:
        r = rel(phase_dir(d, phase) / DOC_FILES[phase], f).replace(os.sep, "/")
        r = os.path.relpath(str(f), str(phase_dir(d, phase)))
        out.append(f"- ![{f.name}]({r})" if f.suffix == ".png" else f"- [{f.name}]({r})")
    return "\n".join(out)

def render_resolved(scope, st):
    rows = resolved_into_scope(scope)
    if not rows:
        return "_none yet_"
    by = {n["name"]: n.get("by") for n in st["names"]}
    return "\n".join(f"- {name} -> {', '.join(ips)} (in {entry})"
                     + (f" <sub>{_src_md(st, by[name])}</sub>" if by.get(name) else "")
                     for name, ips, entry in rows)

def render_conflicts(scope):
    conflicts, notes = scope_conflicts(scope)
    if not conflicts and not notes:
        return "_none_"
    out = [f"- **{c}**" for c in conflicts] + [f"- {x}" for x in notes[:30]]
    return "\n".join(out + ([f"- ... {len(notes) - 30} more"] if len(notes) > 30 else []))

def render_chain(d):
    lines = [l for l in _read(d / "logbook.md").splitlines() if "`pivot" in l]
    out = []
    for l in lines:
        m = re.search(r"`pivot\s*`\s*(.*)$", l)
        out.append(f"- {l[2:18]}  {m.group(1) if m else ''}")
    return "\n".join(out) if out else "_none yet: 'pentrail pivot <from> <to> --via <how>'_"

# ----------------------------------------------------------------------------- notes
# Quick notes from the terminal, tied to a host (the active box unless you say
# otherwise). They show in notes.md, grouped by host, and in the host's section of
# enum.md. Hosts, leads (#3), findings (F01) and other notes (N2) that a note
# mentions become links, and every host lists the notes that mention it.
NOTES_DOC = "notes.md"
NOTES_TEMPLATE = """# Notes - {name}

<!-- Quick notes from the terminal: pentrail note "<text>" goes on the active box,
     pentrail note -t <host> "<text>" on another one. Hosts, leads (#3), findings (F01)
     and other notes (N2) you mention become links. Your own notes go at the bottom. -->

## By host
<!-- pentrail:auto notes-by-host -->
<!-- pentrail:end notes-by-host -->

## Not tied to a host
<!-- pentrail:auto notes-general -->
<!-- pentrail:end notes-general -->

## Your notes

"""

def gh_slug(text):
    """The anchor GitHub, VS Code and pentrail's HTML export give a heading."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)       # a link counts as its text
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")

def _linkable_name(name):
    # host names like 'box1' or 'dc01.corp.local' are safe to link; 'web' is not
    return bool(name) and len(name) >= 3 and bool(re.search(r"[\d.]", name))

def _host_title(h):
    return h["ip"] + (f" ({h['name']})" if h.get("name") else "")

def _note_links(d, st, enum_text=None):
    """Everything a note can point at, for link_note()."""
    text = enum_text if enum_text is not None else _read(phase_dir(d, "enum") / DOC_FILES["enum"])
    anchors, last = {}, ""
    for line in text.splitlines():
        if line.startswith("## "):
            last = line[3:]
        m = re.match(r"<!-- pentrail:host (\S+) -->", line)
        if m:
            anchors[m.group(1)] = gh_slug(last)
    keys = {}
    for h in st["hosts"]:
        for k in [h["ip"], *h.get("aliases", []), *([h["name"]] if _linkable_name(h.get("name")) else [])]:
            keys.setdefault(k.lower(), h["ip"])
    return {"keys": keys, "anchors": anchors, "hosts": {h["ip"]: h for h in st["hosts"]},
            "findings": {x["id"].upper(): rel(d, x["path"]) for x in list_findings(d)},
            "vectors": {v["id"]: v.get("host", "") for v in st["vectors"]},
            "notes": {n["id"]: n.get("host", "") for n in st["notes"]}}

def _notes_anchor(L, host):
    h = L["hosts"].get(host)
    return gh_slug(_host_title(h)) if h else "not-tied-to-a-host"

def _mention_re(L):
    keys = sorted(L["keys"], key=len, reverse=True)
    hosts = "|".join(re.escape(k) for k in keys) or r"(?!x)x"
    return re.compile(r"(?P<f>\bF\d{2,}\b)|(?<![\w#&])#(?P<v>\d+)\b|\bN(?P<n>\d+)\b"
                      r"|(?<![\w.\-/])(?i:(?P<h>" + hosts + r"))(?![\w\-]|\.\w)")

def _mentions(n, L):
    """The hosts a note's text names."""
    return {L["keys"][m.group("h").lower()] for m in _mention_re(L).finditer(n["text"]) if m.group("h")}

def link_note(text, L, base=""):
    """Note text with hosts, leads, findings and notes as Markdown links, relative
    to a doc in folder 'base' ('' = the project folder, '1-enum' = enum.md)."""
    up = "../" if base else ""
    enum = "" if base == "1-enum" else f"{up}1-enum/enum.md"
    notes = f"{up}{NOTES_DOC}" if base else ""
    def host(addr, label):
        anc = L["anchors"].get(L["keys"].get((addr or "").lower(), addr))   # a name -> its host
        return f"[{label}]({enum}#{anc})" if anc else label
    def sub(m):
        if m.group("f"):
            p = L["findings"].get(m.group("f").upper())
            return f"[{m.group('f')}]({up}{p})" if p else m.group(0)
        if m.group("v"):
            vid = int(m.group("v"))
            return host(L["vectors"][vid], f"#{vid}") if vid in L["vectors"] else m.group(0)
        if m.group("n"):
            nid = int(m.group("n"))
            return f"[N{nid}]({notes}#{_notes_anchor(L, L['notes'][nid])})" if nid in L["notes"] else m.group(0)
        return host(L["keys"][m.group("h").lower()], m.group("h"))
    parts = text.split("`")
    for i in range(0, len(parts), 2):            # leave `code` alone
        parts[i] = _mention_re(L).sub(sub, parts[i])
    return "`".join(parts)

def note_line(st, n, L, base=""):
    c = next((c for c in st["commands"] if c["id"] == n.get("by")), None) if n.get("by") else None
    after = f" <sub>after `{c['cmd'][:80].replace('`', chr(39))}`</sub>" if c else ""
    return f"- **N{n['id']}** {n['ts'][:16]} · {n.get('phase', '')} · {link_note(n['text'], L, base)}{after}"

def render_notes_by_host(st, L):
    out = []
    for h in st["hosts"]:
        own = [n for n in st["notes"] if n.get("host") == h["ip"]]
        men = [n for n in st["notes"] if n.get("host") != h["ip"] and h["ip"] in _mentions(n, L)]
        if not own and not men:
            continue
        anc = L["anchors"].get(h["ip"])
        out.append(f"### [{_host_title(h)}](1-enum/enum.md#{anc})" if anc else f"### {_host_title(h)}")
        out += [note_line(st, n, L) for n in own]
        if men:
            out.append("- _mentioned in_ " + ", ".join(
                f"[N{n['id']}](#{_notes_anchor(L, n.get('host'))})" for n in men))
        out.append("")
    return "\n".join(out).strip() or '_no notes yet: pentrail note "<text>"_'

def render_notes_general(st, L):
    ns = [n for n in st["notes"] if n.get("host") not in L["hosts"]]
    return "\n".join(note_line(st, n, L) + (f" _(was on {n['host']})_" if n.get("host") else "")
                     for n in ns) or "_none_"

def render_host_notes(st, h, L):
    own = [n for n in st["notes"] if n.get("host") == h["ip"]]
    men = [n for n in st["notes"] if n.get("host") != h["ip"] and h["ip"] in _mentions(n, L)]
    lines = [note_line(st, n, L, "1-enum") for n in own]
    if men:
        lines.append("- _mentioned in_ " + ", ".join(
            f"[N{n['id']}](../{NOTES_DOC}#{_notes_anchor(L, n.get('host'))})" for n in men))
    return "\n".join(lines) or '_none yet: pentrail note "<text>"_'

def cmd_note(args):
    """A quick note on the active box (or -t <host>, or -t none for the project)."""
    d = require_engagement()
    st = load_state(d)
    text = " ".join(args.text).strip()
    host = st.get("target", "")
    if args.target:
        if args.target.lower() in ("-", "none", "general", "project"):
            host = ""
        else:
            h = _find_host(st, args.target)
            if not h:
                die(f"Unknown host {args.target} (see 'pentrail hosts'); -t none for a project note")
            host = h["ip"]
    m = _live_capture()
    cap = [c for c in st["commands"] if m and c.get("file") == rel(d, Path(m["file"]))]
    nid = max([n["id"] for n in st["notes"]] + [st.get("note_seq", 0)]) + 1   # never reuse a number
    st["note_seq"] = nid
    st["notes"].append({"id": nid, "text": text, "host": host, "phase": st.get("phase", "enum"),
                        "ts": _now(), "by": cap[-1]["id"] if cap else None})
    save_state(d, st)
    log_event("note", f"N{nid}" + (f" [{host}]" if host else "") + f" {text}")
    ok(f"Note N{nid}" + (f" on {host}" if host else " (project)") + f" -> {NOTES_DOC}"
       + (", 1-enum/enum.md" if host else ""))

def cmd_notes(args):
    """List notes (all, or for one host), remove one, or change its text."""
    d = require_engagement()
    st = load_state(d)
    words = list(args.rest or [])
    if words and words[0].lower() in ("rm", "del", "remove", "edit"):
        act = words[0].lower()
        nid = int(re.sub(r"^[Nn]", "", words[1])) if len(words) > 1 and re.fullmatch(r"[Nn]?\d+", words[1]) else None
        n = next((x for x in st["notes"] if x["id"] == nid), None)
        if not n:
            die("Usage: pentrail notes rm <N>   |   pentrail notes edit <N> \"<new text>\"")
        if act == "edit":
            if len(words) < 3:
                die("Usage: pentrail notes edit <N> \"<new text>\"")
            n["text"] = " ".join(words[2:])
            log_event("note", f"N{nid} edited: {n['text']}")
            ok(f"N{nid} changed")
        else:
            st["notes"] = [x for x in st["notes"] if x is not n]
            log_event("note", f"N{nid} removed ({n['text']})")
            ok(f"N{nid} removed")
        save_state(d, st)
        return
    L = _note_links(d, st)
    want = None
    if words:
        h = _find_host(st, words[0])
        if not h:
            die(f"Unknown host {words[0]} (see 'pentrail hosts')")
        want = h["ip"]
    ns = [n for n in st["notes"] if want is None or n.get("host") == want or want in _mentions(n, L)]
    if not ns:
        info('No notes yet. Add one with: pentrail note "<text>"  (on the active box, or -t <host>)')
        return
    for n in ns:
        on = n.get("host") or "project"
        tag = "" if want is None or n.get("host") == want else f" {DIM}(mentions it){N}"
        print(f"  {B}N{n['id']:<3}{N} {DIM}{n['ts'][5:16]} {n.get('phase', ''):<8}{N} {C}{on:<15}{N} {n['text']}{tag}")
    print(f"\n{B}{len(ns)} note(s){N}, also in {NOTES_DOC}. Change one: pentrail notes edit <N> \"<text>\"")


_DOC_WARNED = []

def sync_docs(d, st):
    """Refresh every auto block in the phase docs (the report is refreshed by
    'pentrail report'). Docs never break a command: problems are a warning."""
    try:
        ensure_docs(d)
        f = d / SCOPE_DOC
        old = f.read_text()
        text = old if "<!-- pentrail:auto resolved -->" in old else old.rstrip("\n") + "\n" + SCOPE_DERIVED
        scope = Scope(d, st)
        _write_if_changed(f, old, set_blocks(text, {"resolved": render_resolved(scope, st),
                                                    "conflicts": render_conflicts(scope)}))
        f = phase_dir(d, "enum") / DOC_FILES["enum"]
        old = f.read_text()
        text = old
        for h in st["hosts"]:
            if f"<!-- pentrail:host {h['ip']} -->" not in text:
                title = h["ip"] + (f" ({h['name']})" if h.get("name") else "")
                sec = HOST_SECTION.format(title=title, addr=h["ip"], ports=_auto(f"ports {h['ip']}"),
                                          web=_auto(f"web {h['ip']}"), names=_auto(f"names {h['ip']}"),
                                          leads=_auto(f"leads {h['ip']}"), checklist=_auto(f"checklist {h['ip']}"),
                                          notes=_auto(f"notes {h['ip']}"))
                mark = "<!-- pentrail:hosts"
                text = text.replace(mark, sec + mark, 1) if mark in text else text.rstrip("\n") + "\n\n" + sec
            elif f"<!-- pentrail:auto notes {h['ip']} -->" not in text:
                text = _add_notes_block(text, h["ip"])        # host sections from before notes
        L = _note_links(d, st, text)
        blocks = {"overview": render_overview(st), "names": render_names(st),
                  "commands enum": render_commands(st, "enum")}
        for h in st["hosts"]:
            a = h["ip"]
            blocks.update({f"ports {a}": render_ports(st, h), f"web {a}": render_web(st, a),
                           f"names {a}": render_host_names(st, h), f"leads {a}": render_leads(st, a),
                           f"checklist {a}": render_checklist(st, h, get_block(text, f"checklist {a}")),
                           f"notes {a}": render_host_notes(st, h, L)})
        _write_if_changed(f, old, set_blocks(text, blocks))
        f = d / NOTES_DOC
        old = f.read_text()
        _write_if_changed(f, old, set_blocks(old, {"notes-by-host": render_notes_by_host(st, L),
                                                   "notes-general": render_notes_general(st, L)}))
        for p in PHASE_TITLES:
            f = phase_dir(d, p) / DOC_FILES[p]
            old = f.read_text()
            blocks = {f"commands {p}": render_commands(st, p), f"evidence {p}": render_evidence(d, p)}
            if p == "lateral":
                blocks["chain"] = render_chain(d)
            _write_if_changed(f, old, set_blocks(old, blocks))
    except (OSError, ValueError, KeyError) as e:
        if not _DOC_WARNED:
            _DOC_WARNED.append(1)
            warn(f"Could not update the working docs: {e}")

# ----------------------------------------------------------------------------- findings
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
# A starting severity and weakness per vector type; you set the real ones.
TYPE_DEFAULTS = {
    "sqli": ("High", "CWE-89"), "lfi": ("High", "CWE-22"), "rfi": ("High", "CWE-98"),
    "rce": ("Critical", "CWE-78"), "upload": ("High", "CWE-434"), "xxe": ("High", "CWE-611"),
    "ssrf": ("High", "CWE-918"), "deserial": ("Critical", "CWE-502"), "xss": ("Medium", "CWE-79"),
    "default-cred": ("High", "CWE-1392"), "cred": ("High", "CWE-522"), "web": ("Medium", ""),
    "smb": ("Medium", "CWE-284"), "ftp": ("Medium", "CWE-284"), "nfs": ("Medium", "CWE-284"),
    "snmp": ("Medium", "CWE-1188"), "sudo": ("High", "CWE-269"), "suid": ("High", "CWE-269"),
    "cron": ("High", "CWE-732"), "kernel": ("High", "CWE-1104"), "privesc": ("High", "CWE-269"),
}

def findings_dir(d):
    p = d / "5-report" / "findings"
    p.mkdir(parents=True, exist_ok=True)
    return p

def _field(text, name):
    m = re.search(r"^\|\s*%s\s*\|\s*(.*?)\s*\|\s*$" % re.escape(name), text, re.M | re.I)
    return m.group(1).strip() if m else ""

def list_findings(d):
    out = []
    p = d / "5-report" / "findings"
    for f in sorted(p.glob("F*.md")) if p.is_dir() else []:
        text = _read(f)
        m = re.search(r"^#\s+(F\d+)\s+-\s+(.+)$", text, re.M)
        sev = _field(text, "Severity").capitalize() or "Info"
        out.append({"id": m.group(1) if m else f.stem.split("-")[0], "title": m.group(2).strip() if m else f.stem,
                    "sev": sev if sev in SEVERITIES else "Info", "asset": _field(text, "Asset"),
                    "status": _field(text, "Status") or "open", "path": f, "text": text})
    return sorted(out, key=lambda x: (SEVERITIES.index(x["sev"]), x["id"]))

def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "finding"

def create_finding(d, st, title, vec=None, sev=None):
    nums = [int(re.match(r"F(\d+)", f.name).group(1)) for f in findings_dir(d).glob("F*.md")
            if re.match(r"F(\d+)", f.name)]
    fid = f"F{max(nums, default=0) + 1:02d}"
    dsev, cwe = TYPE_DEFAULTS.get((vec or {}).get("type", ""), ("Medium", ""))
    if vec and vec.get("sev"):
        dsev = vec["sev"].capitalize() if vec["sev"].capitalize() in SEVERITIES else dsev
    sev = (sev or dsev).capitalize()
    c = next((c for c in st["commands"] if c["id"] == (vec or {}).get("by")), None) if vec else None
    steps, evidence = [], []
    if c:
        steps.append(f"1. Run:\n\n   ```\n   {c['cmd']}\n   ```\n\n   <!-- recorded {c['ts']} in {c.get('file')} -->")
        if c.get("file"):
            evidence.append(f"- `{c['file']}` (recording, {c['ts'][:16]})")
    if vec and vec.get("excerpt"):
        steps.append("2. Output:\n\n```text\n" + vec["excerpt"].strip("\n") + "\n```")
    if not steps:
        steps.append("1. ")
    asset = (vec or {}).get("url") or (vec or {}).get("host") or st.get("target", "")
    text = FINDING_TEMPLATE.format(fid=fid, title=title, sev=sev, asset=asset, cwe=cwe,
                                   found=(c["ts"][:16] if c else _now()[:16]),
                                   steps="\n\n".join(steps), evidence="\n".join(evidence) or "- ")
    f = findings_dir(d) / f"{fid}-{_slug(title)}.md"
    f.write_text(text)
    return fid, f

def clean_md(text):
    """Markdown without pentrail's markers and template hints (for reports/pasting)."""
    text = re.sub(r"<!--.*?-->\n?", "", text, flags=re.S)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"

def cmd_finding(args):
    """List findings, create one from a vector or a title, or print one clean."""
    d = require_engagement()
    st = load_state(d)
    words = list(args.rest or [])
    if not words:
        fs = list_findings(d)
        if not fs:
            info("No findings yet. Turn a confirmed lead into one: pentrail finding <vector-id>, "
                 "or pentrail finding \"<title>\".")
            return
        for x in fs:
            col = {"Critical": R, "High": R, "Medium": Y, "Low": C}.get(x["sev"], DIM)
            print(f"  {x['id']:<4} {col}{x['sev']:<9}{N} {x['title']}  {DIM}{x['asset']}  {rel(d, x['path'])}{N}")
        print(f"\n{B}{len(fs)} finding(s){N}. Print one ready to paste: pentrail finding F01")
        return
    key = words[0]
    if re.fullmatch(r"[Ff]\d+", key) and len(words) == 1:
        x = next((x for x in list_findings(d) if x["id"].lower() == key.lower()), None)
        if not x:
            die(f"No finding {key.upper()} (see 'pentrail finding')")
        print(clean_md(x["text"]), end="")
        return
    vec = None
    if key.isdigit() and len(words) == 1:
        vec = next((v for v in st["vectors"] if v["id"] == int(key)), None)
        if not vec:
            die(f"No attack vector #{key} (see 'pentrail vectors')")
        if vec.get("finding"):
            die(f"Vector #{key} is already finding {vec['finding']}")
        title = re.sub(r"^(web|nuclei):\s*", "", vec["desc"])
    else:
        title = " ".join(words)
    sev = args.severity
    if sev and sev.capitalize() not in SEVERITIES:
        die(f"Severity is one of: {', '.join(SEVERITIES)}")
    fid, f = create_finding(d, st, title, vec, sev)
    if vec:
        vec["finding"], vec["status"] = fid, "done"
    save_state(d, st)
    log_event("finding", f"{fid} {title}" + (f" (from vector #{vec['id']})" if vec else ""))
    ok(f"Finding {fid}: {rel(d, f)}")
    print(f"    {DIM}fill in Summary, Impact and Remediation; 'pentrail report' puts it in the report{N}")

# ----------------------------------------------------------------------------- report
def _demote(text, by=1):
    return re.sub(r"^(#{1,5}) ", lambda m: "#" * min(6, len(m.group(1)) + by) + " ", text, flags=re.M)

def _drop_empty_headings(text):
    """Remove headings that have nothing under them (template sections not filled in)."""
    lines, out = text.split("\n"), []
    for i, l in enumerate(lines):
        m = re.match(r"^(#{1,6}) ", l)
        if m:
            lvl, has = len(m.group(1)), False
            for nxt in lines[i + 1:]:
                h = re.match(r"^(#{1,6}) ", nxt)
                if h and len(h.group(1)) <= lvl:
                    break
                if nxt.strip() and not h:
                    has = True
                    break
            if not has:
                continue
        out.append(l)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()

def _phase_story(d, p):
    """The text you wrote in a phase doc; pentrail's own lists and empty sections left out."""
    text = _read(phase_dir(d, p) / DOC_FILES[p])
    text = re.sub(r"<!-- pentrail:auto .*?<!-- pentrail:end [^>]*-->", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"^# .*\n", "", text)
    text = re.sub(r"(?ms)^## (?:Commands run|Evidence|Host chain|Overview|Hostnames & subdomains)\n.*?(?=^## |\Z)", "", text)
    return _demote(_drop_empty_headings(text), 2)

def _secrets(st):
    return sorted({c.get("secret") for c in _norm_creds(st) if c.get("secret")}, key=len, reverse=True)

def build_report(d, st, mask=False):
    """Fill the report's auto blocks from everything pentrail and you recorded."""
    ensure_docs(d)
    f = phase_dir(d, "report") / DOC_FILES["report"]
    fs = list_findings(d)
    scope = Scope(d, st)
    meta = ["| | |", "|---|---|",
            f"| Project | {_cell(d.name)} |",
            f"| Date | {datetime.now():%Y-%m-%d} |"]
    if CFG.get("author"):
        meta.append(f"| Tester | {_cell(CFG['author'])} |")
    first = min((c["ts"] for c in st["commands"]), default="")
    if first:
        meta.append(f"| Testing period | {first[:10]} - {max(c['ts'] for c in st['commands'])[:10]} |")
    meta += [f"| Hosts | {len(st['hosts'])} ({sum(1 for h in st['hosts'] if h['owned'])} owned) |",
             f"| Findings | {len(fs)} |"]
    sc = []
    if scope.defined:
        sc += ["**In scope**", ""] + [f"- {e['raw']}" for e in scope.inc]
        if scope.exc:
            sc += ["", "**Out of scope**", ""] + [f"- {e['raw']}" for e in scope.exc]
        rules = re.search(r"^## Rules of engagement\n(.*?)(?=^## |\Z)", _read(d / SCOPE_DOC) + "\n", re.S | re.M)
        filled = [l for l in (rules.group(1).splitlines() if rules else []) if re.search(r":[ \t]*\S", l)]
        if filled:
            sc += ["", "**Rules of engagement**", ""] + filled
        res = resolved_into_scope(scope)
        if res:
            sc += ["", "**Hostnames resolving into the scope**", ""] + \
                  [f"- {n} -> {', '.join(ips)}" for n, ips, _ in res]
        conflicts, _ = scope_conflicts(scope)
        if conflicts:
            sc += ["", "**Scope conflicts** (settle these before you deliver)", ""] + [f"- {c}" for c in conflicts]
    else:
        sc.append("_No scope recorded (0-scope/scope.md)._")
    counts = {s: sum(1 for x in fs if x["sev"] == s) for s in SEVERITIES}
    summ = ["| Severity | Count |", "|---|---|"] + [f"| {s} | {counts[s]} |" for s in SEVERITIES]
    if fs:
        summ += ["", "| ID | Title | Severity | Asset | Status |", "|---|---|---|---|---|"]
        summ += [f"| {x['id']} | {_cell(x['title'])} | {x['sev']} | {_cell(x['asset'])} | {_cell(x['status'])} |"
                 for x in fs]
    else:
        summ += ["", "_No findings yet: 'pentrail finding <vector-id>' turns a confirmed lead into one._"]
    findings = "\n\n".join(_demote(clean_md(x["text"]), 2).strip() for x in fs) or "_none_"
    story = []
    for p in ("enum", "foothold", "privesc", "lateral"):
        body = _phase_story(d, p)
        if p == "enum" and st["hosts"]:
            body = "#### Hosts and services\n" + render_overview(st) + ("\n\n" + body if body else "")
        if p == "lateral" and "`pivot" in _read(d / "logbook.md"):
            body = (body + "\n\n" if body else "") + "#### Host chain\n" + render_chain(d)
        if body.strip():
            story.append(f"### {PHASE_TITLES.get(p, 'Enumeration')}\n\n{body.strip()}")
    app = ["### Hosts and services"]
    for h in st["hosts"]:
        app += ["", f"**{h['ip']}**" + (f" ({h['name']})" if h.get("name") else "")
                + (f" - {h['os']}" if h.get("os") else ""), "", render_ports(st, h)]
    if st["names"]:
        app += ["", "### Hostnames & subdomains", "", render_names(st)]
    creds = _norm_creds(st)
    if creds:
        app += ["", "### Credentials", "", "| Kind | User | Secret | Host |", "|---|---|---|---|"]
        app += [f"| {c['kind']} | {_cell(c.get('user'))} | {'`[hidden]`' if mask and c.get('secret') else _cell(c.get('secret'))} "
                f"| {_cell(c.get('host'))} |" for c in creds]
    if st.get("flags"):
        app += ["", "### Flags", ""] + [f"- **{x['name']}** ({x.get('host', '')}): "
                                         f"{'[hidden]' if mask else x['value']}" for x in st["flags"]]
    if st["commands"]:
        app += ["", "### Commands", "", render_commands(st)]
    ev = evidence_files(d)
    if ev:
        app += ["", "### Evidence files", ""] + [f"- `{rel(d, p)}`" for p in ev]
    tl = [l for l in _read(d / "logbook.md").splitlines() if l.startswith("- ")]
    if tl:
        app += ["", "### Timeline", ""] + tl
    blocks = {"meta": "\n".join(meta), "scope": "\n".join(sc), "findings-summary": "\n".join(summ),
              "findings": findings, "walkthrough": "\n\n".join(story) or "_Write your steps in the phase docs; they appear here._",
              "appendix": "\n".join(app)}
    old = f.read_text()
    new = set_blocks(old, blocks)
    if mask:
        for s in _secrets(st):
            new = new.replace(s, "[hidden]") if len(s) >= 4 else new
    _write_if_changed(f, old, new)
    return f, fs

def cmd_report(args):
    """Fill 5-report/report.md from the docs and findings; optionally export it."""
    d = require_engagement()
    st = load_state(d)
    auto_ingest_scans(d, st)
    sync_docs(d, st)
    f, fs = build_report(d, st, mask=args.mask)
    log_event("report", f"updated {rel(d, f)}" + (" (masked)" if args.mask else ""))
    ok(f"Report updated: {rel(d, f)}")
    print(f"    {len(st['hosts'])} hosts, {len(fs)} findings, {len(st['vectors'])} leads, "
          f"{len(st['commands'])} recorded commands. Your own text in it is kept.")
    if args.html or args.pdf:
        html = export_html(d, f, st)
        ok(f"HTML: {rel(d, html)}")
        if args.pdf:
            pdf = export_pdf(d, html)
            if pdf:
                ok(f"PDF : {rel(d, pdf)}")
            else:
                warn("No PDF converter found (chromium, google-chrome, wkhtmltopdf or pandoc). "
                     f"Open {rel(d, html)} in a browser and print it to PDF.")

# --- export: Markdown -> styled HTML (print it, or let a converter make the PDF) -------
REPORT_CSS = """
@page { size: A4; margin: 18mm 16mm; }
:root { --ink:#1d2330; --muted:#5b6475; --line:#d9dee7; --accent:#1f4e8c; --bg:#ffffff; --soft:#f4f6fa; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.55 "Segoe UI", "Helvetica Neue", Arial, sans-serif; color: var(--ink);
       background: var(--bg); max-width: 900px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 24pt; color: var(--accent); margin: 0 0 6px; }
h2 { font-size: 15pt; color: var(--accent); border-bottom: 2px solid var(--accent);
     padding-bottom: 4px; margin-top: 34px; page-break-after: avoid; }
h3 { font-size: 12.5pt; margin-top: 24px; page-break-after: avoid; }
h4 { font-size: 11pt; margin-top: 18px; color: var(--muted); }
table { border-collapse: collapse; width: 100%; margin: 10px 0 16px; font-size: 9.5pt; }
th, td { border: 1px solid var(--line); padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: var(--soft); }
code { font: 9pt/1.4 "DejaVu Sans Mono", Consolas, monospace; background: var(--soft);
       padding: 1px 4px; border-radius: 3px; word-break: break-all; }
pre { background: #10151f; color: #e6e9ef; padding: 10px 12px; border-radius: 6px;
      overflow-x: auto; white-space: pre-wrap; page-break-inside: avoid; }
pre code { background: none; color: inherit; padding: 0; }
img { max-width: 100%; border: 1px solid var(--line); border-radius: 4px; }
sub { color: var(--muted); }
.sev { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff; font-weight: 600; font-size: 9pt; }
.sev-critical { background:#7b1fa2; } .sev-high { background:#c62828; } .sev-medium { background:#ef6c00; }
.sev-low { background:#2e7d32; } .sev-info { background:#546e7a; }
.cover { border-bottom: 1px solid var(--line); margin-bottom: 20px; padding-bottom: 12px; }
@media print { body { padding: 0; max-width: none; } h2 { page-break-before: auto; } a { color: inherit; } }
"""

def _inline(s):
    import html as _h
    s = _h.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", s)
    s = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", r'<img alt="\1" src="\2">', s)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])_([^_]+)_(?![\w])", r"<em>\1</em>", s)
    s = re.sub(r"&lt;(/?sub)&gt;", r"<\1>", s)
    s = re.sub(r"\b(Critical|High|Medium|Low|Info)\b(?=</td>)",
               lambda m: f'<span class="sev sev-{m.group(1).lower()}">{m.group(1)}</span>', s)
    return s

def md_to_html(md):
    """A small Markdown renderer for pentrail's own docs: headings, paragraphs,
    lists, task lists, tables, fenced code, images, links, bold/italic/code."""
    import html as _h
    md = re.sub(r"<!--.*?-->", "", md, flags=re.S)
    lines, out, i = md.split("\n"), [], 0
    para = []
    def flush():
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
            para.clear()
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if s.startswith("```"):
            flush()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i]); i += 1
            out.append("<pre><code>" + _h.escape("\n".join(code)) + "</code></pre>")
            i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            flush()
            lvl = len(m.group(1))
            hid = gh_slug(m.group(2))
            out.append(f'<h{lvl} id="{hid}">{_inline(m.group(2))}</h{lvl}>')
            i += 1; continue
        if s.startswith("|") and i + 1 < len(lines) and re.match(r"^\|?\s*:?-{2,}", lines[i + 1].strip()):
            flush()
            def cells(row):
                row = row.strip().strip("|")
                return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", row)]
            head = cells(s)
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i])); i += 1
            t = ["<table><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            t += ["<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in rows]
            out.append("".join(t) + "</tbody></table>")
            continue
        m = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$", line)
        if m:
            flush()
            tag = "ol" if m.group(2)[0].isdigit() else "ul"
            items = []
            while i < len(lines):
                mm = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$", lines[i])
                if not mm:
                    if lines[i].startswith("   ") and items:        # continuation / nested block
                        items[-1] += "\n" + lines[i].strip(); i += 1; continue
                    break
                items.append(mm.group(3)); i += 1
            lis = []
            for it in items:
                first, _, more = it.partition("\n")
                box = re.match(r"^\[([ xX])\]\s+(.*)$", first)
                body = (("&#9745; " if box.group(1).lower() == "x" else "&#9744; ") + _inline(box.group(2))) \
                    if box else _inline(first)
                if more.strip():
                    body += md_to_html(more)
                lis.append(f"<li>{body}</li>")
            out.append(f"<{tag}>" + "".join(lis) + f"</{tag}>")
            continue
        if not s:
            flush(); i += 1; continue
        para.append(s); i += 1
    flush()
    return "\n".join(out)

def export_html(d, md_file, st):
    """report.md -> report.html next to it, styled for screen and print."""
    import html as _h
    body = md_to_html(_read(md_file))
    title = f"Penetration test report - {d.name}"
    page = (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{_h.escape(title)}</title>\n<style>{REPORT_CSS}</style></head>\n"
            f"<body>\n{body}\n</body></html>\n")
    out = md_file.with_suffix(".html")
    out.write_text(page)
    return out

def export_pdf(d, html_file):
    """Use whatever converter is installed; None if there is none."""
    pdf = html_file.with_suffix(".pdf")
    for exe in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(exe):
            cmd = [exe, "--headless", "--disable-gpu", "--no-sandbox", f"--print-to-pdf={pdf}",
                   "--no-pdf-header-footer", html_file.as_uri()]
            break
    else:
        if shutil.which("wkhtmltopdf"):
            cmd = ["wkhtmltopdf", "--enable-local-file-access", str(html_file), str(pdf)]
        elif shutil.which("pandoc"):
            cmd = ["pandoc", str(html_file.with_suffix(".md")), "-o", str(pdf)]
        else:
            return None
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, cwd=str(html_file.parent))
    except (OSError, subprocess.TimeoutExpired):
        return None
    return pdf if pdf.exists() else None
PLAYBOOK = {
    "ftp":    ["ftp {t}  # try anonymous:anonymous", "nmap -p{p} --script ftp-anon,ftp-syst {t}"],
    "ssh":    ["nmap -p{p} --script ssh2-enum-algos,ssh-auth-methods {t}", "ssh-audit {t}"],
    "smtp":   ["nmap -p{p} --script smtp-commands,smtp-enum-users {t}",
               "smtp-user-enum -M VRFY -U users.txt -t {t}"],
    "domain": ["dig axfr @{t} <domain>   # zone transfer", "dnsenum --dnsserver {t} <domain>"],
    # http/https are generated by web_steps() from config (web_tool + wordlist)
    "netbios-ssn": ["enum4linux-ng -A {t}", "smbclient -L //{t}/ -N   # null session",
                    "nmap -p139,445 --script smb-enum-shares,smb-os-discovery {t}"],
    "microsoft-ds": ["enum4linux-ng -A {t}", "smbclient -L //{t}/ -N   # null session",
                     "nmap -p445 --script smb-enum-shares,smb-vuln-* {t}"],
    "snmp":   ["snmpwalk -v2c -c public {t}", "onesixtyone {t} public"],
    "ldap":   ["nmap -p{p} --script ldap-rootdse {t}",
               "ldapsearch -x -H ldap://{t} -s base namingcontexts"],
    "mysql":  ["nmap -p{p} --script mysql-info,mysql-empty-password {t}", "mysql -h {t} -u root"],
    "ms-sql-s": ["nmap -p{p} --script ms-sql-info,ms-sql-empty-password {t}"],
    "rdp":    ["nmap -p{p} --script rdp-ntlm-info {t}  # hostname/domain"],
    "pop3":   ["nmap -p{p} --script pop3-capabilities {t}"],
    "imap":   ["nmap -p{p} --script imap-capabilities {t}"],
    "wsman":  ["nmap -p{p} --script http-title {t}  # WinRM; evil-winrm once you have creds"],
    "nfs":    ["showmount -e {t}", "nmap -p{p} --script nfs-ls,nfs-showmount {t}"],
    "redis":  ["redis-cli -h {t} info", "nmap -p{p} --script redis-info {t}"],
    "mongodb":["nmap -p{p} --script mongodb-info {t}"],
    "postgresql": ["nmap -p{p} --script pgsql-brute {t}"],
    "rpcbind":["rpcinfo -p {t}"],
}
PORT_FALLBACK = {80: "http", 8080: "http", 8000: "http", 8443: "https", 443: "https",
                 445: "microsoft-ds", 139: "netbios-ssn", 5985: "wsman", 5986: "wsman"}

def web_steps(scheme, port, t):
    """Directory brute-force step built from config (web_tool + wordlist)."""
    tool = CFG.get("web_tool", "feroxbuster")
    wl = CFG.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    url = f"{scheme}://{t}:{port}"
    k = " -k" if scheme == "https" else ""
    if tool == "ffuf":
        brute = f"ffuf -u {url}/FUZZ -w {wl}{k}"
    elif tool == "gobuster":
        brute = f"gobuster dir -u {url} -w {wl}{k}"
    else:
        brute = f"feroxbuster -u {url} -w {wl}{k}"
    steps = [f"whatweb {url}  &&  curl -s{'k' if scheme == 'https' else ''}I {url}", brute]
    if scheme == "https":
        steps.append(f"nmap -p{port} --script ssl-cert,ssl-enum-ciphers {t}  # hostnames in the cert")
    steps.append(f"nikto -h {url}")
    steps.append("check /robots.txt, page source, and vhosts via the Host header")
    return steps

DIRBUSTERS = ("feroxbuster", "ffuf", "gobuster", "dirsearch", "dirb", "wfuzz")

def _latest_scan(d):
    files = [f for sd in scan_dirs(d) for f in sd.iterdir() if f.is_file()]
    return max(files, key=lambda p: p.stat().st_mtime, default=None)

def _host_steps(h):
    """[(port, service, [step, ...])] for a host's open ports."""
    out = []
    for p in sorted(h["ports"], key=lambda p: p["port"]):
        port, svc = p["port"], p["service"] or "unknown"
        key = svc if (svc in PLAYBOOK or svc in ("http", "https")) else PORT_FALLBACK.get(port, svc)
        if key in ("http", "https", "ssl/http", "http-proxy"):
            scheme = "https" if ("https" in key or "ssl" in svc or port in (443, 8443)) else "http"
            steps = web_steps(scheme, port, h["ip"])
        else:
            steps = [s.format(t=h["ip"], p=port, h=h["ip"]) for s in PLAYBOOK.get(key, [])]
        out.append((port, svc, steps))
    return out

def _step_done(st, host, step, legacy=""):
    tool = re.split(r"[ /]", step.strip())[0].lower()
    if tool.startswith("check"):
        return False
    script = re.search(r"--script\s+([\w-]+)", step) if tool == "nmap" else None
    for c in st["commands"]:
        if host not in c.get("hosts", []) and host not in c["cmd"]:
            continue
        if tool == "nmap":
            if script and script.group(1) in c["cmd"]:
                return True
        elif c.get("prog") == tool or (tool in DIRBUSTERS and c.get("prog") in DIRBUSTERS):
            return True
    return bool(legacy) and tool in legacy      # projects from before 1.2: tool named in the logbook

def enum_steps(st, h, legacy=""):
    items = []
    for port, svc, steps in _host_steps(h):
        for s in steps:
            items.append((f"{port}/{svc}: {s}", _step_done(st, h["ip"], s, legacy)))
    return items

def cmd_next(args):
    d = require_engagement()
    st = load_state(d)
    n = auto_ingest_scans(d, st, quiet=False)
    target = st.get("target") or current_target()
    h = _find_host(st, target) if target else None
    if not h or not h["ports"]:
        scan = _latest_scan(d)
        warn(f"No open ports known for {target or 'the target'} yet. Run a scan, e.g.:")
        print(f"    nmap -sC -sV -oN 1-enum/scans/initial.txt {target or '<target>'}")
        print(f"    nmap -p- --min-rate 2000 -oN 1-enum/scans/allports.txt {target or '<target>'}")
        if scan:
            print(f"    {DIM}(read {rel(d, scan)}, no open ports for this host in it){N}")
        return
    legacy = (_read(d / "logbook.md") + _read(d / "notes" / "notes.md")).lower() \
        if (d / "notes" / "notes.md").exists() else ""
    info(f"{h['ip']}: {len(h['ports'])} open port(s)" + (f", {n['ports']} new from 1-enum/scans/" if n["ports"] else ""))
    print()
    total = done = 0
    untouched = []
    for port, svc, steps in _host_steps(h):
        label = f"{G}{port:>5}{N}/{svc}"
        if not steps:
            print(f"{label}  {DIM}(no standard playbook - enumerate manually){N}")
            continue
        print(label)
        todo = 0
        for s in steps:
            total += 1
            if _step_done(st, h["ip"], s, legacy):
                done += 1
                print(f"    {G}[x]{N} {DIM}{s}{N}")
            else:
                todo += 1
                print(f"    {Y}[ ]{N} {s}")
        if todo == len(steps):
            untouched.append(f"{port}/{svc}")
        print()
    print(f"{B}Progress:{N} {done}/{total} standard steps seen.  {DIM}(same list: 1-enum/enum.md){N}")
    if done == 0:
        warn("Nothing done yet - start at the top of the list above.")
    elif untouched:
        warn("Services you haven't touched at all: " + ", ".join(untouched)
             + "  <- usually where the way in is when you feel stuck.")
    else:
        ok("You've started on every open service. Still stuck? Re-run a full port scan "
           "(nmap -p-), check vhosts/UDP, and re-read 'pentrail vectors' and your notes.")
    others = [x["ip"] for x in st["hosts"] if x is not h and x["ports"]
              and any(not dn for _, dn in enum_steps(st, x))]
    if others:
        print(f"{DIM}Other hosts with open steps: {', '.join(others)}  (pentrail target <host>){N}")
    tl = d / "logbook.md"
    if tl.exists():
        mins = (time.time() - tl.stat().st_mtime) / 60
        if mins > int(CFG["stale_minutes"]):
            warn(f"Nothing logged for {int(mins)} min. Stuck usually means a rabbit hole - "
                 "jot what you tried (pentrail note ...) so the checklist stays accurate.")
    save_state(d, st)

# ----------------------------------------------------------------------------- config
def cmd_config(args):
    if not args.key:
        for k, v in load_config().items():
            print(f"{k} = {v}")
        print(f"\n({CONFIG_FILE})"); return
    cfg = dict(load_config())
    if args.value is None:
        print(cfg.get(args.key, "")); return
    if args.key not in DEFAULTS:
        die(f"Unknown key: {args.key}. Known: {', '.join(DEFAULTS)}")
    val = args.value
    if args.key in INT_KEYS:
        try:
            val = int(args.value)
        except ValueError:
            die(f"{args.key} must be an integer (got {args.value!r})")
    if args.key == "scope_guard" and val not in GUARD_MODES:
        die(f"scope_guard is one of: {', '.join(GUARD_MODES)}")
    set_config(args.key, val)
    ok(f"{args.key} = {val}  (saved to {CONFIG_FILE})")
# ----------------------------------------------------------------------------- /etc/hosts
def cmd_resolve(args):
    hosts_path = Path("/etc/hosts")
    if args.clean:
        kept = [l for l in hosts_path.read_text().splitlines() if "# pentrail:" not in l]
        if _write_hosts(hosts_path, kept) == 0:
            ok("Removed pentrail-added lines from /etc/hosts")
        else:
            warn("Could not write /etc/hosts (sudo failed?)")
        return
    names = list(args.names)
    ip = current_target()
    if names and IP_RE.match(names[0]):
        ip = names.pop(0)
    if not ip or not names:
        die("Usage: pentrail resolve [ip] <hostname> [hostname...]  (ip defaults to the engagement target)")
    tag = f"pentrail:{current_dir().name if current_dir() else 'manual'}"
    lines = hosts_path.read_text().splitlines()
    added = []
    for name in names:
        if not re.match(r"^[A-Za-z0-9.-]+$", name):
            warn(f"Invalid hostname skipped: {name}"); continue
        if any(not l.lstrip().startswith("#") and "# pentrail:" not in l and name in l.split() for l in lines):
            warn(f"{name} already in /etc/hosts (not via pentrail) - skipped"); continue
        lines = [l for l in lines if not ("# pentrail:" in l and name in l.split())]
        lines.append(f"{ip}\t{name}\t# {tag}")
        added.append(name)
    if not added:
        return
    if _write_hosts(hosts_path, lines) == 0:   # only claim success after the sudo write works
        for name in added:
            ok(f"Added {ip}  {name} to /etc/hosts")
            log_event("resolve", f"{ip} {name}")
    else:
        warn("Could not write /etc/hosts (sudo failed?) - nothing added")

def _write_hosts(path, lines):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_DIR / "hosts.tmp"
    tmp.write_text("\n".join(lines) + "\n")
    rc = subprocess.run([*SUDO, "cp", str(tmp), str(path)]).returncode
    tmp.unlink(missing_ok=True)
    return rc

def cmd_doctor(args):
    """Environment self-check: what is installed, what is missing, and how to fix it."""
    def row(label, present, hint=""):
        mark = f"{G}ok{N}" if present else f"{R}--{N}"
        tail = f"  {DIM}{hint}{N}" if hint else ""
        print(f"  [{mark}] {label}{tail}")

    py = sys.version_info
    print(f"{B}pentrail {VERSION}{N}   Python {py.major}.{py.minor}.{py.micro}   {sys.platform}\n")
    missing = []

    print(f"{B}Core{N} (VPN + capture)")
    for tool, apt in tools_in("core"):
        p = shutil.which(tool)
        if not p: missing.append(tool)
        row(tool, bool(p), p or f"sudo apt install {apt}")

    print(f"\n{B}Screenshots{N}")
    r = CFG.get("termshot_cmd", "termshot")
    p = shutil.which(r)
    row(r, bool(p), p or TOOL_NOTES["termshot"])

    print(f"\n{B}Enumeration{N} (suggested by 'next'; install what you use)")
    for tool, apt in tools_in("enum"):
        p = shutil.which(tool)
        if not p: missing.append(tool)
        row(tool, bool(p), p or (f"sudo apt install {apt}" if apt else ""))

    print(f"\n{B}Config & paths{N}")
    row(f"config file: {CONFIG_FILE}", CONFIG_FILE.exists(),
        "" if CONFIG_FILE.exists() else "created on first 'config' set")
    for key in ("base_dir", "vpn_dir"):
        dp = Path(CFG[key])
        row(f"{key}: {dp}", dp.is_dir(), "" if dp.is_dir() else "created on first use")
    vd = Path(CFG["vpn_dir"])
    n_ovpn = len(list(vd.glob("*.ovpn"))) if vd.is_dir() else 0
    row(f".ovpn files in vpn_dir: {n_ovpn}", n_ovpn > 0,
        "" if n_ovpn else "put your VPN configs there, or pass a path to 'up'")
    wl = Path(os.path.expanduser(CFG["wordlist"]))
    if wl.exists():
        row(f"wordlist: {wl}", True)
    else:
        alts = find_wordlists(limit=1)
        hint = (f"missing; found {alts[0]} - 'pentrail setup' picks one" if alts
                else "missing; 'sudo apt install seclists' or 'pentrail config wordlist <path>'")
        row(f"wordlist: {wl}", False, hint)
    row(f"web_tool: {CFG['web_tool']}", bool(shutil.which(CFG["web_tool"])),
        "" if shutil.which(CFG["web_tool"]) else "install it or 'pentrail config web_tool <other>'")
    print(f"  {DIM}redact list: {len(load_redacts())} secret(s){N}")
    d = current_dir()
    if d:
        print(f"  {DIM}active project: {d.name}{N}")
    if missing:
        print(f"\n{Y}[!]{N} {len(missing)} tool(s) missing: {', '.join(missing)}")
        info("Install them automatically with:  pentrail setup")
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        warn("Running under sudo; run pentrail as your normal user.")

# ----------------------------------------------------------------------------- setup / install
def _pkg_manager():
    """The system package manager and a builder for its non-interactive install
    command, as (name, build(pkgs)->argv). None if we don't recognise one."""
    if shutil.which("apt-get"):
        return "apt-get", lambda pkgs: [*SUDO, "apt-get", "install", "-y", *pkgs]
    if shutil.which("apt"):
        return "apt", lambda pkgs: [*SUDO, "apt", "install", "-y", *pkgs]
    return None, None

def _git_root(start):
    """The top of the git work tree containing 'start', or None."""
    try:
        out = subprocess.run(["git", "-C", str(start), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None

def _file_version(path):
    """Read the VERSION string straight from a pentrail.py on disk (for old->new)."""
    try:
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', path.read_text(), re.M)
        return m.group(1) if m else "?"
    except OSError:
        return "?"

def _remember_src_repo(repo):
    """Persist the source checkout so the installed launcher can find it later."""
    try:
        cfg = dict(load_config())
        if cfg.get("src_repo") == str(repo):
            return
        cfg["src_repo"] = str(repo)
        save_config({k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS})
    except OSError:
        pass

def _append_shell_helper(assume_yes, dry):
    """Offer to add the pcd() helper to the user's shell rc, idempotently."""
    block = ("\n# >>> pentrail >>>\n"
             "# cd into the active project with $TARGET/$VPN_IP already set\n"
             'pcd() { cd "$(pentrail dir)" && source .env; }\n'
             "# <<< pentrail <<<\n")
    shell = os.path.basename(os.environ.get("SHELL", ""))
    rc = HOME / (".zshrc" if shell == "zsh" else ".bashrc")
    try:
        existing = rc.read_text() if rc.exists() else ""
    except OSError as e:
        warn(f"Could not read {rc}: {e}"); return
    if "# >>> pentrail >>>" in existing or "pentrail dir" in existing:
        ok(f"shell helper already in {rc}"); return
    if not (assume_yes or confirm(f"Add the pcd() helper to {rc}?")):
        info(f"Skipped. Add it yourself later:\n    {block.strip()}")
        return
    if dry:
        info(f"[dry-run] would append pcd() to {rc}"); return
    try:
        with rc.open("a") as fh:
            fh.write(block)
        ok(f"Added pcd() to {rc}  (open a new shell, then: pcd)")
    except OSError as e:
        warn(f"Could not write {rc}: {e}")

def cmd_setup(args):
    """Guided install: put pentrail on PATH, install missing tools, set vpn_dir and
    offer the shell helper. Uses sudo only for the steps that need it (install, apt)."""
    dry = args.dry_run
    yes = args.yes
    def ask(m):
        if yes:
            print(f"{Y}[?]{N} {m} [y/N] y"); return True
        return confirm(m)
    def run(cmd):
        info("$ " + " ".join(cmd))
        if dry:
            return 0
        try:
            return subprocess.call(cmd)
        except OSError as e:
            err(f"could not run {cmd[0]}: {e}"); return 1

    print_banner()
    print(f"\n{DIM}Guided setup. Nothing is installed without asking"
          f"{' (dry run: nothing will change)' if dry else ''}.{N}\n")
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        warn("Run setup as your normal user, not with sudo; it calls sudo itself "
             "only for the install and apt steps.")

    # 1. Put pentrail on PATH ------------------------------------------------
    if not args.no_launcher:
        print(f"{B}1. Launcher{N}")
        print(f"  {DIM}Copies this script to /usr/local/bin so you can run 'pentrail' from any")
        print(f"  directory instead of 'python3 pentrail.py'. Needs sudo once to write there.{N}")
        target = Path("/usr/local/bin/pentrail")
        src = Path(__file__).resolve()
        if src == target.resolve() and target.exists():
            ok(f"pentrail already installed at {target}")
        elif not ask(f"Install {src.name} to {target} (sudo)?"):
            info("Skipped the launcher.")
        else:
            rc = run([*SUDO, "install", "-m", "755", str(src), str(target)])
            if rc == 0 and not dry:
                ok(f"Installed. Run it from anywhere: {B}pentrail{N}")
                repo = _git_root(src.parent)
                if repo:
                    _remember_src_repo(repo)
                    ok(f"source repo remembered for 'pentrail update': {repo}")
                if not shutil.which("pentrail"):
                    warn(f"{target.parent} is not on your $PATH; add it to use 'pentrail'.")
            elif rc:
                warn("install failed; see the error above.")
        print()

    # 2. Install missing tools ----------------------------------------------
    if not args.no_tools:
        print(f"{B}2. Tools{N}")
        print(f"  {DIM}Core tools (openvpn, ip, ping, script) are what pentrail itself needs for")
        print(f"  the VPN and capture. Enumeration tools (nmap, ffuf, smbclient, ...) are what")
        print(f"  'pentrail next' suggests - install the ones you use. Installed via apt, with")
        print(f"  sudo. Pass --core-only to skip the enumeration set.{N}")
        groups = ["core"] if args.core_only else ["core", "enum"]
        mgr, build = _pkg_manager()
        for group in groups:
            wanted = tools_in(group)
            missing = [(c, apt) for c, apt in wanted if not shutil.which(c)]
            have = len(wanted) - len(missing)
            label = "core" if group == "core" else "enumeration"
            if not missing:
                ok(f"all {len(wanted)} {label} tools present"); continue
            names = ", ".join(c for c, _ in missing)
            pkgs = sorted({apt for _, apt in missing if apt})
            noapt = [c for c, apt in missing if not apt]
            print(f"  {Y}missing {label}{N} ({have}/{len(wanted)} present): {names}")
            if not pkgs:
                info("nothing here is installable from apt; see notes below.")
            elif not mgr:
                warn("No apt/apt-get found. Install with your package manager:")
                print(f"    {', '.join(pkgs)}")
            elif ask(f"Install {len(pkgs)} package(s) with {mgr}?  ({' '.join(pkgs)})"):
                run(build(pkgs))
            else:
                info("Skipped.")
            for c in noapt:
                note = TOOL_NOTES.get(c)
                if note:
                    print(f"    {DIM}{c}: {note}{N}")
        # Optional extras (not on apt) - point to them, do not install.
        for c, _apt in tools_in("extra"):
            if not shutil.which(c) and TOOL_NOTES.get(c):
                print(f"  {DIM}optional {c}: {TOOL_NOTES[c]}{N}")
        print()

    # 3. Config: where your .ovpn files live --------------------------------
    print(f"{B}3. Config{N}")
    print(f"  {DIM}vpn_dir is the folder pentrail looks in for your .ovpn files. wordlist is")
    print(f"  the directory list 'pentrail next' uses for web brute-forcing. Config is saved")
    print(f"  to {CONFIG_FILE}.{N}")
    cfg = dict(load_config())
    cur_vpn = cfg.get("vpn_dir", DEFAULTS["vpn_dir"])
    new_vpn = args.vpn_dir
    if new_vpn is None and not yes:
        try:
            ans = input(f"{Y}[?]{N} vpn_dir (where your .ovpn files live) [{cur_vpn}]: ").strip()
        except EOFError:
            ans = ""
        new_vpn = ans or None
    if new_vpn:
        new_vpn = os.path.expanduser(new_vpn)
        if not dry:
            cfg["vpn_dir"] = new_vpn
            save_config({k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS})
        ok(f"vpn_dir = {new_vpn}")
    else:
        info(f"vpn_dir unchanged ({cur_vpn})")
    for key in ("vpn_dir", "base_dir"):
        dp = Path(os.path.expanduser(cfg.get(key, DEFAULTS[key])))
        if dry:
            info(f"[dry-run] would ensure {key} {dp} exists")
        else:
            try:
                dp.mkdir(parents=True, exist_ok=True)
                ok(f"{key} ready: {dp}")
            except OSError as e:
                warn(f"could not create {key} {dp}: {e}")

    # wordlist: keep the configured one if present, else find one on the machine
    wl = Path(os.path.expanduser(cfg.get("wordlist", DEFAULTS["wordlist"])))
    if wl.exists():
        ok(f"wordlist present: {wl}")
    else:
        found = find_wordlists()
        if not found:
            info(f"wordlist not found ({wl}).")
            print(f"    {DIM}install SecLists ('sudo apt install seclists') or set one by hand:")
            print(f"    pentrail config wordlist <path>{N}")
        else:
            print(f"  {Y}configured wordlist missing{N}; found {len(found)} on this machine"
                  f" (best first):")
            for i, f in enumerate(found, 1):
                print(f"    {i:>2}) {f}")
            choice = found[0]
            if not yes:
                try:
                    ans = input(f"{Y}[?]{N} use which? [1-{len(found)}, Enter={B}1{N}, s=skip] ").strip().lower()
                except EOFError:
                    ans = ""
                if ans in ("s", "skip"):
                    choice = None
                elif ans:
                    if ans.isdecimal() and 1 <= int(ans) <= len(found):
                        choice = found[int(ans) - 1]
                    else:
                        warn("not a valid choice; leaving wordlist unchanged"); choice = None
            if choice is None:
                info("wordlist unchanged.")
            elif dry:
                info(f"[dry-run] would set wordlist = {choice}")
            else:
                cfg["wordlist"] = str(choice)
                save_config({k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS})
                ok(f"wordlist = {choice}")
    print()

    # About the VPN ----------------------------------------------------------
    print(f"{B}About the VPN{N}")
    print(f"  {DIM}pentrail connects with 'pentrail up' / 'pentrail new', not here. openvpn runs")
    print(f"  as root (sudo, for the tun device and routes) and as a background daemon, so it")
    print(f"  stays up after you close the terminal or exit pentrail - you do not need a")
    print(f"  separate terminal for it. 'pentrail down' stops it; run 'pentrail watch' in its")
    print(f"  own terminal if you want it auto-restarted when it drops.{N}")
    print()

    # 4. Shell helper --------------------------------------------------------
    if not args.no_shell:
        print(f"{B}4. Shell helper{N}")
        print(f"  {DIM}Adds a pcd() function to your shell so one word jumps into the active")
        print(f"  project with $TARGET/$VPN_IP set. cd must happen in your own shell, so it")
        print(f"  cannot be a pentrail command. Added once; safe to re-run.{N}")
        _append_shell_helper(yes, dry)
        print()

    # Done -------------------------------------------------------------------
    print(f"{B}Next{N}")
    _cmd("pentrail doctor", "re-check the environment")
    _cmd("pentrail new box1 10.10.10.5", "start your first project")
    print(f"  {DIM}tip: pentrail config default_vpn <file.ovpn> skips the VPN picker{N}")

def cmd_update(args):
    """Update pentrail in place: git pull the source checkout and reinstall the
    launcher so the new version is the one that runs. Finds the repo from where it
    runs, or from config['src_repo'] (recorded by setup)."""
    dry = args.dry_run
    yes = args.yes
    def ask(m):
        if yes:
            print(f"{Y}[?]{N} {m} [y/N] y"); return True
        return confirm(m)
    def run(cmd):
        info("$ " + " ".join(cmd))
        if dry:
            return 0
        try:
            return subprocess.call(cmd)
        except OSError as e:
            err(f"could not run {cmd[0]}: {e}"); return 1

    # Locate the source checkout. Try, in order: the tree this script runs from
    # (python3 pentrail.py update), the directory you're standing in (running the
    # installed launcher from inside your clone), then the repo setup remembered.
    # The first candidate that is a git checkout containing pentrail.py wins.
    cands = [Path(__file__).resolve().parent, Path.cwd()]
    if CFG.get("src_repo"):
        cands.append(Path(os.path.expanduser(CFG["src_repo"])))
    repo = None
    for c in cands:
        root = _git_root(c)
        if root and (root / "pentrail.py").is_file():
            repo = root
            break
    if not repo:
        die("Don't know where pentrail's source repo is. cd into your pentrail git "
            "checkout and run 'pentrail update' there, or point to it:  "
            "pentrail config src_repo <path>")
    src = repo / "pentrail.py"
    if not dry:
        _remember_src_repo(repo)   # keep it so the installed launcher finds it next time

    git = ["git", "-C", str(repo)]
    cur_branch = subprocess.run([*git, "rev-parse", "--abbrev-ref", "HEAD"],
                                capture_output=True, text=True).stdout.strip() or "?"
    old = _file_version(src)
    print(f"{B}pentrail update{N}   repo {repo}   branch {cur_branch}   version {old}\n")

    # 1. Pull ----------------------------------------------------------------
    if args.branch and args.branch != cur_branch:
        if not ask(f"Switch branch {cur_branch} -> {args.branch}?"):
            info("Keeping the current branch.")
        elif run([*git, "checkout", args.branch]) == 0:
            cur_branch = args.branch
    if not ask(f"git pull origin {cur_branch}?"):
        info("Aborted; nothing pulled."); return
    for attempt in range(4):
        rc = run([*git, "pull", "--ff-only", "origin", cur_branch])
        if rc == 0 or dry:
            break
        if attempt < 3:
            wait = 2 ** (attempt + 1)
            warn(f"pull failed; retrying in {wait}s ({attempt + 1}/3)")
            time.sleep(wait)
    else:
        die("git pull failed. If the branch has diverged, resolve it by hand "
            "(e.g. 'git -C <repo> status') and re-run. Nothing was reinstalled.")

    new = _file_version(src)
    if not dry and new == old:
        ok(f"Already up to date (version {new}).")
    elif not dry:
        ok(f"Pulled: version {old} -> {new}.")

    # 2. Reinstall the launcher ---------------------------------------------
    if args.no_install:
        info("Skipped reinstall (--no-install)."); return
    target = Path("/usr/local/bin/pentrail")
    installed = target.exists()
    if not installed and not shutil.which("pentrail"):
        info("pentrail is not installed to a bin dir; run 'pentrail setup' to install it.")
        return
    dest = target if installed else Path(shutil.which("pentrail"))
    if src.resolve() == dest.resolve():
        ok("Running straight from the repo; nothing to reinstall."); return
    if not ask(f"Reinstall {src} to {dest} (sudo)?"):
        info("Skipped the reinstall; the pulled code is in the repo but not on $PATH yet.")
        return
    if run([*SUDO, "install", "-m", "755", str(src), str(dest)]) == 0 and not dry:
        ok(f"Reinstalled {dest}. 'pentrail version' should now show {new}.")

def _remove_shell_helper(assume_yes, dry):
    """Remove the pcd() helper block from the shell rc files (undo setup)."""
    block_re = re.compile(r"\n?# >>> pentrail >>>.*?# <<< pentrail <<<\n?", re.S)
    found = False
    for rc in (HOME / ".zshrc", HOME / ".bashrc"):
        try:
            text = rc.read_text() if rc.exists() else ""
        except OSError as e:
            warn(f"Could not read {rc}: {e}"); continue
        if "# >>> pentrail >>>" not in text:
            continue
        found = True
        if not (assume_yes or confirm(f"Remove the pcd() helper from {rc}?")):
            info(f"Left {rc} unchanged."); continue
        if dry:
            info(f"[dry-run] would remove pcd() from {rc}"); continue
        try:
            rc.write_text(block_re.sub("\n", text))
            ok(f"Removed pcd() from {rc}  (open a new shell for it to take effect)")
        except OSError as e:
            warn(f"could not write {rc}: {e}")
    if not found:
        info("No pcd() helper found in your shell rc.")

def cmd_uninstall(args):
    """Undo 'pentrail setup': remove the /usr/local/bin launcher and the pcd shell
    helper; with --config also remove config + VPN state. Your pentest projects are
    never deleted. Uses sudo only to remove the launcher."""
    dry = args.dry_run
    yes = args.yes
    def ask(m):
        if yes:
            print(f"{Y}[?]{N} {m} [y/N] y"); return True
        return confirm(m)
    def run(cmd):
        info("$ " + " ".join(cmd))
        if dry:
            return 0
        try:
            return subprocess.call(cmd)
        except OSError as e:
            err(f"could not run {cmd[0]}: {e}"); return 1

    print_banner()
    print(f"\n{DIM}Removes the launcher and shell helper. Your pentest projects are never "
          f"deleted.{' (dry run: nothing will change)' if dry else ''}{N}\n")

    # 0. A running VPN is a root daemon that would be orphaned once the launcher is
    #    gone (no 'pentrail down' left to stop it), so offer to stop it first.
    if vpn_running():
        warn("The VPN is still connected (a root openvpn daemon).")
        if ask("Stop it now before removing pentrail?"):
            if not dry:
                vpn_down()
            else:
                info("[dry-run] would run 'pentrail down'")

    # 1. Launcher ------------------------------------------------------------
    print(f"{B}1. Launcher{N}")
    target = Path("/usr/local/bin/pentrail")
    paths = []
    def consider(p):
        # Skip a source checkout (pentrail.py inside a git repo) so we never rm the
        # repo file - only installed launchers. Removing the launcher you're running
        # is fine on Linux (the inode lives until the process exits).
        if p in paths or (p.name == "pentrail.py" and _git_root(p.parent)):
            return
        if p.exists() or p.is_symlink():
            paths.append(p)
    consider(target)
    w = shutil.which("pentrail")
    if w:
        consider(Path(w))
    if not paths:
        info("No installed launcher found (nothing in /usr/local/bin or on $PATH).")
    for p in paths:
        if ask(f"Remove {p} (sudo)?") and run([*SUDO, "rm", "-f", str(p)]) == 0 and not dry:
            ok(f"Removed {p}")

    # 2. Shell helper --------------------------------------------------------
    print(f"\n{B}2. Shell helper{N}")
    _remove_shell_helper(yes, dry)

    # 3. Settings & VPN state (opt-in) --------------------------------------
    print(f"\n{B}3. Settings & VPN state{N}")
    cfgdir, statedir = CONFIG_FILE.parent, STATE_DIR
    if args.config:
        for p in (cfgdir, statedir):
            if not p.is_dir():
                continue
            if ask(f"Delete {p}?"):
                if dry:
                    info(f"[dry-run] would delete {p}")
                else:
                    shutil.rmtree(p, ignore_errors=True); ok(f"Deleted {p}")
    else:
        info(f"Kept config ({cfgdir}) and VPN state ({statedir}).")
        print(f"  {DIM}pass --config to remove those too (your redact list lives there).{N}")

    # 4. Projects are never auto-deleted ------------------------------------
    base = Path(CFG["base_dir"])
    print(f"\n{B}Your work is safe{N}")
    print(f"  {DIM}pentest projects in {base} were NOT touched - delete them yourself if "
          f"you want them gone.{N}")
    if not dry:
        ok("pentrail uninstalled.")


# ----------------------------------------------------------------------------- help guide
HELP_SECTIONS = [
    ("EVERY DAY  (these five carry a whole box)", [
        ("new <name> [target...]", "Start a project: phase folders, docs, scope, VPN.",
                            "Targets may be IPs, ranges, domains or *.domain. --no-vpn to skip it."),
        ("capture [phase] [--warn]", "Record your shell: every command with its time, the scope guard,",
                            "and what the output shows goes into the phase docs."),
        ("next",            "What to enumerate next on the active box, ticked off as you go."),
        ("finding <id|title>", "Turn a confirmed lead into a finding file for the report."),
        ("report [--html|--pdf]", "Fill 5-report/report.md from your docs and findings; export it."),
    ]),
    ("PROJECT", [
        ("resume [name]",   "Come back: switch, reconnect the VPN, recap where you were."),
        ("use <name>",      "Switch project without touching the VPN."),
        ("list",            "All projects; '*' marks the current one."),
        ("target <host>",   "Set the active box (IP or hostname); $TARGET follows."),
        ("phase [name]",    "Show or set the phase: scope enum foothold privesc lateral report."),
        ("docs",            "List the working docs and refresh their auto blocks."),
        ("dir",             "Print the project path: cd \"$(pentrail dir)\"."),
    ]),
    ("SCOPE", [
        ("scope",           "Show the scope from 0-scope/scope.md and the guard mode."),
        ("scope add|out <asset...>", "Add to In scope / Out of scope (IP, range, domain, *.domain, URL)."),
        ("scope check <host|cmd>", "Is this in scope? Works on a whole command line too."),
        ("scope resolve",   "Look up the names pentrail knows; names in your ranges join the",
                            "scope, contradictions (out-of-scope name in a range) are listed."),
        ("scope guard strict|warn|off", "strict stops out-of-scope commands, warn only reports them",
                            "(logged). Outside a capture: the setting; inside: this capture only."),
    ]),
    ("WHAT YOU FOUND", [
        ("hosts [host]",    "Hosts with their ports; one host shows ports, web, names, leads."),
        ("names [--plain]", "Hostnames and subdomains seen in scope (--plain: one per line)."),
        ("vector(s) [type]", "Leads, sorted by status. vector add | <status> <id> | rm <id>."),
        ("cred(s)",         "Credentials: cred add <user:secret> | users | hashes | export."),
        ("flag <name> <value>", "Record a flag (user/root also marks the box owned)."),
        ("shot [-l label] <cmd>", "Run a command and keep a screenshot + text as evidence."),
        ("shot --last [lines]", "During a capture: screenshot what you just ran."),
        ("ingest <file>",   "Read a saved tool output (nmap -oN/-oX, ffuf, gobuster, ...)."),
        ("note [-t host] <text>", "A quick note on the active box (or another host); in notes.md",
                            "and enum.md. Hosts, #3, F01 and N2 in the text become links."),
        ("notes [host]",    "List notes (one host: its own and those that mention it);",
                            "notes edit <N> \"<text>\" / notes rm <N>."),
        ("log [n]",         "The logbook: everything that happened, with times."),
    ]),
    ("HOSTS & MOVEMENT", [
        ("host add|own|rm <ip>", "Track a host, mark it owned, or stop tracking it."),
        ("pivot <from> <to> [--via note]", "Log movement between hosts (shown in lateral.md)."),
    ]),
    ("VPN", [
        ("up [file.ovpn] / down / restart", "Connect (root daemon, persists), disconnect, reconnect."),
        ("status / check [ip]", "VPN + project state / diagnose with a fix per problem."),
        ("watch [seconds]", "Auto-restart the VPN when it hangs (own terminal)."),
    ]),
    ("SETTINGS & INSTALL", [
        ("set <key> <value>", "Project facts (domain, dc-ip, url, ...); 'set' lists them."),
        ("focus <text>",    "What you are on right now (home screen)."),
        ("redact add <value>", "Your OWN secrets, scrubbed from every capture (hashes only)."),
        ("resolve [ip] <name...>", "Add /etc/hosts entries; --clean removes pentrail's own."),
        ("config [key] [value]", "Settings: base_dir, vpn_dir, scope_guard, author, wordlist, ..."),
        ("doctor / setup / update / uninstall", "Check, install, update or remove pentrail."),
        ("version",         "Print the version."),
    ]),
]
FLOW = [
    "pentrail new box1 10.10.10.5", 'cd "$(pentrail dir)" && source .env',
    "pentrail capture recon            # scans in here are read and checked against scope",
    "pentrail next                     # what to do next; also in 1-enum/enum.md",
    "pentrail finding 3                # a confirmed lead becomes 5-report/findings/F01-...md",
    "pentrail report --html            # 5-report/report.md (+ .html to print as PDF)",
]
BANNER = r"""
                 _             _ _
  _ __  ___ _ _ | |_ _ _ __ _(_) |
 | '_ \/ -_) ' \|  _| '_/ _` | | |
 | .__/\___|_||_|\__|_| \__,_|_|_|
 |_|   the pentest logbook  v%s
""".strip("\n")

def print_banner():
    print(f"{B}{BANNER % VERSION}{N}")

def _cmd(c, text):
    print(f"  {G}{c:<34}{N}{text}")

DETAILS = {
    "resume": ("Come back to a project after a break, reboot or dropped VPN.",
        "pentrail resume [name|path]",
        ["No name = the project you touched most recently. Switches to it, reconnects",
         " the VPN if it is down, and prints a recap: target, hosts (and how many owned),",
         " open attack vectors, the ones you marked 'working', and the last logbook lines.",
         "Nothing is ever lost: every command already writes to disk as it runs."],
        "pentrail resume          # or: pentrail resume blackfield"),
    "check": ("Find out why the connection or the target is not working.",
        "pentrail check [ip]",
        ["Runs through: duplicate openvpn processes, a tun IP, your internet, the VPN",
         " gateway, whether the route to the target really goes through the tunnel, ping,",
         " and MTU. Then it reads the openvpn log for known errors.",
         "Outcome: a line per check (ok / problem) and a concrete fix for each problem,",
         " e.g. 'duplicate connection -> pentrail restart'. Reads only; changes nothing."],
        "pentrail check 10.10.10.192"),
    "watch": ("Keep the VPN alive hands-off so a dead tunnel never costs you progress.",
        "pentrail watch [seconds]        (default 30; Ctrl+C to stop)",
        ["Leave it running in its own terminal. Every <seconds> it checks that openvpn",
         " is alive, tun has an IP, and the VPN gateway answers a ping. Three failed",
         " checks in a row and it runs 'pentrail restart' for you and logs it.",
         "Outcome: you stop losing progress to a hung VPN; each auto-restart adds a",
         " 'vpn auto-restarted' line to the logbook. Asks for sudo once up front so it",
         " is allowed to restart openvpn later."],
        "pentrail watch 20"),
    "capture": ("Record the shell you work in and turn its output into logged leads.",
        "pentrail capture [label]",
        ["Starts a recording shell (via 'script'); work as normal and type 'exit' to",
         " stop. The whole session is saved to evidence/terminal/<box>_<date>_<label>.log",
         " and then parsed: web paths, open ports, hostnames, credentials and recognised",
         " vulnerability signals become logbook entries and tagged attack vectors.",
         "pentrail's own output run inside the capture (e.g. 'pentrail log', 'vectors',",
         " 'creds') is NOT re-ingested, so reviewing your findings mid-capture is safe.",
         "Only one capture runs at a time. Starting another from a second terminal closes",
         " this one first; starting it inside this shell asks you to 'exit' first.",
         "Label is free text: recon, web, sqli, privesc, lateral, whatever fits."],
        "pentrail capture privesc"),
    "shot": ("Keep a terminal screenshot as evidence, hands-off.",
        "pentrail shot [-l label] <command ...>   |   pentrail shot --last [lines]",
        ["<command>: checks it against the scope, runs it once, saves a PNG (via termshot)",
         " and the text to the current phase's evidence/ folder (<box>_<date>_<label>), logs",
         " it, scrubs your redacted secrets, and reads the output like a capture does, with",
         " this command as 'Found by'. Flags go after the command name (or after --).",
         "--last: while a capture is recording, screenshot the output since your previous",
         " --last (or the last N lines). This is how you snapshot a task you just ran",
         " interactively, without re-running it. It needs a capture, because a tool cannot",
         " read your terminal scrollback by itself.",
         "No termshot installed? It still saves text evidence and parses it; set a renderer",
         " with 'pentrail config termshot_cmd <cmd>'."],
        "pentrail shot -l whoami id   ;   (in a capture) pentrail shot --last"),
    "ingest": ("Same parsing as capture, but on a file you already saved.",
        "pentrail ingest <file>",
        ["Reads any tool output (gobuster, ffuf, nmap, enum scripts, ...) and extracts",
         " the same leads, de-duplicated against what you already logged.",
         "Outcome: new attack vectors / creds / hostnames, or 'nothing new'."],
        "pentrail ingest scans/gobuster_80.txt"),
    "vectors": ("Review your attack vectors (the ways in you are tracking), by type.",
        "pentrail vectors [type]",
        ["Lists vectors sorted working > open > done > dead, each with its id, status and",
         " type. Pass a type to filter, e.g. 'pentrail vectors web' or 'vectors privesc'.",
         "Vectors are filled in automatically by capture/ingest and auto-tagged by type;",
         " add your own with 'vector add'."],
        "pentrail vectors sqli"),
    "vector": ("Add a way in by hand, change its status, or remove it.",
        'pentrail vector add "<desc>" [-t <type>]  |  vector <status> <id>  |  vector rm <id>',
        ["add: creates a vector (auto-numbered id) with an optional type. Types are free",
         " text; common ones: web sqli lfi rce upload cred smb kernel privesc lateral.",
         "status (open|working|dead|done) is the verb, like 'host own': vector working 3.",
         "rm: delete a wrong or mis-tagged vector by id.",
         "Outcome: the vector shows up in 'pentrail vectors' and the change is logged."],
        'pentrail vector add "SQLi in login.php?id=" -t sqli   ;   pentrail vector working 3'),
    "doctor": ("Check your environment so nothing fails later for a missing tool.",
        "pentrail doctor",
        ["Lists core tools (openvpn, ip, ping, script), the screenshot renderer, and the",
         " enumeration tools 'next' suggests, each marked ok or missing with an apt hint.",
         "Then it checks your config paths, how many .ovpn files are in vpn_dir, whether",
         " the wordlist exists, and whether web_tool is installed.",
         "Nothing is changed; it only reports. Run it once after installing pentrail."],
        "pentrail doctor"),
    "setup": ("Get from a fresh Kali to a ready pentrail in one guided command.",
        "pentrail setup [--yes] [--core-only] [--vpn-dir PATH] [--no-tools|--no-launcher|--no-shell] [--dry-run]",
        ["Walks four steps and explains each as it goes, asking before every change",
         " (sudo only for the install and apt steps):",
         " 1. install this script to /usr/local/bin/pentrail so 'pentrail' works anywhere;",
         " 2. install missing tools with apt - core (openvpn, iproute2, ping, script) and,",
         "    unless --core-only, the enumeration set (nmap, ffuf, smbclient, hydra, ...);",
         " 3. set vpn_dir, create base_dir/vpn_dir, and - if the configured wordlist is",
         "    missing - find the directory wordlists on this machine and let you pick one;",
         " 4. add the pcd() helper to your shell rc (idempotent).",
         "It also explains how the VPN works (a persistent root daemon, no separate",
         " terminal needed). --yes runs it unattended; --dry-run shows the steps and",
         " changes nothing. termshot is not on apt, so it is only pointed to, not installed."],
        "pentrail setup   ;   pentrail setup --yes --vpn-dir ~/vpn"),
    "update": ("Pull the latest pentrail and make it the version that runs.",
        "pentrail update [--branch NAME] [--no-install] [--yes] [--dry-run]",
        ["Finds the source checkout (the repo you run it from, or the one setup recorded",
         " in config as src_repo), runs 'git pull --ff-only' on the current branch, and",
         " reinstalls pentrail.py to /usr/local/bin/pentrail so the new code is live.",
         "--branch pulls and switches to another branch first (e.g. main after a merge);",
         " --no-install pulls only; --yes answers every prompt; --dry-run changes nothing.",
         "A diverged branch stops it (nothing is reinstalled) so your local work is safe;",
         " network errors on the pull are retried with backoff."],
        "pentrail update   ;   pentrail update --branch main --yes"),
    "uninstall": ("Undo 'pentrail setup' - remove what it installed, keep your work.",
        "pentrail uninstall [--config] [--yes] [--dry-run]",
        ["Removes the /usr/local/bin/pentrail launcher (sudo) and the pcd() helper from",
         " your shell rc. If the VPN is still connected it offers to stop it first, since",
         " the root daemon would otherwise be left with no 'pentrail down' to stop it.",
         "--config also deletes your config and VPN state (~/.config/pentrail and",
         " ~/.local/state/pentrail, including the redact list). Your pentest projects in",
         " base_dir are NEVER deleted - remove them yourself if you want them gone.",
         "--yes answers every prompt; --dry-run shows the steps and changes nothing."],
        "pentrail uninstall   ;   pentrail uninstall --config --yes"),
    "report": ("Compile the whole project into one Markdown report.",
        "pentrail report [--mask]",
        ["Writes report/report.md from the current state: a meta block (target, domain,",
         " facts), a hosts table, attack vectors grouped by status, a credentials table,",
         " flags, the full timeline and a list of evidence files. Re-run any time; it",
         " overwrites the file.",
         "--mask hides credential secrets (shows [hidden]) so you can share the report."],
        "pentrail report   ;   pentrail report --mask"),
    "flag": ("Record a captured flag (HTB user.txt / root.txt and the like).",
        "pentrail flag <name> <value>     |     pentrail flag",
        ["Stores the flag against the active box. A name of user/root/system/admin also",
         " marks that box as owned. With no value it lists the flags you have.",
         "Outcome: a logbook 'flag' entry and, for user/root, an OWNED host."],
        "pentrail flag root 8f3b...e21"),
    "creds": ("Keep credentials structured so you can spray, brute-force and crack.",
        "pentrail creds   |   creds users|passwords|hashes   |   creds export [dir]",
        ["No args: list them, each shown as its kind (username/password/hash/ntlm).",
         "users/passwords/hashes: print just those values, one per line, to pipe to a",
         " file. export: write users.txt, passwords.txt and hashes.txt (default into",
         " loot/) and print ready netexec/hydra/hashcat commands for the active target.",
         "Creds come from capture/ingest (incl. secretsdump user:rid:lm:nt) or 'cred add'."],
        "pentrail creds export   ;   pentrail creds hashes > nt.txt"),
    "cred": ("Store one credential by hand.",
        "pentrail cred add <user>:<secret> [host]   (or just a <hash>)",
        ["Splits on the first ':'. A 32-hex secret is tagged ntlm, a long hex or $-string",
         " a hash, otherwise a password; a lone value with no ':' is stored as a secret.",
         "Outcome: it joins 'pentrail creds' and the export lists."],
        "pentrail cred add svc_sql:Summer2024   ;   pentrail cred add 31d6cfe0...089c0"),
    "next": ("Decide what to enumerate next and see what you already did.",
        "pentrail next",
        ["Reads new files in 1-enum/scans/ and uses the ports pentrail knows for the active",
         " box; per open service it lists the standard enumeration steps with the host",
         " filled in, ticked [x] once a recorded command ran that step against that host.",
         " The same checklist is in 1-enum/enum.md. The web brute-force step uses your configured",
         " tool and wordlist: 'pentrail config web_tool feroxbuster|ffuf|gobuster' and",
         " 'pentrail config wordlist <path>' (default a SecLists directory list).",
         "Outcome: a per-service checklist and a call-out of untouched services."],
        "pentrail next"),
    "config": ("Show or change settings.",
        "pentrail config [key] [value]",
        ["No args prints all; a key prints its value; key + value sets it. Keys include",
         " base_dir, vpn_dir, default_vpn, web_tool, wordlist, termshot_cmd,",
         " connect_timeout, stale_minutes, vpn_iface."],
        "pentrail config web_tool ffuf   ;   pentrail config wordlist ~/lists/common.txt"),
    "set": ("Keep project facts you reach for often.",
        "pentrail set <key> <value>   |   pentrail set",
        ["Stores a key/value on the project: domain, dc-ip, base-dn, url, anything. No",
         " args lists them; a key alone prints its value. The domain is also detected",
         " automatically from nmap/ldap/smb output during capture/ingest.",
         "Facts show up in 'pentrail status' and on the home screen."],
        "pentrail set domain blackfield.local"),
    "focus": ("Note what you are working on right now.",
        "pentrail focus <text>   |   pentrail focus",
        ["Records a one-line current focus, shown on the home screen and in status, so",
         " after a break you see what you were in the middle of. No text shows it.",
         "Outcome: a 'focus' logbook entry and the line on your home screen."],
        'pentrail focus "LDAP enum for usernames"'),
    "redact": ("Stop your OWN credentials ever being captured.",
        "pentrail redact add <value...>   |   pentrail redact list   |   pentrail redact clear",
        ["Register the secrets you log in to tools with (your vault password, API tokens,",
         " your own usernames). pentrail stores only their SHA-256, so the values are",
         " never written anywhere, and scrubs them to [REDACTED] in every capture/ingest",
         " and in the saved evidence file, so they are never parsed or logged as creds.",
         "Note: passwords typed at a real prompt (ssh/sudo) are not captured anyway; this",
         " covers command-line creds and pasted tokens. It matches delimiter-separated",
         " occurrences, so prefer '-p Secret' over the glued '-pSecret'. It is global",
         " (applies to every project) and needs no active engagement."],
        "pentrail redact add 'MyVaultPass!' hunter2 my.ops.username"),
    "pivot": ("Record lateral movement from one host to another.",
        "pentrail pivot <from> <to> [--via note]",
        ["Logs that you moved from one host to another; adds the destination as a tracked",
         " host if it is new. --via records how (reused creds, pass-the-hash, SSH key).",
         "Outcome: a 'pivot' logbook line and the movement chain in 'pentrail map'."],
        'pentrail pivot 10.10.10.5 10.10.10.7 --via "reused SSH key"'),
    "resolve": ("Add target hostnames to /etc/hosts (needs sudo for that one write).",
        "pentrail resolve [ip] <name...>   |   pentrail resolve --clean",
        ["ip defaults to the current target. On a box reset with a new IP, re-running",
         " replaces pentrail's own old line; it never touches entries you added yourself.",
         "--clean removes every line pentrail added."],
        "pentrail resolve dc01.htb blackfield.htb"),
}

def print_command_detail(name):
    e = DETAILS.get(name)
    if not e:
        return False
    what, usage, body, example = e
    print(f"{B}pentrail {name}{N} - {what}\n")
    print(f"{B}Usage{N}  {usage}\n")
    for line in body:
        print(f"  {line}")
    print(f"\n{B}Example{N}")
    print(f"  {DIM}${N} {example}")
    return True


def print_home(_args=None):
    print_banner()
    print(f"\n{DIM}For authorized labs, engagements and bug bounty programs only.{N}\n")
    d = current_dir()
    if d:
        vpn = f"{G}up{N}" if vpn_running() else f"{R}down{N}"
        print(f"Active project: {B}{d.name}{N}   VPN: {vpn}")
        project_summary(d, loglines=3)
        print(f"\n{B}Carry on{N}")
        _cmd("pentrail capture <phase>", "record a shell; scope-checked, auto-documented")
        _cmd("pentrail next", "what to enumerate next")
        _cmd("pentrail hosts", "hosts, ports and what you found")
        _cmd("pentrail finding <vector-id>", "a confirmed lead becomes a finding")
        _cmd("pentrail report --html", "the report, filled from your docs")
    else:
        print("No active project.\n")
        print(f"{B}Get started{N}")
        _cmd("pentrail setup", "install pentrail + missing tools, set vpn_dir")
        _cmd("pentrail new <name> <target>", "new project: phases, docs, scope, VPN")
        _cmd("pentrail resume", "resume the project you last worked on")
        _cmd("pentrail list", "list existing projects")
        projs = [x.name for x in _projects()]
        if projs:
            print(f"\n{DIM}Projects: {', '.join(projs[:12])}{N}")
    print(f"\n{B}A box from start to report{N}")
    for i, step in enumerate(FLOW, 1):
        print(f"  {DIM}{i}.{N} {step}")
    print(f"\nAll commands: {G}pentrail help{N}   one command: {G}pentrail help <command>{N}")

def print_help_guide(_args=None):
    print(f"{B}pentrail{N} - the pentest logbook (for authorized labs, engagements and bug bounties)\n")
    print("Usage: pentrail <command> [args]")
    print(f"       {DIM}pentrail help <command>   full explanation + example for one command{N}\n")
    for title, rows in HELP_SECTIONS:
        print(f"{B}{title}{N}")
        for row in rows:
            cmd, first, *more = row
            if len(cmd) <= 30:
                print(f"  {G}{cmd:<30}{N}{first}")
            else:
                print(f"  {G}{cmd}{N}")
                print(f"  {'':<30}{first}")
            for extra in more:
                print(f"  {'':<30}{extra}")
        print()
    print(f"{B}Typical flow{N}")
    for line in FLOW:
        print(f"  {DIM}${N} {line}")
    print(f"\nConfig lives in {CONFIG_FILE}")

DETAILS.update({
    "note": ("Jot something down about a target while you work.",
        "pentrail note [-t <host>|none] <text>",
        ["Adds note N<n> to the active box (-t another host, -t none for the project), in",
         " the phase you are in. Inside a capture it also remembers the command you ran last.",
         "It appears in notes.md (grouped by host, with 'mentioned in' backlinks) and in the",
         " host's 'Logged notes' in 1-enum/enum.md. Hosts (IP, name, alias), leads (#3),",
         " findings (F01) and other notes (N2) you mention become links. It is also a line",
         " in the logbook. Change or remove one with 'pentrail notes edit|rm <N>'."],
        'pentrail note "login on :8080 looks default, try on 10.10.10.6 - see #3"'),
    "notes": ("Read back your notes, for everything or for one host.",
        "pentrail notes [host]   |   notes edit <N> \"<text>\"   |   notes rm <N>",
        ["No args: every note. A host: its own notes plus the notes that mention it.",
         "edit replaces a note's text; rm removes it (its number is never reused, so links",
         " in other notes do not end up pointing at a different note)."],
        "pentrail notes 10.10.10.6   ;   pentrail notes edit 4 \"creds work on SMB too\""),
    "new": ("Start a project: one folder per phase, working docs, scope and the VPN.",
        "pentrail new <name> [target ...] [--no-vpn]",
        ["Creates ~/pentests/<name>/ with 0-scope ... 5-report folders, a Markdown doc per",
         " phase, a logbook, and makes it the active project. Targets (IPs, ranges, domains,",
         " *.domain or URLs) go into 0-scope/scope.md as in scope; the first host becomes",
         " the active box. The VPN is connected unless you pass --no-vpn or have no .ovpn.",
         "Outcome: a ready workspace; 'source .env' gives you $TARGET and $VPN_IP."],
        "pentrail new blackfield 10.10.10.192   ;   pentrail new acme '*.acme.com' --no-vpn"),
    "capture": ("Record the shell you work in; document everything it finds.",
        "pentrail capture [phase|label] [--warn | --guard strict|warn|off] [--plain]",
        ["Starts a recording shell (bash or zsh) in the phase you name (recon/enum, foothold,",
         " privesc, lateral, ...); the recording and shots go to that phase's evidence/.",
         "Each command is recorded with its time, folder and exit code, with variables like",
         " $TARGET filled in. Before a command runs, every host in it is checked against",
         " 0-scope/scope.md: outside scope it is stopped (scope-ok <command> runs it once,",
         " logged). After each command its output is read: ports with versions, web paths,",
         " hostnames, leads; each is kept with the command that found it and written to the",
         " docs right away, so you can look things up instead of running them again.",
         "Only in-scope results are logged. pentrail's own output is never re-read.",
         "--warn (or --guard strict|warn|off) sets the guard for this capture only: warn",
         " reports out-of-scope commands and logs them, but lets them run. Typing",
         " 'pentrail scope guard strict|warn|off' inside the capture switches it right away.",
         "--plain records without the hook (no guard, the recording is split at prompts)."],
        "pentrail capture recon   ;   pentrail capture privesc --warn"),
    "scope": ("Say what you may test; the capture shell enforces it.",
        "pentrail scope [add|out|check|guard] ...",
        ["The scope is 0-scope/scope.md: edit it or paste a program's scope under '## In",
         " scope' and '## Out of scope', one asset per line. Assets: 10.10.10.5,",
         " 10.10.10.0/24, 10.10.10.1-50, app.example.com, *.example.com, or a URL.",
         "add / out append to those sections; check tells you whether a host, URL or whole",
         " command line is in scope; guard sets strict (stop), warn (report and log, let it",
         " run) or off. Run outside a capture, guard changes the setting; run inside one, it",
         " changes only that capture, at once. 'capture --warn' starts a capture in warn mode.",
         "Names and DNS: a hostname whose addresses all fall inside your in-scope IPs or",
         " ranges counts as in scope; captures look new names up in DNS and 'scope resolve'",
         " looks up all of them. They are listed under 'Resolved into the scope' in scope.md.",
         "Conflicts are listed there too, and the guard stops them: an out-of-scope name that",
         " resolves into an in-scope range (that IP becomes a conflict; settle it by listing",
         " the IP under In or Out of scope, or leave it out with --exclude), an in-scope name",
         " that resolves to an out-of-scope address, a name only partly inside the scope,",
         " and entries that are both in and out. Out of scope always wins."],
        "pentrail scope add '*.example.com'   ;   pentrail scope check curl https://blog.example.com"),
    "phase": ("Show or set the methodology phase you are in.",
        "pentrail phase [scope|enum|foothold|privesc|lateral|report]",
        ["The phase decides where captures and shots go (its folder's evidence/) and which",
         " doc lists the commands. 'pentrail capture <phase>' sets it too."],
        "pentrail phase foothold"),
    "finding": ("Write up a vulnerability: one file per finding, reused by the report.",
        "pentrail finding [<vector-id> | \"<title>\" | F01] [-s severity]",
        ["No args lists findings by severity. A vector id creates 5-report/findings/F01-....md",
         " prefilled with severity, weakness, asset, the command that found it, the output",
         " and the evidence file; a title creates an empty one. F01 prints it clean, ready to",
         " paste into a bug bounty platform. Fill in Summary, Impact and Remediation."],
        "pentrail finding 3   ;   pentrail finding \"Exposed .git directory\" -s low"),
    "report": ("Fill the report template from everything you recorded, and export it.",
        "pentrail report [--mask] [--html] [--pdf]",
        ["5-report/report.md has your sections (executive summary, conclusion) and auto blocks",
         " pentrail fills: project details, scope and rules, findings overview by severity,",
         " the findings themselves, a walkthrough from your phase docs, and an appendix with",
         " hosts and ports, names, credentials, commands, evidence and the timeline.",
         "--mask hides secrets; --html writes a styled report.html (print it to PDF);",
         " --pdf also converts it with chromium, wkhtmltopdf or pandoc when installed."],
        "pentrail report --html   ;   pentrail report --mask --pdf"),
    "docs": ("Find the working docs and refresh their auto blocks.",
        "pentrail docs",
        ["Lists each phase doc and creates any that are missing (older projects get them",
         " too). Auto blocks sit between 'pentrail:auto' and 'pentrail:end' markers; write",
         " anywhere else in the files and pentrail leaves it alone."],
        "pentrail docs"),
    "hosts": ("See what you know about the hosts, without running anything again.",
        "pentrail hosts [ip|name]",
        ["No args: every host with OS, owned flag and open ports, plus the movement chain.",
         "With a host: its ports with versions and the command that found each, web paths,",
         " hostnames and leads."],
        "pentrail hosts 10.10.10.5"),
    "names": ("Hostnames, vhosts and subdomains seen in scope.",
        "pentrail names [--plain]",
        ["Each with its IP when known and the command that found it. --plain prints one per",
         " line, to feed other tools."],
        "pentrail names --plain > 1-enum/names.txt"),
})

# ----------------------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(prog="pentrail", description="the pentest logbook (authorized work only)")
    p.add_argument("--version", "-V", action="version", version=f"pentrail {VERSION}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the version").set_defaults(
        func=lambda a: print(f"pentrail {VERSION}"))

    s = sub.add_parser("new", help="start a project: phase folders, docs, scope, VPN")
    s.add_argument("name"); s.add_argument("targets", nargs="*")
    s.add_argument("--no-vpn", action="store_true", help="do not start the VPN")
    s.set_defaults(func=cmd_new)
    s = sub.add_parser("use", help="switch to an existing project (no VPN)")
    s.add_argument("name"); s.set_defaults(func=cmd_use)
    s = sub.add_parser("resume", help="come back: switch, reconnect VPN, show where you left off")
    s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_resume)
    sub.add_parser("list", aliases=["ls"], help="list projects").set_defaults(func=cmd_list)
    s = sub.add_parser("target", help="set the active box: target <ip|name>")
    s.add_argument("ip"); s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_target)
    s = sub.add_parser("phase", help="show or set the methodology phase")
    s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_phase)
    sub.add_parser("docs", help="list the working docs and refresh them").set_defaults(func=cmd_docs)
    s = sub.add_parser("scope", help="scope: show | add | out | check | guard")
    s.add_argument("action", nargs="?"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_scope)

    s = sub.add_parser("up", aliases=["connect"], help="connect the VPN")
    s.add_argument("file", nargs="?"); s.set_defaults(func=lambda a: vpn_up(a.file))
    sub.add_parser("down", aliases=["stop"], help="disconnect").set_defaults(func=lambda a: vpn_down())
    s = sub.add_parser("restart", help="reconnect the VPN")
    s.add_argument("file", nargs="?"); s.set_defaults(func=lambda a: vpn_restart(a.file))
    sub.add_parser("status", aliases=["st"], help="VPN + project status").set_defaults(func=lambda a: vpn_status())
    s = sub.add_parser("check", aliases=["diag"], help="diagnose the connection")
    s.add_argument("ip", nargs="?"); s.set_defaults(func=cmd_check)
    s = sub.add_parser("watch", help="monitor VPN, auto-restart when it hangs")
    s.add_argument("interval", nargs="?", type=int, default=30); s.set_defaults(func=cmd_watch)

    s = sub.add_parser("log", help="show the logbook")
    s.add_argument("n", nargs="?", type=int); s.set_defaults(func=cmd_log)
    s = sub.add_parser("note", help="a quick note on the active box (-t <host> for another)")
    s.add_argument("-t", "--target", help="the host it is about (default: the active box; 'none' = project)")
    s.add_argument("text", nargs="+"); s.set_defaults(func=cmd_note)
    s = sub.add_parser("notes", help="list notes [host] | rm <N> | edit <N> \"<text>\"")
    s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_notes)
    s = sub.add_parser("capture", help="record the shell: scope guard, per-command docs")
    s.add_argument("label", nargs="?")
    s.add_argument("--plain", action="store_true", help="record without the shell hook")
    s.add_argument("--guard", choices=GUARD_MODES, help="scope guard for this capture only")
    s.add_argument("--warn", dest="guard", action="store_const", const="warn",
                   help="this capture only reports out-of-scope commands (same as --guard warn)")
    s.set_defaults(func=cmd_capture)
    s = sub.add_parser("shot", help="screenshot a command (shot <cmd>) or recent capture output (shot --last)")
    s.add_argument("-l", "--label")
    s.add_argument("--last", nargs="?", const=0, type=int,
                   help="screenshot the active capture's recent output (optionally last N lines)")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_shot)
    s = sub.add_parser("ingest", help="read a saved tool output file")
    s.add_argument("file"); s.set_defaults(func=cmd_ingest)
    sub.add_parser("next", aliases=["suggest"],
                   help="what to enumerate next on the active box").set_defaults(func=cmd_next)

    s = sub.add_parser("vector", aliases=["vectors"], help='leads: list | add "<desc>" [-t type] | <status> <id> | rm <id>')
    s.add_argument("action", nargs="?"); s.add_argument("rest", nargs="*")
    s.add_argument("-t", "--type", help="category, e.g. web/sqli/rce/privesc/lateral (any string)")
    s.set_defaults(func=cmd_vector)
    s = sub.add_parser("cred", aliases=["creds"], help="credentials: list | add <user:secret> | rm <n> | users | passwords | hashes | export")
    s.add_argument("action", nargs="?"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_cred)
    s = sub.add_parser("finding", aliases=["findings"], help="findings: list | <vector-id> | \"<title>\" | F01")
    s.add_argument("rest", nargs="*"); s.add_argument("-s", "--severity")
    s.set_defaults(func=cmd_finding)
    s = sub.add_parser("flag", help="record/list a flag: flag user <value> | flag (list)")
    s.add_argument("name", nargs="?", default=""); s.add_argument("value", nargs="*"); s.set_defaults(func=cmd_flag)
    s = sub.add_parser("set", help="project facts: set <key> <value> | set (list)")
    s.add_argument("key", nargs="?"); s.add_argument("value", nargs="*"); s.set_defaults(func=cmd_set)
    s = sub.add_parser("focus", help="what you are working on now")
    s.add_argument("text", nargs="*"); s.set_defaults(func=cmd_focus)
    s = sub.add_parser("redact", help="your own secrets to never capture: redact add <value...> | list | clear")
    s.add_argument("action"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_redact)

    s = sub.add_parser("hosts", aliases=["map"], help="hosts with ports; one host in detail")
    s.add_argument("ip", nargs="?"); s.set_defaults(func=cmd_hosts)
    s = sub.add_parser("host", help="host add <ip> [name] [os] | own <ip> | rm <ip> | <ip>")
    s.add_argument("action"); s.add_argument("ip", nargs="?")
    s.add_argument("name", nargs="?"); s.add_argument("os", nargs="?"); s.set_defaults(func=cmd_host)
    s = sub.add_parser("names", help="hostnames and subdomains seen in scope")
    s.add_argument("--plain", action="store_true", help="one per line"); s.set_defaults(func=cmd_names)
    s = sub.add_parser("pivot", help="log lateral movement: pivot <from> <to> [--via note]")
    s.add_argument("src"); s.add_argument("dst"); s.add_argument("--via", default=""); s.set_defaults(func=cmd_pivot)
    s = sub.add_parser("report", help="fill 5-report/report.md; --html / --pdf to export")
    s.add_argument("--mask", action="store_true", help="hide credential secrets (for sharing)")
    s.add_argument("--html", action="store_true", help="also write a styled report.html")
    s.add_argument("--pdf", action="store_true", help="also write report.pdf (needs chromium, wkhtmltopdf or pandoc)")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("resolve", help="add /etc/hosts entries (resolve --clean to remove)")
    s.add_argument("names", nargs="*"); s.add_argument("--clean", action="store_true",
                   help="remove the /etc/hosts lines pentrail added"); s.set_defaults(func=cmd_resolve)
    sub.add_parser("dir", help="print the current project path").set_defaults(
        func=lambda a: print(require_engagement()))
    s = sub.add_parser("config", help="view or set config")
    s.add_argument("key", nargs="?"); s.add_argument("value", nargs="?"); s.set_defaults(func=cmd_config)
    sub.add_parser("doctor", help="check your environment: installed tools, paths, wordlist").set_defaults(func=cmd_doctor)
    s = sub.add_parser("setup", help="guided install: PATH launcher, missing tools, vpn_dir, shell helper")
    s.add_argument("--vpn-dir", help="set vpn_dir (where your .ovpn files live)")
    s.add_argument("--core-only", action="store_true", help="only core tools, skip the enumeration set")
    s.add_argument("--no-tools", action="store_true", help="do not install any tools")
    s.add_argument("--no-launcher", action="store_true", help="do not install pentrail to /usr/local/bin")
    s.add_argument("--no-shell", action="store_true", help="do not touch your shell rc")
    s.add_argument("-y", "--yes", action="store_true", help="assume yes (non-interactive)")
    s.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    s.set_defaults(func=cmd_setup)
    s = sub.add_parser("update", aliases=["upgrade"],
                       help="update pentrail: git pull the source repo and reinstall the launcher")
    s.add_argument("--branch", help="pull a specific branch (default: the checked-out one)")
    s.add_argument("--no-install", action="store_true", help="pull only, do not reinstall to /usr/local/bin")
    s.add_argument("-y", "--yes", action="store_true", help="assume yes (non-interactive)")
    s.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    s.set_defaults(func=cmd_update)
    s = sub.add_parser("uninstall", help="undo setup: remove the launcher + shell helper (--config also removes settings)")
    s.add_argument("--config", action="store_true", help="also remove config + VPN state (projects are kept)")
    s.add_argument("-y", "--yes", action="store_true", help="assume yes (non-interactive)")
    s.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    s.set_defaults(func=cmd_uninstall)
    s = sub.add_parser("help", help="full usage guide (or: pentrail help <command>)")
    s.add_argument("topic", nargs="?"); s.set_defaults(func=None)
    return p

HELP_ALIASES = {"vectors": "vector", "creds": "cred", "findings": "finding", "map": "hosts",
                "ls": "list", "connect": "up", "stop": "down", "st": "status", "diag": "check",
                "suggest": "next", "upgrade": "update"}

def _dispatch(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "help":
        if args.topic:
            topic = HELP_ALIASES.get(args.topic, args.topic)
            if print_command_detail(topic) or print_command_detail(args.topic):
                return
            parser.parse_args([args.topic, "-h"])   # fall back to argparse help and exit
        print_help_guide(); return
    if not getattr(args, "func", None):
        print_home(); return      # bare 'pentrail' = banner + orientation
    args.func(args)

def main():
    if sys.version_info < (3, 8):
        sys.exit("pentrail needs Python 3.8 or newer (found "
                 f"{sys.version_info.major}.{sys.version_info.minor}).")
    if len(sys.argv) > 1 and sys.argv[1] == "_hook":       # called by the capture shell
        try:
            sys.exit(hook_main(sys.argv[2:]))
        except KeyboardInterrupt:
            sys.exit(0)
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    warn_if_root()
    # Running inside a capture: bracket our own terminal output with an invisible
    # sentinel (ESC _ ... ESC \) so the capture parser drops it and never re-ingests
    # what you view with pentrail (e.g. 'pentrail log'). Only when stdout is the tty
    # that 'script' records - not when output is piped to a file.
    inside = bool(os.environ.get("PENTRAIL_CAPTURE"))
    wrap = inside and sys.stdout.isatty()
    if wrap:
        try:
            sys.stdout.write(CAP_BEGIN); sys.stdout.flush()
        except OSError:
            wrap = False
    try:
        if inside:
            capture_catchup(quiet=True)       # so lookups include what you just ran
        _dispatch()
    finally:
        if wrap:
            try:
                sys.stdout.write(CAP_END); sys.stdout.flush()
            except OSError:
                pass

if __name__ == "__main__":
    main()
