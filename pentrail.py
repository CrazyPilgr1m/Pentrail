#!/usr/bin/env python3
"""pentrail - the pentest logbook.

Starts an engagement (VPN + evidence folders), then keeps a running, timestamped
logbook for you: folders, scans, notes, discovered attack vectors, hosts you reach
and lateral movement between them. `pentrail capture` records the shell you work in
and parses the output with built-in rules, turning gobuster/nmap hits into logged
attack vectors automatically. For labs and engagements you are authorized to test
(HTB, OffSec, a scoped client engagement).

Pure Python 3, standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

VERSION = "1.0"
SCHEMA = 1                      # state.json layout version, for future migrations
HOME = Path.home()
CONFIG_FILE = Path(os.environ.get("PENTRAIL_CONFIG", HOME / ".config" / "pentrail" / "config.json"))
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local" / "state")) / "pentrail"
PID_FILE = STATE_DIR / "openvpn.pid"
LOG_FILE = STATE_DIR / "openvpn.log"
LAST_VPN_FILE = STATE_DIR / "last_vpn"
CURRENT_FILE = STATE_DIR / "current"
CAPTURE_MARKER = STATE_DIR / "capture.json"
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
}

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

# ----------------------------------------------------------------------------- config / state
def load_config():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text()))
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

# ----------------------------------------------------------------------------- engagement state
def current_dir():
    d = _read(CURRENT_FILE)
    return Path(d) if d and Path(d).is_dir() else None

def require_engagement():
    d = current_dir()
    if not d:
        die("No active engagement - run 'pentrail new <name>' first")
    return d

def _atomic_write(path, text):
    """Write via a temp file + os.replace so a crash can't corrupt the target."""
    path = Path(path)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(text)
    os.replace(tmp, path)

def load_state(d):
    st = {"schema": SCHEMA, "target": "", "hosts": [], "vectors": [], "creds": [],
          "hostnames": [], "flags": [], "facts": {}, "focus": ""}
    f = d / "state.json"
    if f.exists():
        try:
            st.update(json.loads(f.read_text()))
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
    return st

def save_state(d, st):
    _atomic_write(d / "state.json", json.dumps(st, indent=2) + "\n")

def write_env(d, target, vip=None):
    if vip is None:
        m = re.search(r'^VPN_IP="?(.*?)"?$', _read(d / ".env"), re.M)
        vip = m.group(1) if m else ""
    (d / ".env").write_text(f'TARGET="{target}"\nVPN_IP="{vip}"\nENG="{d}"\n')

def current_target():
    d = current_dir()
    if not d:
        return ""
    t = load_state(d).get("target")
    if t:
        return t
    m = re.search(r'^TARGET="?(.*?)"?$', _read(d / ".env"), re.M)
    return m.group(1) if m else ""

# ----------------------------------------------------------------------------- logbook
def log_event(kind, text):
    """Append a timestamped, typed line to the engagement logbook."""
    d = current_dir()
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
        # light coloring by kind tag
        m = re.search(r"`(\w+)", l)
        tag = m.group(1) if m else ""
        col = {"vector": C, "own": G, "pivot": Y, "note": B, "scan": C}.get(tag, "")
        print(col + l + N if col else l)

def cmd_note(args):
    require_engagement()
    log_event("note", " ".join(args.text))
    ok("Noted in the logbook")

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
        return str(files[int(input("Pick a VPN file: ")) - 1])
    except (ValueError, IndexError, EOFError):
        die("Invalid choice")

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
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_VPN_FILE.write_text(ovpn)
    PID_FILE.unlink(missing_ok=True)
    LOG_FILE.unlink(missing_ok=True)
    if subprocess.run([*SUDO, "openvpn", "--cd", os.path.dirname(ovpn), "--config", ovpn,
                       "--daemon", "--writepid", str(PID_FILE), "--log", str(LOG_FILE)]).returncode != 0:
        die("openvpn could not start")
    return wait_for_tunnel()

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
            print("    - IP changed after a reset -> pentrail new <name> <new-ip>")
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

# ----------------------------------------------------------------------------- engagement setup
SUBDIRS = ["notes", "scans", "loot", "files", "report",
           "evidence/screenshots", "evidence/terminal", "evidence/output"]
NOTES_TEMPLATE = """# {name}

| | |
|---|---|
| Start | {when} |
| Target | {target} |
| My VPN IP | {vip} |
| VPN config | {vpn} |

## Scope

## Findings

## Credentials

## Evidence / flags

See `logbook.md` for the running timeline and `pentrail vectors` for attack vectors.
"""

def cmd_new(args):
    name = args.name
    if not re.match(r"^[A-Za-z0-9._-]+$", name):
        die("Name may only contain letters, digits and . _ -")
    target = args.ip or ""
    if target and not IP_RE.match(target):
        die(f"Not a valid IPv4 address: {target}")
    d = Path(CFG["base_dir"]) / name
    if d.is_dir():
        info(f"Folder exists, reusing: {d}")
    for sub in SUBDIRS:
        (d / sub).mkdir(parents=True, exist_ok=True)
    try:                       # loot/ and state.json hold creds: keep it private
        os.chmod(d, 0o700)
    except OSError:
        pass
    CURRENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_FILE.write_text(str(d))

    if not vpn_running() and not vpn_up():
        warn("VPN not connected - see above, or use 'pentrail check' and 'pentrail restart'")
    vip = tun_ip()

    st = load_state(d)
    if not target:
        target = st.get("target", "")
    st["target"] = target
    if target and not any(h["ip"] == target for h in st["hosts"]):
        st["hosts"].append({"ip": target, "name": name, "os": "", "owned": False,
                            "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
    save_state(d, st)
    write_env(d, target, vip)

    notes = d / "notes" / "notes.md"
    if not notes.exists():
        notes.write_text(NOTES_TEMPLATE.format(
            name=name, when=f"{datetime.now():%Y-%m-%d %H:%M}", target=target or "?",
            vip=vip or "?", vpn=os.path.basename(_read(LAST_VPN_FILE)) or "?"))
    log_event("new", f"session started - target {target or '?'}, VPN IP {vip or '?'}")

    if target and vip:
        ok(f"Target {target} reachable") if ping(target, count=2, wait=2) else \
            warn(f"Target {target} not responding to ping (yet) - 'pentrail check' for diagnosis")
    print()
    ok(f"Engagement ready: {d}")
    print(f'    cd "{d}" && source .env')

# ----------------------------------------------------------------------------- switch / list / resume
def resolve_project(name):
    """A project by name under base_dir, or a path to a project folder."""
    p = Path(os.path.expanduser(name))
    if p.is_dir() and ((p / "state.json").exists() or (p / "logbook.md").exists()):
        return p
    d = Path(CFG["base_dir"]) / name
    return d if d.is_dir() else None

def latest_project():
    base = Path(CFG["base_dir"])
    if not base.is_dir():
        return None
    projs = [d for d in base.iterdir() if (d / "state.json").exists() or (d / "logbook.md").exists()]
    def mtime(d):
        f = d / "logbook.md"
        return f.stat().st_mtime if f.exists() else d.stat().st_mtime
    return max(projs, key=mtime, default=None)

def project_summary(d, loglines=6):
    st = load_state(d)
    owned = sum(1 for h in st["hosts"] if h["owned"])
    openp = [p for p in st["vectors"] if p["status"] in ("open", "working")]
    dom = st.get("facts", {}).get("domain")
    info(f"Project {B}{d.name}{N}   target: {st.get('target') or '-'}" + (f"   domain: {dom}" if dom else ""))
    if st.get("focus"):
        print(f"    focus : {Y}{st['focus']}{N}")
    if st["hosts"]:
        print(f"    hosts : {len(st['hosts'])} ({owned} owned)")
    print(f"    vectors: {len(openp)} open/working of {len(st['vectors'])}"
          + (f"   creds: {len(_norm_creds(st))}" if st.get("creds") else ""))
    for p in [p for p in st["vectors"] if p["status"] == "working"][:5]:
        print(f"      {C}working{N} #{p['id']} {p['desc']}")
    facts = {k: v for k, v in st.get("facts", {}).items() if k != "domain"}
    if facts:
        print("    facts : " + ", ".join(f"{k}={v}" for k, v in facts.items()))
    lines = [l for l in _read(d / "logbook.md").splitlines() if l.startswith("- ")]
    if lines:
        print("    last activity:")
        for l in lines[-loglines:]:
            print(f"      {DIM}{l[2:]}{N}")

def cmd_use(args):
    d = resolve_project(args.name)
    if not d:
        die(f"No project '{args.name}' in {CFG['base_dir']} - run 'pentrail new {args.name}'")
    CURRENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_FILE.write_text(str(d))
    st = load_state(d)
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
    CURRENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_FILE.write_text(str(d))
    ok(f"Resumed {d.name}")
    log_event("resume", "session resumed")
    if vpn_running():
        ok(f"VPN already up ({iface()}: {tun_ip()})")
    else:
        info("Reconnecting VPN ...")
        vpn_up()
    print()
    project_summary(d)
    print(f'\n    cd "{d}" && source .env')

def cmd_list(args):
    base = Path(CFG["base_dir"])
    if not base.is_dir():
        info("No engagements yet - 'pentrail new <name>'"); return
    cur = current_dir()
    rows = 0
    for d in sorted(base.iterdir()):
        if not (d / "state.json").exists() and not (d / "logbook.md").exists():
            continue
        st = load_state(d)
        mark = f"{G}*{N}" if cur and d == cur else " "
        owned = sum(1 for h in st["hosts"] if h["owned"])
        openp = sum(1 for p in st["vectors"] if p["status"] in ("open", "working"))
        print(f" {mark} {d.name:<18} target {st.get('target') or '-':<15} "
              f"{len(st['hosts'])} host(s), {owned} owned, {openp} open vector(s)")
        rows += 1
    if rows == 0:
        info("No engagements yet - 'pentrail new <name>'")

# ----------------------------------------------------------------------------- hosts & lateral movement
def _find_host(st, ip):
    return next((h for h in st["hosts"] if h["ip"] == ip or h["name"] == ip), None)

def cmd_target(args):
    d = require_engagement()
    st = load_state(d)
    h = _find_host(st, args.ip)
    if h:
        ip = h["ip"]
    elif IP_RE.match(args.ip):
        ip = args.ip
        st["hosts"].append({"ip": ip, "name": args.name or "", "os": "", "owned": False,
                            "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
    else:
        die(f"Give an IP, or the name of a known host (see 'pentrail hosts'). Unknown: {args.ip}")
    st["target"] = ip
    save_state(d, st)
    write_env(d, ip)
    log_event("target", f"active box -> {ip}")
    ok(f"Active box: {ip}  (re-run 'source .env' in open shells)")

def cmd_hosts(args):
    d = require_engagement()
    st = load_state(d)
    if not st["hosts"]:
        info("No hosts yet - 'pentrail host add <ip> [name]'"); return
    for h in st["hosts"]:
        flag = f"{G}OWNED{N}" if h["owned"] else f"{DIM}-{N}"
        tgt = "  <- target" if h["ip"] == st.get("target") else ""
        print(f"  {h['ip']:<15} {h.get('name',''):<14} {h.get('os',''):<10} [{flag}]{tgt}")

def cmd_host(args):
    d = require_engagement()
    st = load_state(d)
    action = args.action
    if action == "add":
        if not args.ip:
            die("Usage: pentrail host add <ip> [name] [os]")
        if _find_host(st, args.ip):
            info(f"Host {args.ip} already tracked")
        else:
            st["hosts"].append({"ip": args.ip, "name": args.name or "", "os": args.os or "",
                                "owned": False, "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
            log_event("host", f"added {args.ip} {args.name or ''}".strip())
            ok(f"Host {args.ip} added")
    elif action == "own":
        h = _find_host(st, args.ip) if args.ip else None
        if not h:
            if args.ip:
                h = {"ip": args.ip, "name": args.name or "", "os": "", "owned": False,
                     "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"}
                st["hosts"].append(h)
            else:
                die("Usage: pentrail host own <ip>")
        h["owned"] = True
        log_event("own", f"foothold / compromised {h['ip']} {h.get('name','')}".strip())
        ok(f"Marked {h['ip']} as owned")
    elif action in ("rm", "del", "remove"):
        h = _find_host(st, args.ip) if args.ip else None
        if not h:
            die("Usage: pentrail host rm <ip|name>")
        st["hosts"] = [x for x in st["hosts"] if x is not h]
        log_event("host", f"removed {h['ip']} {h.get('name','')}".strip())
        ok(f"Removed host {h['ip']}")
    else:
        die("Usage: pentrail host add|own|rm <ip> [name]")
    save_state(d, st)

def cmd_pivot(args):
    d = require_engagement()
    st = load_state(d)
    src, dst = args.src, args.dst
    if not _find_host(st, dst):
        st["hosts"].append({"ip": dst, "name": "", "os": "", "owned": False,
                            "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
        ok(f"New host {dst} added")
    save_state(d, st)
    log_event("pivot", f"{src} -> {dst}" + (f" ({args.via})" if args.via else ""))
    ok(f"Lateral movement logged: {src} -> {dst}")

def cmd_map(args):
    d = require_engagement()
    st = load_state(d)
    print(f"{B}Hosts{N} ({d.name}):")
    for h in st["hosts"]:
        flag = f"{G}OWNED{N}" if h["owned"] else f"{DIM}not owned{N}"
        print(f"  {h['ip']:<15} {h.get('name',''):<14} [{flag}]")
    pivots = [l for l in _read(d / "logbook.md").splitlines() if "`pivot" in l]
    if pivots:
        print(f"\n{B}Lateral movement{N}:")
        for l in pivots:
            m = re.search(r"`pivot\s*`\s*(.*)$", l)
            ts = l[2:21]
            print(f"  {ts}  {m.group(1) if m else ''}")

# ----------------------------------------------------------------------------- attack vectors
VALID_STATUS = ("open", "working", "dead", "done")
STATUS_COL = {"open": Y, "working": C, "dead": DIM, "done": G}

def _next_pid(st):
    return max((p["id"] for p in st["vectors"]), default=0) + 1

# Suggested vector types; any string is allowed, these are just the common ones.
PATH_TYPES = ["web", "sqli", "lfi", "rfi", "rce", "upload", "xxe", "ssrf", "deserial",
              "cred", "default-cred", "brute", "smb", "snmp", "nfs", "ftp",
              "kernel", "privesc", "suid", "sudo", "cron", "lateral", "misc"]

def add_vector(d, st, desc, host="", status="open", sig=None, ptype="misc"):
    """Add an attack vector if not already present (deduped by signature)."""
    sig = sig or desc
    if any(p.get("sig") == sig for p in st["vectors"]):
        return None
    pid = _next_pid(st)
    st["vectors"].append({"id": pid, "host": host, "desc": desc, "status": status,
                        "type": ptype, "sig": sig, "added": f"{datetime.now():%Y-%m-%d %H:%M:%S}"})
    log_event("vector", f"#{pid} [{ptype}] {desc}" + (f" on {host}" if host else ""))
    return pid

def cmd_vectors(args):
    d = require_engagement()
    st = load_state(d)
    paths = st["vectors"]
    if not paths:
        info("No attack vectors yet. They appear from 'pentrail capture' / 'pentrail ingest', "
             "or add one with 'pentrail vector add \"<desc>\" -t <type>'.")
        return
    want = getattr(args, "type", None)
    if want:
        paths = [p for p in paths if p.get("type", "misc") == want]
        if not paths:
            info(f"No '{want}' attack vectors. Types in use: "
                 + ", ".join(sorted({p.get('type', 'misc') for p in st['vectors']})))
            return
    order = {"working": 0, "open": 1, "dead": 3, "done": 2}
    for p in sorted(paths, key=lambda p: (order.get(p["status"], 1), p["id"])):
        col = STATUS_COL.get(p["status"], "")
        host = f" {DIM}[{p['host']}]{N}" if p.get("host") else ""
        print(f"  {col}#{p['id']:<3} {p['status']:<8}{N} {C}{p.get('type','misc'):<11}{N} {p['desc']}{host}")
    openc = sum(1 for p in paths if p["status"] in ("open", "working"))
    label = f"'{want}' " if want else ""
    print(f"\n{B}{len(paths)} {label}attack vectors{N}, {openc} still worth trying.")

USAGE_VECTOR = ('Usage: pentrail vector add "<desc>" [-t <type>]   |   '
                "pentrail vector <status> <id>   (status: open|working|dead|done)")

def cmd_vector(args):
    d = require_engagement()
    st = load_state(d)
    verb = args.action
    if verb == "add":
        desc = " ".join(args.rest)
        if not desc:
            die(USAGE_VECTOR)
        ptype = (args.type or "misc").lower()
        pid = add_vector(d, st, desc, host=current_target(), ptype=ptype)
        save_state(d, st)
        ok(f"Attack vector #{pid} added [{ptype}]") if pid else info("Already tracked")
        return
    if verb in ("rm", "del", "remove"):
        if not args.rest or not args.rest[0].isdigit():
            die("Usage: pentrail vector rm <id>")
        pid = int(args.rest[0])
        p = next((p for p in st["vectors"] if p["id"] == pid), None)
        if not p:
            die(f"No attack vector #{pid}")
        st["vectors"] = [x for x in st["vectors"] if x["id"] != pid]
        save_state(d, st)
        log_event("vector", f"#{pid} removed ({p['desc']})")
        ok(f"Removed vector #{pid}")
        return
    # status as the verb, to match 'host own <ip>':  vector working 3
    if verb not in VALID_STATUS or not args.rest or not args.rest[0].isdigit():
        die(USAGE_VECTOR)
    pid = int(args.rest[0])
    p = next((p for p in st["vectors"] if p["id"] == pid), None)
    if not p:
        die(f"No attack vector #{pid}")
    p["status"] = verb
    save_state(d, st)
    log_event("vector", f"#{pid} -> {verb}  ({p['desc']})")
    ok(f"#{pid} set to {verb}")

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

def cmd_report(args):
    """Compile the whole project into report/report.md: hosts, vectors, creds,
    flags, facts, timeline and evidence. The basis of your write-up, for free."""
    d = require_engagement()
    st = load_state(d)
    _norm_creds(st)
    L = []
    def A(s=""):
        L.append(s)
    A(f"# {d.name} - engagement report")
    A()
    A(f"- Generated: {datetime.now():%Y-%m-%d %H:%M}")
    A(f"- Target: {st.get('target') or '-'}")
    facts = st.get("facts", {})
    if facts.get("domain"):
        A(f"- Domain: {facts['domain']}")
    for k, v in facts.items():
        if k != "domain":
            A(f"- {k}: {v}")
    if st.get("focus"):
        A(f"- Current focus: {st['focus']}")

    A(); A("## Hosts")
    if st["hosts"]:
        A("| IP | Name | OS | Owned |")
        A("|---|---|---|---|")
        for h in st["hosts"]:
            A(f"| {h['ip']} | {h.get('name','')} | {h.get('os','')} | {'yes' if h['owned'] else ''} |")
    else:
        A("_none_")

    A(); A("## Attack vectors")
    if st["vectors"]:
        for status in ("working", "open", "done", "dead"):
            grp = [p for p in st["vectors"] if p["status"] == status]
            if not grp:
                continue
            A(f"### {status} ({len(grp)})")
            for p in grp:
                host = f" _({p['host']})_" if p.get("host") else ""
                A(f"- `{p.get('type','misc')}` {p['desc']}{host}")
            A()
    else:
        A("_none_")

    A(); A("## Credentials")
    if st["creds"]:
        A("| Kind | User | Secret | Host |")
        A("|---|---|---|---|")
        for c in st["creds"]:
            secret = "`[hidden]`" if args.mask and c.get("secret") else c.get("secret", "")
            A(f"| {c['kind']} | {c.get('user','')} | {secret} | {c.get('host','')} |")
        if args.mask:
            A(); A("_secrets hidden (--mask); drop it for the full values_")
    else:
        A("_none_")

    if st.get("flags"):
        A(); A("## Flags")
        for f in st["flags"]:
            A(f"- **{f['name']}**: {f['value']}  _({f.get('host','')})_")

    A(); A("## Timeline")
    tl = [l for l in _read(d / "logbook.md").splitlines() if l.startswith("- ")]
    A("\n".join(tl) if tl else "_empty_")

    files = sorted(p for p in (d / "evidence").rglob("*") if p.is_file())
    if files:
        A(); A("## Evidence files")
        for p in files:
            A(f"- `{p.relative_to(d)}`")

    out = d / "report" / "report.md"
    out.write_text("\n".join(L) + "\n")
    log_event("report", f"generated {out.name}" + (" (masked)" if args.mask else ""))
    ok(f"Report written: {out}")
    print(f"    {len(st['hosts'])} hosts, {len(st['vectors'])} vectors, "
          f"{len(st['creds'])} creds, {len(st.get('flags', []))} flags")

# ----------------------------------------------------------------------------- intel parser (the smart rules)
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
        m = re.search(r"(?:valid|found|success|login)\b.*?\b([A-Za-z0-9._\\-]{2,}):(\S{3,})\b", line, re.I)
        if m:
            _add({"user": m.group(1), "secret": m.group(2), "kind": cred_kind(m.group(2))})
    # labelled user=/password=
    for m in re.finditer(r"\b(user(?:name)?|login)\s*[:=]\s*(\S{2,})", text, re.I):
        _add({"user": m.group(2), "secret": "", "kind": "username"})
    for m in re.finditer(r"\b(pass(?:word)?|pwd|passwd|secret)\s*[:=]\s*(\S{3,})", text, re.I):
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

def ingest_text(d, st, text, source):
    text, nred = redact_text(text)        # scrub the operator's own secrets first
    if nred:
        warn(f"Redacted {nred} token(s) matching your redact list (not parsed, not stored).")
    found = parse_intel(text)
    target = st.get("target") or current_target()
    added = 0

    if found["ports"]:
        info(f"Ports: " + ", ".join(f"{p}/{s}" for p, s in sorted(found["ports"].items())))

    new_web = 0
    for path, status in sorted(found["web"].items()):
        if status in (200, 201, 204, 301, 302, 307, 401, 403) and \
           (status in (200, 301, 302) or INTERESTING.search(path)):
            wtype, hint = web_type(path)
            desc = f"web: {path} ({status})" + (f" - {hint}" if hint else "")
            if add_vector(d, st, desc, host=target, sig=f"web:{target}:{path}", ptype=wtype):
                added += 1; new_web += 1
    if new_web:
        ok(f"{new_web} web path(s) -> vectors")

    new_vuln = 0
    for vtype, desc, sig in found["vulns"]:
        if add_vector(d, st, desc, host=target, status="working", sig=sig, ptype=vtype):
            added += 1; new_vuln += 1
    if new_vuln:
        ok(f"{new_vuln} tagged vulnerability signal(s) -> vectors (status: working)")

    new_hosts = [h for h in found["hosts"] if h not in st["hostnames"]]
    if new_hosts:
        st["hostnames"].extend(new_hosts)
        warn("New hostnames (add with 'pentrail resolve'): " + ", ".join(new_hosts))
        log_event("intel", f"hostnames from {source}: {', '.join(new_hosts)}")

    _norm_creds(st)
    new_creds = 0
    for c in found["creds"]:
        if "[REDACTED]" in c.get("user", "") or "[REDACTED]" in c.get("secret", ""):
            continue    # a redacted operator secret; never store
        c.setdefault("host", target); c.setdefault("src", source)
        c.setdefault("added", f"{datetime.now():%Y-%m-%d %H:%M:%S}")
        if add_cred(st, c):
            new_creds += 1
            log_event("cred", f"{cred_str(c)} [{c['kind']}] (from {source})")
    if new_creds:
        warn(f"{new_creds} new credential(s) -> 'pentrail creds'")

    new_facts = 0
    st.setdefault("facts", {})
    for k, v in found["facts"].items():
        if v and not st["facts"].get(k):
            st["facts"][k] = v
            new_facts += 1
            log_event("fact", f"{k} = {v} (from {source})")
            ok(f"Detected {k}: {v}")

    save_state(d, st)
    dupes = (len(found["creds"]) - new_creds) + (len(found["hosts"]) - len(new_hosts))
    if added or new_hosts or new_creds or new_facts:
        bits = []
        if added:     bits.append(f"{added} attack vector(s)")
        if new_hosts: bits.append(f"{len(new_hosts)} hostname(s)")
        if new_creds: bits.append(f"{new_creds} credential(s)")
        if new_facts: bits.append(f"{new_facts} fact(s)")
        print(f"\n{B}New:{N} " + ", ".join(bits) + " - see 'pentrail vectors' / 'pentrail creds' / 'pentrail log'.")
        if dupes:
            print(f"{DIM}    ({dupes} already-known item(s) skipped){N}")
    elif found["ports"] or found["web"] or found["hosts"] or found["creds"] or found["vulns"]:
        info(f"Nothing new from {source} - everything was already logged.")
    else:
        info(f"No leads parsed from {source}.")

def cmd_ingest(args):
    d = require_engagement()
    f = Path(args.file)
    if not f.is_file():
        die(f"File not found: {f}")
    st = load_state(d)
    log_event("ingest", f"parsed {f.name}")
    ingest_text(d, st, f.read_text(errors="replace"), f.name)

def _read_marker():
    try:
        return json.loads(CAPTURE_MARKER.read_text())
    except (OSError, json.JSONDecodeError):
        return None

def cmd_capture(args):
    d = require_engagement()
    if not shutil.which("script"):
        die("'script' missing (sudo apt install bsdutils)")
    lbl = re.sub(r"[^A-Za-z0-9._-]", "-", args.label) if args.label else "shell"

    # Already inside a capture in THIS shell: a child can't close its own parent
    # script and keep running, so ask the user to close it first.
    inside = os.environ.get("PENTRAIL_CAPTURE")
    if inside:
        die(f"You're inside capture '{inside}'. Type 'exit' to close it, then run "
            f"'pentrail capture {args.label or ''}'.".rstrip())

    # A capture running in another shell/tab: close it so this one replaces it.
    m = _read_marker()
    if m and process_alive(m.get("pid")):
        info(f"Closing previous capture '{m.get('label')}' (pid {m['pid']}) ...")
        try:
            os.kill(m["pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(12):
            if not process_alive(m["pid"]):
                break
            time.sleep(0.5)

    box = d.name
    f = d / "evidence" / "terminal" / f"{box}_{datetime.now():%Y-%m-%d_%H%M%S}_{lbl}.log"
    info(f"Recording shell '{lbl}' to {f}")
    print(f"{DIM}    work as usual; type 'exit' when done - output is parsed for leads afterwards.{N}")
    log_event("capture", f"started {lbl} ({f.name})")

    env = dict(os.environ, PENTRAIL_CAPTURE=lbl)
    proc = subprocess.Popen(["script", "-q", "-f", str(f)], env=env)
    CAPTURE_MARKER.write_text(json.dumps(
        {"pid": proc.pid, "label": lbl, "file": str(f), "eng": str(d)}))
    proc.wait()

    # clear the marker only if it still points at this capture (a replacement
    # started elsewhere may already have overwritten it)
    m2 = _read_marker()
    if m2 and m2.get("pid") == proc.pid:
        CAPTURE_MARKER.unlink(missing_ok=True)

    # scrub your own registered secrets out of the saved evidence file itself
    raw = f.read_text(errors="replace")
    clean, nred = redact_text(raw)
    if nred:
        f.write_text(clean)
        warn(f"Scrubbed {nred} of your own secret(s) from {f.name} before saving.")
    ok(f"Recording saved: {f}")
    st = load_state(d)
    log_event("capture", f"ended {lbl} ({f.name})")
    ingest_text(d, st, clean, f.name)

def _shot_save(d, label, display, source):
    """Render text to a PNG via termshot, save text + png as evidence, log, redact,
    and parse for leads. Shared by 'shot <cmd>' and 'shot --last'."""
    ts = datetime.now()
    label = re.sub(r"[^A-Za-z0-9._-]", "-", label or "shot")[:24]
    base = f"{d.name}_{ts:%Y-%m-%d_%H%M%S}_{label}"
    png = d / "evidence" / "screenshots" / f"{base}.png"
    txt = d / "evidence" / "output" / f"{base}.txt"
    display, nred = redact_text(display)
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
    log_event("shot", f"{source} -> {(png if made else txt).name}")
    ok(f"Saved: {png if made else txt}")
    st = load_state(d)
    ingest_text(d, st, display, f"shot:{label}")

def _shot_last(d, args):
    """Screenshot recent output of the active capture (the task you just ran)."""
    m = _read_marker()
    if not (m and process_alive(m.get("pid"))):
        die("'shot --last' screenshots recent output during a capture. Start 'pentrail "
            "capture' first, or use 'pentrail shot <command>'. (A tool cannot read your "
            "terminal scrollback on its own, so there must be a capture recording it.)")
    cap = Path(m["file"])
    data = cap.read_text(errors="replace") if cap.exists() else ""
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
    CAPTURE_MARKER.write_text(json.dumps(m))
    _shot_save(d, args.label or m.get("label", "snap"), chunk,
               f"capture {m.get('label', '')} tail")

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
    _shot_save(d, args.label or cmd[0], f"$ {' '.join(cmd)}\n{raw}", " ".join(cmd))

# ----------------------------------------------------------------------------- enumeration suggestions
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

def _latest_scan(d):
    files = sorted((d / "scans").glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return next((f for f in files if f.is_file()), None)

def parse_ports(text):
    out = {}
    for m in re.finditer(r"^(\d+)/(?:tcp|udp)\s+open\s+(\S+)", text, re.M):
        out[int(m.group(1))] = m.group(2)
    for m in re.finditer(r"(\d+)/open/(?:tcp|udp)//([^/]*)/", text):
        out.setdefault(int(m.group(1)), m.group(2) or "unknown")
    return sorted(out.items())

def cmd_next(args):
    d = require_engagement()
    target = current_target() or "{t}"
    done_text = (_read(d / "logbook.md") + _read(d / "notes" / "notes.md")).lower()
    scan = _latest_scan(d)
    if not scan:
        warn(f"No scan output in {d}/scans/ yet. Run a scan first, e.g.:")
        print(f"    nmap -sC -sV -oN {d}/scans/initial.txt {target}")
        print(f"    nmap -p- --min-rate 2000 -oN {d}/scans/allports.txt {target}")
        return
    ports = parse_ports(_read(scan))
    if not ports:
        warn(f"No open ports parsed from {scan.name}. Is it nmap -oN or -oG output?")
        return
    info(f"Latest scan: {scan.name}  ({len(ports)} open ports)")
    print()
    total = done = 0
    untouched = []
    for port, svc in ports:
        key = svc if (svc in PLAYBOOK or svc in ("http", "https")) else PORT_FALLBACK.get(port, svc)
        if key in ("http", "https"):
            steps = web_steps(key, port, target)
        else:
            steps = PLAYBOOK.get(key)
        label = f"{G}{port:>5}{N}/{svc}"
        if not steps:
            print(f"{label}  {DIM}(no standard playbook - enumerate manually){N}")
            continue
        print(label)
        svc_todo = 0
        for step in steps:
            cmd = step.format(t=target, p=port, h=target)
            tool = re.split(r"[ /]", cmd.strip())[0].lower()
            total += 1
            if tool in done_text:
                done += 1
                print(f"    {G}[x]{N} {DIM}{cmd}{N}")
            else:
                svc_todo += 1
                print(f"    {Y}[ ]{N} {cmd}")
        if svc_todo == len(steps):
            untouched.append(f"{port}/{svc}")
        print()
    print(f"{B}Progress:{N} {done}/{total} standard steps logged.")
    if done == 0:
        warn("Nothing logged yet - start at the top of the list above.")
    elif untouched:
        warn("Services you haven't touched at all: " + ", ".join(untouched)
             + "  <- usually where the way in is when you feel stuck.")
    else:
        ok("You've started on every open service. Still stuck? Re-run a full port scan "
           "(nmap -p-), check vhosts/UDP, and re-read 'pentrail vectors' and your logbook.")
    tl = d / "logbook.md"
    if tl.exists():
        mins = (time.time() - tl.stat().st_mtime) / 60
        if mins > int(CFG["stale_minutes"]):
            warn(f"Nothing logged for {int(mins)} min. Stuck usually means a rabbit hole - "
                 "jot what you tried (pentrail note ...) so the checklist stays accurate.")

# ----------------------------------------------------------------------------- /etc/hosts
def cmd_resolve(args):
    hosts_path = Path("/etc/hosts")
    if args.names and args.names[0] == "--clean":
        kept = [l for l in hosts_path.read_text().splitlines() if "# pentrail:" not in l]
        _write_hosts(hosts_path, kept)
        ok("Removed pentrail-added lines from /etc/hosts"); return
    names = list(args.names)
    ip = current_target()
    if names and IP_RE.match(names[0]):
        ip = names.pop(0)
    if not ip or not names:
        die("Usage: pentrail resolve [ip] <hostname> [hostname...]  (ip defaults to the engagement target)")
    tag = f"pentrail:{current_dir().name if current_dir() else 'manual'}"
    lines = hosts_path.read_text().splitlines()
    for name in names:
        if not re.match(r"^[A-Za-z0-9.-]+$", name):
            warn(f"Invalid hostname skipped: {name}"); continue
        if any(not l.lstrip().startswith("#") and "# pentrail:" not in l and name in l.split() for l in lines):
            warn(f"{name} already in /etc/hosts (not via pentrail) - skipped"); continue
        lines = [l for l in lines if not ("# pentrail:" in l and name in l.split())]
        lines.append(f"{ip}\t{name}\t# {tag}")
        ok(f"Added {ip}  {name} to /etc/hosts")
        log_event("resolve", f"{ip} {name}")
    _write_hosts(hosts_path, lines)

def _write_hosts(path, lines):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_DIR / "hosts.tmp"
    tmp.write_text("\n".join(lines) + "\n")
    subprocess.run([*SUDO, "cp", str(tmp), str(path)])
    tmp.unlink(missing_ok=True)

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
    val = int(args.value) if args.key in ("connect_timeout", "stale_minutes") else args.value
    cfg[args.key] = val
    save_config({k: cfg[k] for k in DEFAULTS})
    ok(f"{args.key} = {val}  (saved to {CONFIG_FILE})")

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
    row(f"wordlist: {wl}", wl.exists(),
        "" if wl.exists() else "set 'pentrail config wordlist <path>' (e.g. SecLists)")
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
    print()

    # 4. Shell helper --------------------------------------------------------
    if not args.no_shell:
        print(f"{B}4. Shell helper{N}")
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

    # Locate the source checkout --------------------------------------------
    repo = _git_root(Path(__file__).resolve().parent)
    from_cfg = False
    if not repo and CFG.get("src_repo"):
        cand = Path(CFG["src_repo"])
        repo = _git_root(cand)
        from_cfg = bool(repo)
    if not repo:
        die("Don't know where pentrail's source repo is. Run 'pentrail update' from "
            "the git checkout, or point to it:  pentrail config src_repo <path>")
    src = repo / "pentrail.py"
    if not src.exists():
        die(f"No pentrail.py in {repo}. Is that the right checkout?")
    if not from_cfg and not dry:
        _remember_src_repo(repo)   # keep it for the installed launcher next time

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

# ----------------------------------------------------------------------------- help guide
HELP_SECTIONS = [
    ("PROJECT & BOXES", [
        ("new <name> [ip]", "Create project <name> under base_dir (evidence folders,",
                            "logbook, notes), connect the VPN, and ping [ip] if given."),
        ("use <name>",      "Switch to an existing project. No folders, no VPN touched."),
        ("resume [name]",   "Come back to a project (last one if omitted): switch to it,",
                            "reconnect the VPN, and print where you left off."),
        ("list",            "List all projects; '*' marks the current one."),
        ("target <ip|name>","Set the active box in this project (adds it if new).",
                            "Updates $TARGET; new findings attach to this box."),
        ("dir",             "Print the current project path: cd \"$(pentrail dir)\"."),
    ]),
    ("VPN", [
        ("up [file.ovpn]",  "Connect. No file: use default_vpn, else last used, else pick."),
        ("down",            "Disconnect the VPN."),
        ("restart [file]",  "Reconnect (same file unless you pass one)."),
        ("status",          "Show VPN state + the current project."),
        ("check [ip]",      "Diagnose the connection and print a concrete fix per problem."),
        ("watch [seconds]", "Keep watching; auto-restart the VPN if it hangs (default 30)."),
    ]),
    ("LOGBOOK & EVIDENCE", [
        ("log [n]",         "Show the logbook (last n lines; default all)."),
        ("note <text>",     "Add a timestamped line to the logbook."),
        ("capture [label]", "Record this shell (via script) into evidence/terminal/.",
                            "On exit it is parsed for leads. Only one capture at a time."),
        ("shot [-l label] <cmd>", "Run a command, save a termshot PNG + text as evidence,",
                            "and parse its output. One step, no manual screenshots."),
        ("shot --last [lines]", "During a capture: screenshot the task you just ran."),
        ("ingest <file>",   "Parse an existing output file for leads (same rules)."),
    ]),
    ("ATTACK VECTORS  (leads to try; auto-filled + auto-tagged by capture/ingest)", [
        ("next",            "From your newest nmap in scans/, list enumeration steps per",
                            "service and tick off what you already did."),
        ("vectors [type]",  "List attack vectors, sorted by status; filter by type."),
        ("vector add \"<desc>\" [-t type]", "Add an attack vector by hand, with a type."),
        ("vector <status> <id>", "Set status: open | working | dead | done (e.g. vector working 3)."),
        ("vector rm <id>",   "Remove a wrong or mis-tagged vector."),
    ]),
    ("FINDINGS", [
        ("creds",           "List credentials (captured automatically or added)."),
        ("creds users|passwords|hashes", "Print one per line (pipe to a file)."),
        ("creds export [dir]", "Write users/passwords/hashes.txt + spray/crack hints."),
        ("cred add <user:secret>", "Store one (user:pass, user:hash, or just a hash)."),
        ("cred rm <n>",     "Remove credential #n (from 'pentrail creds')."),
        ("flag <name> <value>", "Record an HTB flag (user/root also marks the box owned).",
                            "'pentrail flag' with no value lists them."),
        ("report [--mask]", "Compile report/report.md; --mask hides credential secrets."),
    ]),
    ("PROJECT CONTEXT", [
        ("set <key> <value>", "Keep a project fact: domain, dc-ip, base-dn, url, ...",
                            "'pentrail set' lists them; the domain is auto-detected too."),
        ("focus <text>",    "Note what you are on now (shown on the home screen)."),
        ("redact add <value>", "Register your OWN creds/tokens so captures scrub them to",
                            "[REDACTED]. Stored as hashes; 'redact list' / 'redact clear' too."),
    ]),
    ("HOSTS & LATERAL MOVEMENT", [
        ("hosts",           "List hosts in this project (with OWNED flags)."),
        ("host add <ip> [name] [os]", "Track a host."),
        ("host own <ip>",   "Mark a host compromised."),
        ("host rm <ip|name>", "Stop tracking a host."),
        ("pivot <from> <to> [--via note]", "Log lateral movement between hosts."),
        ("map",             "Show hosts + the movement chain."),
    ]),
    ("OTHER", [
        ("resolve [ip] <name...>", "Add /etc/hosts entries (ip defaults to the target).",
                            "'pentrail resolve --clean' removes pentrail's own entries."),
        ("config [key] [value]", "Show or set config (base_dir, vpn_dir, default_vpn,",
                            "web_tool, wordlist, termshot_cmd, connect_timeout, ...)."),
        ("doctor",          "Check installed tools, paths and wordlist; shows apt hints."),
        ("setup",           "Guided install: put pentrail on PATH, install missing tools,",
                            "set vpn_dir and add the pcd shell helper. --yes for unattended."),
        ("update",          "Update pentrail: git pull the source repo and reinstall the",
                            "launcher so the new version runs. --branch to pull another branch."),
        ("version",         "Print the version (also: pentrail --version)."),
    ]),
]
FLOW = [
    "pentrail new box1 10.10.10.5", 'cd "$(pentrail dir)" && source .env',
    "nmap -sC -sV -oN scans/initial.txt $TARGET", "pentrail next",
    "pentrail capture recon          # work in the shell, then type exit",
    "pentrail vectors                  # leads found so far",
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

def print_home(_args=None):
    print_banner()
    print(f"\n{DIM}For authorized labs and engagements only.{N}\n")
    d = current_dir()
    if d:
        st = load_state(d)
        vpn = f"{G}up{N}" if vpn_running() else f"{R}down{N}"
        print(f"Active project: {B}{d.name}{N}   VPN: {vpn}")
        project_summary(d, loglines=3)
        print(f"\n{B}Carry on{N}")
        _cmd("pentrail resume", "reconnect the VPN and recap")
        _cmd("pentrail next", "what to enumerate next")
        _cmd("pentrail capture <label>", "record a shell; findings auto-logged")
        _cmd("pentrail vectors", "your leads, by status")
        _cmd("pentrail creds", "credentials, for spraying / cracking")
    else:
        print("No active project.\n")
        print(f"{B}Get started{N}")
        _cmd("pentrail setup", "install pentrail + missing tools, set vpn_dir")
        _cmd("pentrail new <name> <ip>", "new project: folders, VPN, logbook")
        _cmd("pentrail resume", "resume the project you last worked on")
        _cmd("pentrail list", "list existing projects")
        base = Path(CFG["base_dir"])
        projs = sorted([x.name for x in base.iterdir()
                        if (x / "state.json").exists()]) if base.is_dir() else []
        if projs:
            print(f"\n{DIM}Projects: {', '.join(projs[:12])}{N}")
    print(f"\n{B}Walkthrough of a box{N}")
    for i, step in enumerate(FLOW, 1):
        print(f"  {DIM}{i}.{N} {step}")
    print(f"\nAll commands: {G}pentrail help{N}   one command: {G}pentrail help <command>{N}")

def print_help_guide(_args=None):
    print(f"{B}pentrail{N} - the pentest logbook (for authorized labs and engagements)\n")
    print("Usage: pentrail <command> [args]")
    print(f"       {DIM}pentrail help <command>   full explanation + example for one command{N}\n")
    for title, rows in HELP_SECTIONS:
        print(f"{B}{title}{N}")
        for row in rows:
            cmd, first, *more = row
            if len(cmd) <= 26:
                print(f"  {G}{cmd:<26}{N}{first}")
            else:
                print(f"  {G}{cmd}{N}")          # too wide: effect on its own line
                print(f"  {'':<26}{first}")
            for extra in more:
                print(f"  {'':<26}{extra}")
        print()
    print(f"{B}Typical flow{N}")
    for line in FLOW:
        print(f"  {DIM}${N} {line}")
    print(f"\nConfig lives in {CONFIG_FILE}")

# Rich per-command help shown by 'pentrail help <command>'.
# Each entry: what it does, how to use it, what comes out, and an example.
DETAILS = {
    "new": ("Start a new project (one engagement, one or more boxes).",
        "pentrail new <name> [ip]",
        ["Creates ~/pentests/<name>/ with evidence folders, a logbook and a notes",
         " template, makes it the active project, connects the VPN, and if you pass an",
         " IP records it as the target and pings it.",
         "Outcome: a ready workspace; 'source .env' gives you $TARGET and $VPN_IP."],
        "pentrail new blackfield 10.10.10.192"),
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
         "Only one capture runs at a time. Starting another from a second terminal closes",
         " this one first; starting it inside this shell asks you to 'exit' first.",
         "Label is free text: recon, web, sqli, privesc, lateral, whatever fits."],
        "pentrail capture privesc"),
    "shot": ("Keep a terminal screenshot as evidence, hands-off.",
        "pentrail shot [-l label] <command ...>   |   pentrail shot --last [lines]",
        ["<command>: runs it once, saves a PNG (via termshot) to evidence/screenshots/",
         " <box>_<date>_<label>.png and the text to evidence/output/, logs it, scrubs your",
         " redacted secrets, and parses the output for leads. Flags go after the command",
         " name (or after --).",
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
        ["Walks four steps, asking before each change (sudo only for install and apt):",
         " 1. install this script to /usr/local/bin/pentrail so 'pentrail' works anywhere;",
         " 2. install missing tools with apt - core (openvpn, iproute2, ping, script) and,",
         "    unless --core-only, the enumeration set (nmap, ffuf, smbclient, hydra, ...);",
         " 3. set vpn_dir and create base_dir/vpn_dir;",
         " 4. add the pcd() helper to your shell rc (idempotent).",
         "--yes runs it unattended (answers yes); --dry-run shows the steps and changes",
         " nothing. termshot is not on apt, so it is only pointed to, not installed."],
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
        ["Reads the newest file in scans/ and, per open service, lists the standard",
         " enumeration steps with your target filled in; steps whose tool is already in",
         " your logbook are ticked [x]. The web brute-force step uses your configured",
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

# ----------------------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(prog="pentrail", description="the pentest logbook (authorized labs/engagements)")
    p.add_argument("--version", "-V", action="version", version=f"pentrail {VERSION}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the version").set_defaults(
        func=lambda a: print(f"pentrail {VERSION}"))

    s = sub.add_parser("new", help="start engagement: folders, VPN, logbook, target check")
    s.add_argument("name"); s.add_argument("ip", nargs="?"); s.set_defaults(func=cmd_new)
    s = sub.add_parser("use", help="switch to an existing project (no scaffolding/VPN)")
    s.add_argument("name"); s.set_defaults(func=cmd_use)
    s = sub.add_parser("resume", help="come back: switch, reconnect VPN, show where you left off")
    s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_resume)
    sub.add_parser("list", aliases=["ls"], help="list projects").set_defaults(func=cmd_list)
    s = sub.add_parser("target", help="set the active box within this engagement: target <ip|name>")
    s.add_argument("ip"); s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_target)

    s = sub.add_parser("up", aliases=["connect"], help="connect the VPN")
    s.add_argument("file", nargs="?"); s.set_defaults(func=lambda a: vpn_up(a.file))
    sub.add_parser("down", aliases=["stop"], help="disconnect").set_defaults(func=lambda a: vpn_down())
    s = sub.add_parser("restart", help="reconnect the VPN")
    s.add_argument("file", nargs="?"); s.set_defaults(func=lambda a: vpn_restart(a.file))
    sub.add_parser("status", aliases=["st"], help="VPN + engagement status").set_defaults(func=lambda a: vpn_status())
    s = sub.add_parser("check", aliases=["diag"], help="diagnose the connection")
    s.add_argument("ip", nargs="?"); s.set_defaults(func=cmd_check)
    s = sub.add_parser("watch", help="monitor VPN, auto-restart when it hangs")
    s.add_argument("interval", nargs="?", type=int, default=30); s.set_defaults(func=cmd_watch)

    s = sub.add_parser("log", help="show the logbook")
    s.add_argument("n", nargs="?", type=int); s.set_defaults(func=cmd_log)
    s = sub.add_parser("note", help="add a line to the logbook")
    s.add_argument("text", nargs="+"); s.set_defaults(func=cmd_note)
    s = sub.add_parser("capture", help="record the shell and parse it for leads")
    s.add_argument("label", nargs="?"); s.set_defaults(func=cmd_capture)
    s = sub.add_parser("shot", help="screenshot a command (shot <cmd>) or recent capture output (shot --last)")
    s.add_argument("-l", "--label")
    s.add_argument("--last", nargs="?", const=0, type=int,
                   help="screenshot the active capture's recent output (optionally last N lines)")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_shot)
    s = sub.add_parser("ingest", help="parse an existing output file for leads")
    s.add_argument("file"); s.set_defaults(func=cmd_ingest)
    sub.add_parser("next", aliases=["suggest"],
                   help="suggest untried enumeration from your nmap output").set_defaults(func=cmd_next)

    s = sub.add_parser("vectors", help="list attack vectors (optionally filter by type)")
    s.add_argument("type", nargs="?"); s.set_defaults(func=cmd_vectors)
    s = sub.add_parser("vector", help='attack vectors: add "<desc>" [-t type] | <status> <id>')
    s.add_argument("action"); s.add_argument("rest", nargs="*")
    s.add_argument("-t", "--type", help="category, e.g. web/sqli/rce/privesc/lateral (any string)")
    s.set_defaults(func=cmd_vector)
    s = sub.add_parser("creds", help="list credentials | creds users|passwords|hashes|export")
    s.add_argument("what", nargs="?"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_creds)
    s = sub.add_parser("cred", help="cred add <user:secret> [host]  (user:pass, user:hash, or just a hash)")
    s.add_argument("action"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_cred)
    s = sub.add_parser("flag", help="record/list an HTB flag: flag user <value> | flag (list)")
    s.add_argument("name", nargs="?", default=""); s.add_argument("value", nargs="*"); s.set_defaults(func=cmd_flag)
    s = sub.add_parser("set", help="project facts: set <key> <value> | set (list), e.g. set domain x.local")
    s.add_argument("key", nargs="?"); s.add_argument("value", nargs="*"); s.set_defaults(func=cmd_set)
    s = sub.add_parser("focus", help="what you are working on now: focus \"LDAP enum\" | focus (show)")
    s.add_argument("text", nargs="*"); s.set_defaults(func=cmd_focus)
    s = sub.add_parser("redact", help="your own secrets to never capture: redact add <value...> | list | clear")
    s.add_argument("action"); s.add_argument("rest", nargs="*"); s.set_defaults(func=cmd_redact)

    sub.add_parser("hosts", help="list hosts in this engagement").set_defaults(func=cmd_hosts)
    s = sub.add_parser("host", help="host add <ip> [name] | host own <ip>")
    s.add_argument("action"); s.add_argument("ip", nargs="?")
    s.add_argument("name", nargs="?"); s.add_argument("os", nargs="?"); s.set_defaults(func=cmd_host)
    s = sub.add_parser("pivot", help="log lateral movement: pivot <from> <to> [--via note]")
    s.add_argument("src"); s.add_argument("dst"); s.add_argument("--via", default=""); s.set_defaults(func=cmd_pivot)
    sub.add_parser("map", help="show hosts + lateral movement").set_defaults(func=cmd_map)
    s = sub.add_parser("report", help="compile report/report.md (hosts, vectors, creds, timeline)")
    s.add_argument("--mask", action="store_true", help="hide credential secrets (for sharing)")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("resolve", help="add /etc/hosts entries (resolve --clean to remove)")
    s.add_argument("names", nargs="+"); s.set_defaults(func=cmd_resolve)
    sub.add_parser("dir", help="print the current engagement path").set_defaults(
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
    s = sub.add_parser("help", help="full usage guide (or: pentrail help <command>)")
    s.add_argument("topic", nargs="?"); s.set_defaults(func=None)
    return p

def main():
    if sys.version_info < (3, 8):
        sys.exit("pentrail needs Python 3.8 or newer (found "
                 f"{sys.version_info.major}.{sys.version_info.minor}).")
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    warn_if_root()
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd == "help":
        if args.topic:
            if print_command_detail(args.topic):
                return
            parser.parse_args([args.topic, "-h"])   # fall back to argparse help and exit
        print_help_guide(); return
    if not getattr(args, "func", None):
        print_home(); return      # bare 'pentrail' = banner + orientation
    args.func(args)

if __name__ == "__main__":
    main()
