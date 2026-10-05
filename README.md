# pentrail, the pentest logbook

`pentrail` gets a pentest session going in one command and then keeps the paperwork
for you. It connects the VPN, lays out evidence folders, and keeps a running,
timestamped logbook: scans, notes, discovered attack vectors, hosts you reach and
how you moved between them. `pentrail capture` records the shell you work in and reads
the output for you, turning gobuster and nmap hits into logged attack vectors, and it
never writes the same finding twice.

It is for labs and engagements you are authorized to test (HTB, OffSec, a scoped
client engagement). Pure Python 3 (3.8+), standard library only, so there is nothing
to `pip install`. Built for Kali/Linux.

## Quickstart

```bash
python3 pentrail.py setup             # install to PATH + missing tools + config (or do it by hand, below)
pentrail doctor                       # check what is installed, with apt hints
pentrail config vpn_dir ~/vpn         # where your .ovpn files live
pentrail new box1 10.10.10.5          # project + VPN + logbook, pings the target
cd "$(pentrail dir)" && source .env   # $TARGET is now set
nmap -sC -sV -oN scans/initial.txt $TARGET
pentrail next                         # what to enumerate next
pentrail capture recon                # record a shell; exit when done, findings auto-logged
pentrail report                       # compile report/report.md when you are done
```

`pentrail setup` does the install for you (`pentrail` on `$PATH`, missing tools via
`apt`, `vpn_dir`, and a `pcd` shell helper), asking before each change. See
[Install](#install) for the manual steps if you prefer.

Run `pentrail` with no arguments any time for the home screen (where you left off and
what to do next).

## Install

The quickest way is the guided installer, which explains each step as it goes: it
puts `pentrail` on your `$PATH`, installs the tools you are missing with `apt`, sets
`vpn_dir`, finds a directory wordlist already on your machine if the configured one is
missing, and adds the `pcd` shell helper. It asks before every change and uses `sudo`
only for the install and `apt` steps:

```bash
python3 pentrail.py setup          # guided; or: --yes for unattended
```

Flags: `--yes` (assume yes, non-interactive), `--core-only` (skip the enumeration
toolkit), `--vpn-dir <path>`, `--no-tools` / `--no-launcher` / `--no-shell` to skip a
step, and `--dry-run` to see exactly what it would do without changing anything. Run
it as your normal user; it elevates only where it must.

Prefer to do it by hand? Install the one file and set your config directly:

```bash
sudo install -m 755 pentrail.py /usr/local/bin/pentrail
```

### Updating

Once installed, pull the latest and reinstall in one step:

```bash
pentrail update                 # git pull the source repo + reinstall the launcher
pentrail update --branch main   # e.g. after a PR is merged to main
```

`update` finds the source checkout (the repo you run it from, or the one `setup`
recorded as `src_repo`), runs `git pull --ff-only`, and reinstalls `pentrail` to
`/usr/local/bin` so the new version is the one that runs. A diverged branch stops it
before anything is reinstalled, so your local work is never clobbered. By hand it is
just `git pull` in the repo followed by the `install` line above.

Then set three things once, so a session starts without any prompts:

```bash
pentrail config vpn_dir      ~/vpn
pentrail config default_vpn  ~/vpn/lab.ovpn     # optional, skips the file picker
pentrail config base_dir     ~/pentests
```

Config lives in `~/.config/pentrail/config.json`, VPN state in `~/.local/state/pentrail/`.
You need `openvpn`, `iproute2`, `ping` and `script`, all present on Kali. For PNG
terminal screenshots (`pentrail shot`) install [termshot](https://github.com/homeport/termshot);
without it, `shot` still saves text evidence. Run `pentrail` as your normal user; it
calls `sudo` by itself where it needs to.

Drop this in `~/.zshrc` so one word takes you into the project with `$TARGET` set.
`cd` has to happen in your own shell, so this is a small function rather than a
pentrail command; name it whatever you like:

```bash
pcd() { cd "$(pentrail dir)" && source .env; }
```

## Finding your way around

Run `pentrail` on its own for the home screen: a banner, where you left off (active
project, VPN state, open vectors, focus) and the handful of commands to carry on, or
how to start if there is no project yet. `pentrail help` is the full command guide
grouped by topic; `pentrail help <command>` prints a longer explanation of one
command with what it does, how to use it, the outcome and an example (try `pentrail
help watch` or `pentrail help creds`). The rest of this file walks through a session.

## Running as your normal user (least privilege)

Run `pentrail` as your normal user, never with `sudo`. It does the unprivileged work
itself (creating folders, parsing, pinging, reading `ip`) and calls `sudo` only for
the few steps that truly need root: starting and stopping the openvpn process and
writing `/etc/hosts`. If you run `sudo pentrail` it warns you, because that would
create root-owned files in `~/pentests` and open the capture shell as root. The
capture shell always runs as you.

## A session from start to finish

```bash
pentrail new box1 10.10.10.5          # make the project, connect VPN, ping the target
pcd                               # cd in; $TARGET and $VPN_IP are now set

nmap -sC -sV -oN scans/initial.txt $TARGET
pentrail next                         # suggests what to enumerate, ticks off what you did

pentrail capture recon                # record a shell; run gobuster, curl, etc; type exit
                                  # web paths become attack vectors, creds go in the logbook

pentrail vectors                        # the leads you have, sorted by status
pentrail vector working 3               # you are pursuing lead #3
pentrail vector dead 1                  # #1 went nowhere

pentrail host own 10.10.10.5          # you got a foothold
pentrail pivot 10.10.10.5 10.10.10.6 --via "reused SSH key"
pentrail map                          # the hosts and how you moved
pentrail log                          # the whole logbook, any time
```

### What a project looks like on disk

```
~/pentests/box1/
├── logbook.md       the running timeline, everything timestamped
├── state.json       hosts, attack vectors, creds and hostnames already seen
├── .env             TARGET, VPN_IP, ENG  (source it)
├── notes/notes.md   a notes template you fill in
├── scans/           your nmap output goes here, read by 'pentrail next'
├── evidence/{screenshots,terminal,output}/
├── loot/  files/  report/
```

## One project, many boxes

A project is one folder; the boxes in it are tracked hosts. You run `pentrail new` once
per project, never once per box. Add boxes and move between them without starting
anything new:

```bash
pentrail new offshore 10.10.10.5      # the project, first box is the target
pentrail host add 10.10.10.6 web02    # more boxes
pentrail host add 10.10.10.7 dc01 Windows
pentrail target web02                 # make web02 the active box; $TARGET follows
pentrail list                         # all projects, * is the current one
pentrail use offshore                 # come back to a project later, no VPN or setup
```

`pentrail target <ip|name>` decides which box `next`, `resolve`, `capture` and new
attack vectors apply to. Name your scans per box, like `scans/web02_initial.txt`, so
they stay apart.

## Stopping and coming back

There is nothing to save. Every command writes straight to disk, so closing the
terminal, dropping the VPN or rebooting loses nothing. The folder, the logbook and
`state.json` are the session. `state.json` is written atomically, and if it is ever
found corrupt it is backed up (not silently overwritten) so you can recover. Project
folders are created `chmod 700`, since `loot/` and `state.json` hold credentials.

To pick up where you left off:

```bash
pentrail resume            # last project you worked on
pentrail resume offshore   # or a specific one, by name or path
```

`resume` switches to the project, reconnects the VPN if it is down, and prints a
recap: target, how many hosts and how many are owned, open attack vectors, the ones
you marked `working`, and the last few logbook lines. Then `pcd` and carry on. If
you only want to switch projects without touching the VPN, use `pentrail use`.

## The logbook

Every action lands in `logbook.md` with a time and a short tag, so you can always
see when you were doing what:

```
- 2026-10-01 10:02:11  `new     ` session started - target 10.10.10.5
- 2026-10-01 10:14:03  `vector  ` #3 web: /admin (301) on 10.10.10.5
- 2026-10-01 10:41:55  `own     ` foothold / compromised 10.10.10.5 box1
- 2026-10-01 11:07:20  `pivot   ` 10.10.10.5 -> 10.10.10.6 (reused SSH key)
```

`pentrail log` prints it, `pentrail log 20` the last 20 lines, `pentrail note "<text>"` adds a
line yourself.

## Capturing a shell and turning output into leads

`pentrail capture [label]` records the shell with `script` and parses the whole session
when you type `exit`. Recordings are named after the box, like
`evidence/terminal/box1_2026-10-01_1002_recon.log`. `pentrail ingest <file>` does the
same for output you already have on disk. The built-in rules pull out:

- web paths from gobuster, ffuf, feroxbuster, dirsearch and dirb, so every
  interesting hit (2xx or 3xx, or a juicy name like admin, backup, upload, .git)
  becomes a numbered attack vector;
- open ports from nmap;
- hostnames like `*.htb` and `*.local`, suggested for `pentrail resolve`;
- likely credentials (`user=`, `password:` and so on), written to the logbook;
- vulnerability signals, smart-tagged by type (see below).

Nothing is logged twice. Attack vectors are keyed by host and path, and creds and
hostnames are remembered in `state.json`. Run the same capture again and it says
"Nothing new, everything was already logged" instead of repeating itself. When some
of the output is new, it adds only that and notes how many known items it skipped.

Only one capture runs at a time. Start `pentrail capture foothold` from another terminal
while `recon` is still recording and it closes `recon` first, saving and parsing it.
Start it inside the recon shell and it asks you to `exit` recon first, because a
recorded shell cannot close the one it is running inside.

### Terminal screenshots in one step

`pentrail shot <command>` runs a command and keeps a terminal-screenshot PNG of it as
evidence, so you never run-then-screenshot-then-save-then-note by hand:

```bash
pentrail shot -l whoami id
pentrail shot -- smbclient -L //$TARGET/ -N
```

It runs the command once, renders a PNG with [termshot](https://github.com/homeport/termshot)
into `evidence/screenshots/<box>_<date>_<label>.png`, saves the text to
`evidence/output/`, logs it, scrubs your redacted secrets, and parses the output for
leads like any capture. No termshot installed means it still saves the text and
parses it; point `pentrail config termshot_cmd <cmd>` at another renderer if you use
one. Put your command's own flags after the command name (or after `--`).

To screenshot something you just ran interactively, without re-running it, do it
inside a capture and use `--last`:

```bash
pentrail capture recon        # work normally...
pentrail shot --last          # screenshot the output since your previous --last
pentrail shot --last 30       # or just the last 30 lines
```

`--last` reads the running capture's own recording, so it only works during a
capture: a tool cannot read your terminal's scrollback by itself.

### Keeping your own credentials out of captures

A capture records everything in the shell, so your own logins to tools would land in
the logbook too. Register your secrets once and pentrail scrubs them from then on:

```bash
pentrail redact add 'MyVaultPass!' my.ops.username   # your own creds/tokens
pentrail redact list                                 # count only
```

It stores only the SHA-256 of each value (never the value itself) and replaces any
matching token with `[REDACTED]` in every capture and ingest, in the saved evidence
file, and before anything is parsed, so your credentials are never logged or stored
as a finding. Adding one of them with `cred add` is refused as well. The list is
global (all projects) and needs no active project.

Two things worth knowing: passwords typed at a real prompt (ssh, sudo, login) are
not captured anyway because the terminal turns off echo, so this is mainly for
command-line creds and pasted tokens; and matching is per token, so prefer
`-p Secret` over the glued `-pSecret`.

### Smart tagging

It does not just file everything under "web". It reads the output for tell-tale
signs and tags the attack vector by vulnerability type, setting the strong ones to
`working` so they rise to the top. For example `root:x:0:0:` in a response becomes an
`lfi` path, a reflected SQL error becomes `sqli`, `uid=0(root)` output becomes `rce`,
a `NOPASSWD:` line from `sudo -l` becomes `sudo`, anonymous FTP becomes `ftp`, and so
on for smb, suid, default creds and CVE mentions. It is a hint from the output, not a
claim that something is exploitable; confirm it yourself.

### Attack vectors

Paths carry a type, so you can keep every class of exploit in one place, not just
recon and web. The types are free text; `capture`/`ingest` fill them in for you, and
you can set your own.

```bash
pentrail vectors                        # list, sorted: working, open, done, dead; type shown
pentrail vectors sqli                   # filter to one type
pentrail vector add "SQLi in login.php?id=" -t sqli   # add one by hand, with a type
pentrail vector working 3               # set its status (verb first)
```

Common types: web, sqli, lfi, rfi, rce, upload, xxe, ssrf, deserial, cred,
default-cred, brute, smb, snmp, nfs, ftp, kernel, privesc, suid, sudo, cron,
lateral, misc. Anything else works too.

`pentrail next` is the other half: after an nmap into `scans/`, it lists the standard
enumeration steps per open service with your target filled in, marks the ones whose
tool already shows up in your logbook as done, and points out any service you have
not touched at all. That last line is usually where the way in hides when you feel
stuck. The web brute-force step follows your config: `pentrail config web_tool
feroxbuster|ffuf|gobuster` and `pentrail config wordlist <path>` (default a SecLists
directory list).

### Credentials

Credentials are stored structured (user, secret, and a kind: username, password,
hash or ntlm), so they feed straight into spraying, brute-forcing and cracking.
`capture`/`ingest` pick them up automatically, including secretsdump
`user:rid:lm:nt:::` lines, and you can add your own.

```bash
pentrail creds                        # list, each shown by kind
pentrail cred add svc_sql:Summer2024  # user:pass, user:hash, or just a hash
pentrail creds users                  # one per line, pipe-friendly: > users.txt
pentrail creds hashes                 # just the hashes, for hashcat / rainbow tables
pentrail creds export                 # write users/passwords/hashes.txt to loot/ + print
                                      # ready netexec (spray/pass-the-hash), hydra, hashcat commands
```

### Flags

```bash
pentrail flag user 2f1c...9ab         # record an HTB flag; user/root also marks the box owned
pentrail flag                         # list the flags you have
```

### Project facts and focus

Keep the facts you keep reaching for, and a note of what you are on right now. The
domain is also detected automatically from nmap, SMB and LDAP output.

```bash
pentrail set domain blackfield.local  # also: dc-ip, base-dn, url, anything
pentrail set                          # list the facts
pentrail focus "LDAP enum for usernames"   # shown on the home screen and in status
```

### Report

When you are done, compile everything into one Markdown file for your write-up:

```bash
pentrail report            # writes report/report.md
pentrail report --mask     # same, but with credential secrets hidden, for sharing
```

It pulls together the meta block (target, domain, facts), a hosts table, attack
vectors grouped by status, a credentials table, flags, the full timeline and a list
of evidence files. Re-run it any time; it overwrites the file.

## Hosts and lateral movement

For multi-host or AD work, track where you are and how you got there:

```bash
pentrail host add 10.10.10.7 dc01 Windows   # track a host
pentrail host own 10.10.10.7                # mark it compromised
pentrail hosts                              # list, with OWNED flags
pentrail pivot 10.10.10.5 10.10.10.7 --via "pass-the-hash"
pentrail map                                # hosts plus the movement chain
```

## VPN

`pentrail up` needs root (openvpn creates the tun device and routes), so it asks for
your `sudo` password. openvpn then runs as a **background daemon**: it stays connected
after you close the terminal or exit pentrail, so you do not need a separate terminal
for it. `pentrail down` stops it; run `pentrail watch` in its own terminal if you want
it auto-restarted when it drops.

| Situation | Command |
|---|---|
| Start or reconnect | `pentrail up`, `pentrail restart` |
| Something is off | `pentrail check` (a concrete fix per problem) |
| It keeps dropping | `pentrail watch` (auto-restarts if the gateway fails 3 times) |
| Done for now | `pentrail down` |
| Box reset, new IP | `pentrail target <new-ip>` or `pentrail new <name> <new-ip>` |

`pentrail check` looks at duplicate openvpn processes, the tun IP, your internet, the
VPN gateway, whether the route to the target really goes through the tunnel, ping
and MTU. Then it reads the openvpn log for known errors (TLS timeout, AUTH_FAILED,
route conflict, missing tun device, the same .ovpn used on two machines) and prints
the fix for each.

## Command reference

`pentrail help` prints this grouped and `pentrail help <command>` gives the long
version of any one. Each command below shows its parameters, what it does, and an
example.

### Project and boxes

**`new <name> [ip]`** - create project `<name>` (folders, logbook, notes), make it
active, connect the VPN, and record/ping `[ip]` as the target if given.
`$ pentrail new blackfield 10.10.10.192`

**`use <name>`** - switch to an existing project without scaffolding or touching the
VPN. `<name>` is a project name or a path.
`$ pentrail use blackfield`

**`resume [name]`** - come back: switch (to `[name]`, or the most recent project),
reconnect the VPN if down, and print a recap of where you left off.
`$ pentrail resume`

**`list`** - list all projects; `*` marks the active one.
`$ pentrail list`

**`target <ip|name>`** - set the active box in the project (adds it if new); `$TARGET`
and new findings follow it.
`$ pentrail target web02`

**`dir`** - print the active project's folder path.
`$ cd "$(pentrail dir)"`

### VPN

**`up [file.ovpn]`** - connect; no file means default_vpn, else the last one, else pick.
`$ pentrail up`

**`down`** - disconnect the VPN. **`restart [file]`** - reconnect (same file unless you
pass one). **`status`** - show VPN state and the active project.
`$ pentrail restart`

**`check [ip]`** - diagnose the connection (processes, tun IP, internet, gateway,
route, ping, MTU) and print a concrete fix per problem. Reads only.
`$ pentrail check 10.10.10.192`

**`watch [seconds]`** - keep the VPN alive hands-off: every `[seconds]` (default 30) it
checks the tunnel and auto-restarts after 3 failed checks. Leave it in its own
terminal; Ctrl+C stops it.
`$ pentrail watch 20`

### Logbook and evidence

**`log [n]`** - show the logbook (last `n` lines, default all).
`$ pentrail log 20`

**`note <text>`** - add a timestamped line to the logbook.
`$ pentrail note "svc runs as SYSTEM"`

**`capture [label]`** - record this shell (via `script`) to
`evidence/terminal/<box>_<date>_<label>.log` and parse it for leads on `exit`. One at
a time; `label` is free text.
`$ pentrail capture privesc`

**`shot [-l label] <command>`** - run a command, save a termshot PNG + text as
evidence, log it, and parse the output. No manual screenshots.
`$ pentrail shot -l whoami id`

**`shot --last [lines]`** - during a capture, screenshot the output you just produced
(since the previous `--last`, or the last N lines).
`$ pentrail shot --last`

**`ingest <file>`** - parse an output file you already have, with the same rules and
de-duplication.
`$ pentrail ingest scans/gobuster_80.txt`

**`next`** - from your newest nmap in `scans/`, list enumeration steps per service,
tick off what you already did, and flag untouched services.
`$ pentrail next`

### Attack vectors, credentials, flags

**`vectors [type]`** - list attack vectors, sorted working > open > done > dead;
optionally filter by `type`.
`$ pentrail vectors sqli`

**`vector add "<desc>" [-t type]`** - add a vector by hand with an optional type
(auto-numbered id).
`$ pentrail vector add "SQLi in login.php?id=" -t sqli`

**`vector <status> <id>`** - set a vector's status; the status is the verb
(`open|working|dead|done`), like `host own`.
`$ pentrail vector working 3`

**`vector rm <id>`** - remove a wrong or mis-tagged vector.
`$ pentrail vector rm 4`

**`creds`** - list credentials by kind. **`creds users|passwords|hashes`** - print just
those values, one per line, to pipe to a file. **`creds export [dir]`** - write
`users/passwords/hashes.txt` and print spray/crack commands.
`$ pentrail creds export`

**`cred add <user:secret> [host]`** - store one credential (user:pass, user:hash, or a
lone hash). **`cred rm <n>`** - remove credential #n from `pentrail creds`.
`$ pentrail cred add svc_backup:Passw0rd`

**`flag <name> <value>`** - record an HTB flag (`user`/`root` also mark the box owned);
no value lists them.
`$ pentrail flag root 2f1c...9ab`

### Project context

**`set <key> <value>`** - keep a project fact (domain, dc-ip, base-dn, url, ...); no
args lists them, a key alone prints it. The domain is auto-detected too.
`$ pentrail set domain blackfield.local`

**`focus <text>`** - note what you are working on now; shown on the home screen and in
status. No text shows the current focus.
`$ pentrail focus "LDAP enum for usernames"`

**`redact add <value...>` / `redact list` / `redact clear`** - register your own
credentials/tokens so captures scrub them to `[REDACTED]`; stored as hashes, global.
`$ pentrail redact add 'MyVaultPass!' my.ops.username`

### Hosts and lateral movement

**`hosts`** - list hosts in the project with OWNED flags. **`host add <ip> [name] [os]`**
- track a host. **`host own <ip>`** - mark it compromised. **`host rm <ip|name>`** - stop
tracking it.
`$ pentrail host add 10.10.10.7 dc01 Windows`

**`pivot <from> <to> [--via note]`** - log lateral movement; adds the destination host
if new.
`$ pentrail pivot 10.10.10.5 10.10.10.7 --via "reused creds"`

**`map`** - show hosts plus the movement chain.
`$ pentrail map`

### Other

**`resolve [ip] <name...>`** - add `/etc/hosts` entries (ip defaults to the target);
`resolve --clean` removes the ones pentrail added.
`$ pentrail resolve dc01.htb`

**`report [--mask]`** - compile `report/report.md` from hosts, vectors, creds, flags,
facts, timeline and evidence; `--mask` hides credential secrets for sharing.
`$ pentrail report`

**`config [key] [value]`** - view or set config (base_dir, vpn_dir, default_vpn,
web_tool, wordlist, termshot_cmd, connect_timeout, stale_minutes, vpn_iface).
`$ pentrail config web_tool ffuf`

**`doctor`** - check the environment: core tools, screenshot renderer, enumeration
tools, config paths and wordlist, each marked ok/missing with an install hint.
`$ pentrail doctor`

**`setup [--yes] [--core-only] [--vpn-dir PATH] [--dry-run]`** - guided install: put
`pentrail` on `$PATH`, install missing tools with `apt`, set `vpn_dir`, and add the
`pcd` shell helper. Asks before each change; `sudo` only for install and `apt`.
`$ pentrail setup --yes`

**`update [--branch NAME] [--no-install] [--yes] [--dry-run]`** - update pentrail:
`git pull` the source checkout and reinstall the launcher so the new version runs.
`$ pentrail update --branch main`

**`help [command]`** - this reference, or the long help for one command.
`$ pentrail help watch`

**`version`** - print the version (also `pentrail --version`).
`$ pentrail version`
