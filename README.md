# pentrail, the pentest logbook

`pentrail` gets a pentest session going in one command and then does the paperwork
for you. It lays out a project folder per methodology phase, keeps a Markdown working
doc in each phase that fills itself, guards your scope, and builds the report from
what you recorded.

`pentrail capture` records the shell you work in. Every command is kept with its time,
and before it runs pentrail checks that its hosts are in scope. Out-of-scope commands
are stopped. The output of every command that touches a target is read: ports with
service versions, web paths, hostnames and subdomains, and leads. Each one is written
into the docs straight away, together with the command that found it. You look things
up instead of running scans again, and every finding already has its proof of concept
command.

It is for labs, engagements and bug bounty programs you are authorized to test (HTB,
OffSec, a scoped client engagement, a public program). Pure Python 3 (3.8+), standard
library only, so there is nothing to `pip install`. Built for Kali/Linux.

## Quickstart

```bash
python3 pentrail.py setup               # install to PATH + missing tools + config
pentrail new box1 10.10.10.5            # project + scope + VPN + docs
cd "$(pentrail dir)" && source .env     # $TARGET is now set
pentrail capture recon                  # work here: scans are scope-checked and documented
pentrail next                           # what to enumerate next (also in 1-enum/enum.md)
pentrail finding 3                      # lead #3 is confirmed: write it up
pentrail report --html                  # 5-report/report.md + a styled report.html
```

Five commands cover a whole box: `new`, `capture`, `next`, `finding` and `report`.
Everything else is there for when you need it. Run `pentrail` with no arguments for the
home screen, `pentrail help` for all commands and `pentrail help <command>` for one.

## A project on disk

```
~/pentests/box1/
├── 0-scope/scope.md          what you may test; the capture shell enforces it
├── 1-enum/enum.md            per host: ports, web paths, hostnames, leads, checklist
│   ├── scans/                nmap -oN/-oX and other tool files (read automatically)
│   └── evidence/             recordings and screenshots made in this phase
├── 2-foothold/foothold.md    \
├── 3-privesc/privesc.md       > Summary, Steps, Result, Notes + commands run + evidence
├── 4-lateral/lateral.md      /   (lateral.md also shows the host chain)
├── 5-report/
│   ├── findings/F01-...md    one file per finding
│   └── report.md             the report template, filled by 'pentrail report'
├── loot/                     exported credential lists
├── logbook.md                the timestamped timeline of everything
├── state.json                what pentrail knows (hosts, ports, names, leads, commands)
└── .env                      export TARGET, VPN_IP, ENG  (source it)
```

The project folder is `chmod 700`, because `loot/` and `state.json` hold credentials.

### Docs you write in, with blocks that fill themselves

Every doc is plain Markdown. pentrail only writes between its own markers:

```markdown
### Ports & services
<!-- pentrail:auto ports 10.10.10.5 -->
| Port | Service | Version | Found by |
|---|---|---|---|
| 80/tcp | http | Apache httpd 2.4.41 | `nmap -sC -sV 10.10.10.5` (2026-10-16 10:02) |
<!-- pentrail:end ports 10.10.10.5 -->

### Notes
Anything you write here, or anywhere outside the markers, is yours and stays.
```

The blocks are refreshed whenever pentrail learns something, also during a capture,
after each command. In the enumeration checklist you can tick items by hand; pentrail
ticks them too when it sees the step run against that host, and never unticks yours.
`pentrail docs` lists the docs and recreates any you deleted. Projects from older
versions get the folders and docs the first time you `use` or `resume` them; nothing
is moved or overwritten.

### Phases

The phase decides where captures and screenshots go and which doc lists the commands.
`pentrail capture privesc` switches to that phase and records into `3-privesc/evidence/`.
`pentrail phase` shows where you are, and `pentrail phase lateral` changes it. Short
names work too: `recon` and `web` mean enum, `pe` and `root` mean privesc, `pivot` means
lateral.

## Scope

The scope lives in `0-scope/scope.md`. Write it, paste a bug bounty program's scope
into it, or use the commands:

```bash
pentrail new acme '*.acme.com' api.acme.io --no-vpn   # targets become "in scope"
pentrail scope add 10.10.10.0/24                       # more in scope
pentrail scope out blog.acme.com                       # explicitly out of scope
pentrail scope                                         # show it, with the guard mode
pentrail scope check ffuf -u https://blog.acme.com/FUZZ   # would this be allowed?
```

```markdown
## In scope
- *.acme.com          main program
- api.acme.io
- 10.10.10.0/24

## Out of scope
- blog.acme.com       third party
```

One asset per line, and the first word is the asset. Accepted: an IP, a CIDR range, an
IP range (`10.10.10.1-50`), a domain, a wildcard (`*.acme.com`, which covers the
subdomains but not `acme.com` itself) or a URL. An out-of-scope URL with a path, like
`https://acme.com/blog`, excludes only that path.

What the scope does:

- **The capture shell stops commands that point outside it.** Before a command runs,
  pentrail finds the hosts in it (IPs, ranges, domains, URLs, `user@host`, with `$TARGET`
  and your other variables filled in) and checks each one. If a host is out of scope
  or not listed, the command does not run, you see why, and the block goes into the
  logbook. Hostnames that point at an in-scope IP count as in scope: aliases pentrail
  saw, `/etc/hosts` entries, or `pentrail resolve`.
- **Only in-scope results are logged.** Anything a tool prints about other hosts is
  counted and left out.
- **Results land on the right host.** A gobuster run against host B while host A is
  active files its paths under B.

To run one command anyway, prefix it: `scope-ok <command>`. The override is logged.
Local commands that only handle text (`echo`, `grep`, `cat`, editors and similar)
are never stopped, and neither is your own machine or tooling sites like github.com.
`pentrail scope guard warn` only warns, `off` disables the guard, and `strict` is the
default. The guard works in zsh (Kali's default) and bash. In other shells, or with
`pentrail capture --plain`, the session is recorded without it.

## Capturing a shell

```bash
pentrail capture recon     # or: foothold, privesc, lateral, any label
...work as usual...
exit                       # the recording is saved and read
```

The recording is saved as `<phase>/evidence/<box>_<date>_<label>.log`. Inside a capture:

- Every command is recorded with start time, duration, exit code and folder. Commands
  that touch a target appear under **Commands run** in the phase doc.
- After each command that touches a target, the output is read and the docs are
  updated, and a short line shows what was added. `pentrail hosts 10.10.10.5`, run in
  the same shell, already shows the new ports.
- `$TARGET`, `$VPN_IP` and `$ENG` are set without `source .env`.
- pentrail's own output (when you run `pentrail log` or `pentrail hosts` inside) is
  never read back as findings.
- Only one capture runs at a time. Starting one in another terminal closes the first.

What the reader understands: nmap normal, greppable and XML output (ports, versions,
OS, and hostnames from redirects and certificates), rustscan and masscan, the usual
content-discovery tools (gobuster, ffuf, feroxbuster, dirsearch, dirb, wfuzz),
vhost and subdomain tools (gobuster vhost/dns, ffuf with a `Host: FUZZ` header,
subfinder, amass, dnsx and similar), httpx and whatweb, nuclei and nikto, curl and wget
status lines, and the generic signs the earlier versions already knew (credentials,
domain names, vulnerability signals). Tools it does not know still give the general
results: ports, URLs and hostnames in scope.

`pentrail ingest <file>` reads a saved output the same way. Files in `1-enum/scans/` are
read automatically by `next`, `report` and at the end of a capture. nmap files carry
their own command line, so `nmap -oN` output also gets a proper "Found by".

### Looking things up instead of running them again

```bash
pentrail hosts                 # every host: OS, owned, open ports
pentrail hosts 10.10.10.5      # one host: ports + versions + who found them, web, names, leads
pentrail names                 # hostnames and subdomains in scope
pentrail names --plain         # one per line, to feed other tools
pentrail vectors               # leads, working > open > done > dead
```

### Screenshots

`pentrail shot <command>` checks the command against the scope, runs it, and keeps a
PNG (via [termshot](https://github.com/homeport/termshot)) and the text in the current
phase's `evidence/`. Its output is read with this command as "Found by". During a
capture, `pentrail shot --last` screenshots what you just ran, without running it again.
Without termshot it keeps the text evidence.

### Your own secrets stay out

```bash
pentrail redact add 'MyVaultPass!' my.ops.username
```

pentrail stores only the SHA-256 of each value and replaces matching tokens with
`[REDACTED]` in every capture, shot and ingest, before anything is read or saved.

## Findings and the report

When a lead turns out to be real, turn it into a finding:

```bash
pentrail finding 3                                   # from lead #3
pentrail finding "Exposed .git directory" -s low     # or from a title
pentrail finding                                     # list, by severity
pentrail finding F01                                 # print it clean, ready to paste
```

A finding is `5-report/findings/F01-<title>.md` with a fixed structure: severity, CVSS,
asset, weakness (CWE), status and date, then **Summary**, **Steps to reproduce**,
**Impact**, **Remediation** and **Evidence**. pentrail fills in what it knows: the asset,
a starting severity and weakness from the lead's type, the exact command that found it,
the output, and the recording it is in. You write the summary, impact and fix. The
same structure is what bug bounty platforms ask for, so `pentrail finding F01` gives
you a submission to paste.

`pentrail report` fills `5-report/report.md`, the report template:

| Section | Where it comes from |
|---|---|
| Project details | project, date, tester (`pentrail config author "Your Name"`), testing period, hosts |
| Executive summary | you |
| Scope | in/out of scope and the filled-in rules of engagement from `scope.md` |
| Methodology | default text, yours to change |
| Findings overview | count per severity and a table of all findings |
| Findings | every finding file, sorted by severity |
| Walkthrough | hosts and services, plus what you wrote in the phase docs |
| Conclusion & recommendations | you |
| Appendix | hosts and ports, hostnames, credentials, flags, commands, evidence, timeline |

Your own sections are kept when you run it again. `--mask` hides credential secrets
and flags (for sharing). To export it:

```bash
pentrail report --html     # 5-report/report.html: styled, print it to PDF from a browser
pentrail report --pdf      # also report.pdf, via chromium, wkhtmltopdf or pandoc if installed
```

## Hosts and lateral movement

```bash
pentrail host add 10.10.10.7 dc01 Windows   # track a host (captures add them too)
pentrail host own 10.10.10.7                # mark it compromised
pentrail pivot 10.10.10.5 10.10.10.7 --via "reused SSH key"   # appears in lateral.md
pentrail target dc01                        # the active box; $TARGET follows
```

## Credentials and flags

```bash
pentrail creds                    # list, by kind
pentrail cred add svc_sql:Summer2024
pentrail creds users              # one per line, pipe-friendly
pentrail creds export             # users/passwords/hashes.txt into loot/
pentrail flag user 2f1c...9ab     # user/root also marks the box owned
```

## The logbook

Every action lands in `logbook.md` with a time and a tag: captures, new leads, scope
blocks and overrides, phase changes, findings and reports. `pentrail log` shows it and
`pentrail note "<text>"` adds a line.

## Install

```bash
python3 pentrail.py setup          # guided; --yes for unattended, --dry-run to look first
```

`setup` puts `pentrail` on your `$PATH`, installs missing tools with `apt`, sets
`vpn_dir`, finds a directory wordlist if the configured one is missing, and adds the
`pcd` shell helper (`cd` into the project with `$TARGET` set). It asks before every
change and uses `sudo` only for the install and `apt` steps. By hand:
`sudo install -m 755 pentrail.py /usr/local/bin/pentrail`.

`pentrail update` pulls the source checkout and reinstalls the launcher.
`pentrail uninstall` removes the launcher and the shell helper; your projects are
never deleted. Config lives in `~/.config/pentrail/config.json` and VPN state in
`~/.local/state/pentrail/`.

Run pentrail as your normal user. It calls `sudo` itself only for openvpn and
`/etc/hosts`, and the capture shell always runs as you.

## VPN

`pentrail up` connects (openvpn runs as a root daemon that stays up after the terminal
closes), `down` disconnects and `restart` reconnects. `status` shows the state,
`check [ip]` diagnoses the tunnel and prints a fix per problem, and `watch` restarts the
VPN when it hangs. `new` connects automatically unless you pass `--no-vpn` or have no
`.ovpn` files (bug bounty work usually needs no VPN).

## Command reference

| Command | What it does |
|---|---|
| `new <name> [target...] [--no-vpn]` | create a project: phase folders, docs, scope, VPN |
| `resume [name]` / `use <name>` | come back (with VPN and recap) / switch projects |
| `list` | all projects |
| `target <host>` | set the active box (IP or hostname) |
| `phase [name]` | show or set the phase |
| `docs` | list the working docs, refresh them |
| `scope [add\|out\|check\|guard]` | the scope and the guard |
| `capture [phase] [--plain]` | record a shell: scope guard, per-command docs |
| `shot [-l label] <cmd>` / `shot --last` | screenshot evidence |
| `ingest <file>` | read a saved tool output |
| `next` | enumeration checklist for the active box |
| `hosts [host]` / `names [--plain]` | look up hosts, ports, web paths, hostnames |
| `vector(s) [type]`, `vector add\|<status>\|rm` | leads |
| `cred(s)`, `cred add\|rm\|users\|passwords\|hashes\|export` | credentials |
| `finding [<id>\|"title"\|F01] [-s sev]` | findings |
| `report [--mask] [--html] [--pdf]` | fill and export the report |
| `host add\|own\|rm`, `pivot <from> <to>` | hosts and movement |
| `flag`, `set`, `focus`, `note`, `log` | flags, facts, focus, logbook |
| `redact add\|list\|clear` | keep your own secrets out of captures |
| `up`, `down`, `restart`, `status`, `check`, `watch` | VPN |
| `resolve [ip] <name...>` / `resolve --clean` | `/etc/hosts` entries |
| `config [key] [value]` | settings: base_dir, vpn_dir, scope_guard, scope_allow, author, web_tool, wordlist, ... |
| `doctor`, `setup`, `update`, `uninstall`, `version`, `help` | housekeeping |

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release.
