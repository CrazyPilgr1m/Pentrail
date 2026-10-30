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
├── notes.md                  your quick notes, by host, linked to hosts, leads and findings
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
pentrail scope check https://blog.acme.com             # in scope? (only checks, runs nothing)
pentrail scope resolve                                 # look up known names, list conflicts
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

`pentrail scope check` takes hosts, URLs or a whole command line
(`pentrail scope check nmap -sV 10.10.10.5`, no quotes needed) and answers with its exit
code too, so scripts can use it: `0` everything is in scope (or is your own machine or a
tooling host), `3` something is out of scope, not in scope or a conflict, `2` no host
found, `4` no scope set. `--json` prints the verdicts.

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

### Names in your IP ranges, and conflicts

When the scope is IPs or ranges, names count by where they point. A capture that
finds a hostname without an address looks it up in DNS first, and
`pentrail scope resolve` looks up every name pentrail knows. A name whose addresses all
fall inside the in-scope IPs counts as in scope and is listed in `scope.md` under
**Resolved into the scope**. Names nmap already printed with their IP need no lookup.

The same lookups expose contradictions, listed in `scope.md` under **Scope conflicts**
and shown by `pentrail scope`:

| Situation | What pentrail does |
|---|---|
| Scope `10.10.10.0/24`, but out-of-scope `blog.acme.com` resolves to `10.10.10.30` | `10.10.10.30` is a conflict: commands on it are stopped, and so is a scan of the whole range unless it leaves the IP out (`nmap ... --exclude 10.10.10.30`). Settle it by listing `10.10.10.30` under In scope or Out of scope. |
| `*.acme.com` in scope, but `intranet.acme.com` resolves into out-of-scope `10.0.0.0/8` | the name is a conflict and commands on it are stopped |
| A name resolves partly inside the scope (`1.1.1.1`) and partly outside it (`1.0.0.1`) | a conflict, because traffic may go either way |
| An entry is both in and out (`app.acme.com` in, `*.acme.com` out) | listed; out of scope wins |
| An in-scope name points outside your IP ranges | a note: test it by name, not by IP |

### Blocking or informative

The guard has three modes: `strict` stops out-of-scope commands (the default), `warn`
only reports them, and `off` does not check. In `warn` mode the command runs, you see
which host is outside the scope, and the logbook keeps a `warned:` line, so you still
have the record. Results about out-of-scope hosts are not logged in either mode.

You choose the mode in three places:

```bash
pentrail scope guard warn          # the setting, for every capture (same as: pentrail config scope_guard warn)
pentrail capture recon --warn      # this capture only (or --guard strict|warn|off)
pentrail scope guard strict        # typed inside a running capture: switches that capture now
```

Inside a capture, `scope guard` changes only that capture and leaves the setting alone.
`pentrail scope` shows which mode is in effect.

To run one command anyway in `strict` mode, prefix it: `scope-ok <command>`. The
override is logged. Local commands that only handle text (`echo`, `grep`, `cat`,
editors and similar) are never stopped, and neither is your own machine or tooling
sites like github.com. The guard works in zsh (Kali's default) and bash. In other
shells, or with `pentrail capture --plain`, the session is recorded without it.

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
pentrail seen 10.10.10.5 gobuster   # already run against that host? exit 0 + the commands, 1 if not
pentrail trace -H 10.10.10.5   # what ran: time, phase, who, capture/shot/ingest, output file
pentrail show 12               # the output of command #12 again, from its command line on
```

`seen` treats ffuf, feroxbuster, gobuster, dirsearch, dirb and wfuzz as one tool, and
also takes an nmap script name (`ssl-cert`, `smb-vuln-*`; `-sC` counts as `default`) or
any text in the command line (`-p-`, `raft-medium`). A range scan counts for every host
in it, unless it left the host out with `--exclude`. A command that is still running
counts too, so you never start the same scan twice.

### Notes, linked to your targets

```bash
pentrail note "admin panel on :8080, try the same login on 10.10.10.6 - see #3"
pentrail note -t 10.10.10.6 "SSH open; test the creds from N1 here"
pentrail note -t none "client: no active scans after 17:00"
pentrail notes                  # all notes
pentrail notes 10.10.10.6       # its own notes plus the ones that mention it
pentrail notes edit 2 "..."     # or: pentrail notes rm 2
```

A note goes on the active box unless you name another host (`-t`), or on the project
with `-t none`. It remembers the phase and, inside a capture, the command you ran last.
Every note shows up in `notes.md`, grouped by host, and under **Logged notes** in that
host's section of `1-enum/enum.md`. Whatever a note mentions becomes a link: hosts (IP,
name or alias) link to their section, `#3` to the lead, `F01` to the finding file and
`N2` to the other note. Each host also lists the notes that mention it. The links are
normal Markdown links, so they work on GitHub, in VS Code and in other editors. Longer
notes of your own go under **Your notes** in `notes.md`, or in the **Notes** section of
any doc.

### Screenshots

`pentrail shot <command>` checks the command against the scope, runs it, and keeps a
PNG (via [termshot](https://github.com/homeport/termshot)) and the text in the current
phase's `evidence/`. Its output is read with this command as "Found by". During a
capture, `pentrail shot --last` screenshots what you just ran, without running it again.
Without termshot it keeps the text evidence. `pentrail shot -q` keeps the terminal quiet
and exits with the tool's own exit code; see [AI layer](#ai-layer-claude-code).

**Auto-shot.** With `pentrail config auto_shot on`, a capture keeps every command that
finds something (a new port, web path, hostname, lead, credential or fact) as a
screenshot: its command line and its output, as `<phase>/evidence/<box>_<date>_found-<tool>.txt`
and, when termshot is installed, as a PNG rendered in the background so your prompt comes
back at once. The capture shell shows `◉ evidence: ...` under the command, `pentrail trace`
marks the command with `◉`, and a finding made from it lists the screenshot as evidence. No
AI involved; it is off until you turn it on.

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

Every action lands in `logbook.md` with a time and a tag: captures, new leads, notes,
scope blocks, warnings and overrides, phase changes, findings and reports.
`pentrail log` shows it.

## AI layer (Claude Code)

pentrail ships its own AI layer for Claude Code in [`ai/`](ai/README.md): **PeTe**, an
assistant that works the pentrail way from the first message, for scoping, recon,
enumeration, triage and reporting. It does not exploit anything. Everything it runs goes
through the same scope guard as your own commands, is recorded with its output, and is
marked as PeTe's. You stay responsible for every command it runs ([ai/TERMS.md](ai/TERMS.md)).

**PeTe is optional.** pentrail does everything in this README on its own; nothing about
the AI layer shows up until you install it in a project. Without it, pentrail is the same
tool it always was.

### Putting PeTe in a project

```bash
pentrail setup                       # step 5 copies ai/ to ~/.local/share/pentrail/ai
pentrail new box1 10.10.10.5 --ai    # a new project with PeTe in it
pentrail ai install [project]        # or an existing one (default: the active project)
cd ~/pentests/box1 && claude         # and trust the folder when Claude Code asks
```

`pentrail ai install` writes `CLAUDE.md`, `.claude/skills/` (12 skills) and
`.claude/settings.json` into the project folder, adds the PeTe rules once under "Rules of
engagement" in `0-scope/scope.md`, and records what it installed in
`.claude/pentrail-ai.json` (the version, a hash of every file, every settings entry it
added). The settings set `PENTRAIL_ACTOR=pete` and `PENTRAIL_PROJECT=<the project>`, so
what PeTe runs is marked as its own and lands in this project, whichever project is active
in your terminals. Running it again changes nothing. A `CLAUDE.md` of your own is kept as
`CLAUDE.md.bak`; a `.claude/settings.json` of your own is merged (rule lists and hooks
joined, your values kept), never overwritten. The project folder stays mode 700, and the
files hold no secrets: they are the same for every project.

- `pentrail ai status [project]`: the installed and the available version, and anything
  missing (files, hooks, the rules, a `pentrail` on your PATH that can run the hooks).
  Exit 1 when something is. `--all` lists every project with PeTe.
- `pentrail ai update [project|--all]`: brings a project to the PeTe you have. A file of
  PeTe's that you changed is kept as `.bak` next to the new one.
- `pentrail ai remove [project]`: takes out only what `ai install` put in (not files you
  changed since), puts your own `CLAUDE.md` back and takes PeTe's entries out of your
  settings. The PeTe rules stay in `scope.md`.
- `pentrail config ai_auto on`: `pentrail new` puts PeTe in every new project, as with
  `--ai`; `--no-ai` skips it once. Off by default.

The layer comes with the pentrail you run: the `ai/` folder next to `pentrail.py` when you
run it from the checkout, else setup's copy in `~/.local/share/pentrail/ai`, else the `ai/`
folder of the checkout setup remembered (`pentrail config src_repo`). `pentrail update`
refreshes setup's copy and `pentrail uninstall` removes it; neither touches your projects.

### What it does in a session

When PeTe is installed in a project, Claude Code calls two pentrail hooks:

- **The guardrail** (`pentrail ai hook pretooluse`) runs before every Bash command and web
  fetch PeTe makes. It stops a command aimed at a host outside the scope, and a command
  aimed at an in-scope host that does not go through `pentrail shot` (so it would not be
  checked or recorded): PeTe gets the exact `pentrail shot -q --by pete ...` command to use
  instead. It also stops scope overrides, edits of `0-scope/`, the logbook, `state.json` and
  PeTe's own files, and the tools the PeTe rules deny (hydra, sqlmap, msfconsole, nmap brute
  scripts, ...); for tools they mark `ask` (nikto, nuclei, vuln scripts, `sudo`, credentials
  on the command line) you get a permission prompt. PeTe never runs the pentrail commands
  that change its own guardrails (`scope add|out|guard`, `config scope_guard|pete_rules`,
  `capture`, `ai install|update|remove`, `setup`, `update`, `uninstall`), whatever the
  permission rules say. Everything else gets no decision from
  the hook, so Claude Code's own permission rules decide. Every stop is in the logbook as
  `hook blocked: ... (by pete)`, and a guard that fails blocks instead of letting the call
  through.
- **The session brief** (`pentrail ai hook sessionstart`) puts a compact page into PeTe's
  context when a session starts: project, phase, scope and guard, the PeTe rules, the
  rules of engagement, hosts with their plan, what is running, open leads, findings and the
  last logbook lines, never credentials. You get a one-line greeting, and the session is
  named after the project. `pentrail ai brief` prints the same page for you.
- **The status line** (`pentrail ai statusline`) sits under Claude Code's prompt the whole
  session: `PeTe ◕‿◕ · box1 · box 10.10.10.5 · enum · 2 open lead(s) · ◷ 1 running ·
  guard strict`. A `statusLine` of your own in the project settings is kept.

What the layer holds: PeTe's master prompt (`ai/claude/CLAUDE.md`: Rule 0, how it teaches,
what it asks before and never does), 12 skills (session start, methodology, scope guard,
pentrail, enumeration rounds, passive and active recon, services, web, Active Directory,
triage, findings and the report), the Claude Code permissions (`ai/claude/settings.json`)
and the **PeTe rules** (`ai/claude/rules.md`).

The PeTe rules say what the assistant may run on its own (`allow`, after one "go" per
round), only after your yes (`ask`), or never (`deny`), per activity: passive recon, port
scans and their rate, service enumeration, web content discovery, vulnerability scripts,
credentialed enumeration, root commands, brute force, password spraying, exploitation and
denial of service. They live under "Rules of engagement" in `0-scope/scope.md`, and you
edit them per project. `pentrail config pete_rules on` puts them into new projects even
without the AI layer; the report leaves them out of its rules of engagement.

The building blocks in pentrail itself:

- **Quiet runs.** `pentrail shot -q --by <name> -l <label> -- <command>` runs a command
  the way `shot` always does (scope check, evidence file, parsing), but prints only where
  the output was saved and what was new, and exits with the tool's own exit code. Exit `3`
  is kept for "blocked by the scope guard" (a tool's own `3` becomes `1`), and the BLOCKED
  message goes to stderr. Scope warnings that do not block also go to stderr.
- **Who ran it.** `--by <name>`, or `PENTRAIL_ACTOR=<name>` in the environment, records who
  ran a command, in the command record's `via` field. It shows in the logbook
  (`... (by pete)`), in "Found by" in the docs and in `pentrail hosts`, and as a By column
  in the commands tables of the phase docs and the report appendix. Commands you run
  yourself carry no name, and the tables only get the column once someone else ran
  something. A command with an actor can never override the scope guard: `scope-ok` and
  `PENTRAIL_SCOPE_OK=1` are refused (exit 3) and logged as a refused override.
- **Side by side.** You and the assistant can work on the same project at the same time:
  your capture in one terminal, its shots in another. Every change to `state.json` holds
  a per-project lock, so neither overwrites the other's results, and `next` ticks a step
  no matter who ran it.
- **What ran, and what runs now.** `pentrail seen <host> <tool>`, `pentrail trace` and
  `pentrail show <id>` let the assistant check what was already done (by you or by it)
  and read the output again instead of rerunning a scan. Commands in flight count: a
  `shot` registers itself while it runs, and the command running in your capture is read
  from its recording. `seen` reports both as "running now".
- **Plans as JSON.** `pentrail next [host] --json` gives the per-port playbook plus the
  coverage checks (full TCP scan, `-sV` on every open TCP port, UDP top ports, virtual
  hosts when there is a web port), each step marked done with the ids of the commands
  that did it. `pentrail hosts --json` and `pentrail trace --json` give hosts and
  commands. No JSON output ever holds a credential: stored secrets, your redacted values
  and password arguments (`-p`, `--password`, `user:pass@host`, `-H <hash>`, ...) become
  `[secret]`.
- **One project per session.** `PENTRAIL_PROJECT=<project>` (a path or a name) pins a
  shell or an assistant's session to its project, so `pentrail use` in another terminal
  does not move it.
- **Scope answers in exit codes.** `pentrail scope check` exits `0` (in scope), `3` (out of
  scope, not in scope or a conflict), `2` (no host found) or `4` (no scope set), and
  `--json` gives the verdicts:

```json
{
  "input": "nmap -sV 10.10.10.5 8.8.8.8",
  "status": "out",
  "exit": 3,
  "guard": "strict",
  "targets": [
    {"target": "10.10.10.5", "verdict": "in", "text": "in scope", "why": ""},
    {"target": "8.8.8.8", "verdict": "unknown", "text": "not in scope", "why": ""}
  ],
  "notes": []
}
```

## Install

```bash
python3 pentrail.py setup          # guided; --yes for unattended, --dry-run to look first
```

`setup` puts `pentrail` on your `$PATH`, installs missing tools with `apt`, sets
`vpn_dir`, finds a directory wordlist if the configured one is missing, adds the
`pcd` shell helper (`cd` into the project with `$TARGET` set) and, optionally, copies the
AI layer to `~/.local/share/pentrail/ai` (`--no-ai` skips that). It asks before every
change and uses `sudo` only for the install and `apt` steps. Run interactively, it also
asks whether to turn on `auto_shot`. By hand:
`sudo install -m 755 pentrail.py /usr/local/bin/pentrail`.

`pentrail update` pulls the source checkout, reinstalls the launcher and refreshes the AI
layer's copy if you have one. `pentrail uninstall` removes the launcher, the shell helper
and the AI layer's copy (`--no-launcher` keeps the launcher); your projects are never
deleted, and PeTe stays in the projects that have it. Config lives in `~/.config/pentrail/config.json` and VPN state in
`~/.local/state/pentrail/`.

`pentrail doctor` checks the tools, your config and the `pentrail` on your PATH: when that
copy is older than the checkout you run doctor from, it says so (`pentrail update`).

Run pentrail as your normal user. It calls `sudo` itself only for openvpn and
`/etc/hosts`, and the capture shell always runs as you.

In a UTF-8 terminal pentrail draws its logo, project card and checklists with symbols
(✔ ✖ ⚠ ➜ ○); elsewhere it falls back to plain `[+] [*] [!] [-]`. Colours appear only on a
terminal, and never when `NO_COLOR` is set.

## VPN

`pentrail up` connects (openvpn runs as a root daemon that stays up after the terminal
closes), `down` disconnects and `restart` reconnects. `status` shows the state,
`check [ip]` diagnoses the tunnel and prints a fix per problem, and `watch` restarts the
VPN when it hangs. `new` connects automatically unless you pass `--no-vpn` or have no
`.ovpn` files (bug bounty work usually needs no VPN).

## Command reference

| Command | What it does |
|---|---|
| `new <name> [target...] [--no-vpn] [--ai\|--no-ai]` | create a project: phase folders, docs, scope, VPN; `--ai` with PeTe |
| `resume [name]` / `use <name>` | come back (with VPN and recap) / switch projects |
| `list` | all projects |
| `target <host>` | set the active box (IP or hostname) |
| `phase [name]` | show or set the phase |
| `docs` | list the working docs, refresh them |
| `scope [add\|out\|check\|resolve\|guard]` | the scope, DNS lookups and conflicts, and the guard |
| `scope check [--json] <host\|cmd>` | in scope? exit 0 in, 3 out / not in scope / conflict, 2 no host, 4 no scope |
| `capture [phase] [--warn] [--plain]` | record a shell: scope guard, per-command docs |
| `shot [-q] [--by name] [-l label] <cmd>` / `shot --last` | screenshot evidence; `-q` quiet, tool's exit code; `--by` who ran it |
| `ingest <file>` | read a saved tool output |
| `next [host] [--json]` | enumeration checklist for the active box (or a host), with coverage checks |
| `seen <host> <tool\|script\|text>` | already run (or running) against that host? exit 0 yes, 1 no |
| `trace [-H host] [-t tool] [--json]` | what ran per host: time, phase, who, source, output file |
| `show <id> [-n lines]` | the recorded output of one command |
| `hosts [host] [--json]` / `names [--plain]` | look up hosts, ports, web paths, hostnames |
| `vector(s) [type]`, `vector add\|<status>\|rm` | leads |
| `cred(s)`, `cred add\|rm\|users\|passwords\|hashes\|export` | credentials |
| `finding [<id>\|"title"\|F01] [-s sev]` | findings |
| `report [--mask] [--html] [--pdf]` | fill and export the report |
| `host add\|own\|rm`, `pivot <from> <to>` | hosts and movement |
| `note [-t host] <text>`, `notes [host]\|edit\|rm` | quick notes, linked to hosts, leads, findings |
| `flag`, `set`, `focus`, `log` | flags, facts, focus, logbook |
| `redact add\|list\|clear` | keep your own secrets out of captures |
| `up`, `down`, `restart`, `status`, `check`, `watch` | VPN |
| `resolve [ip] <name...>` / `resolve --clean` | `/etc/hosts` entries |
| `config [key] [value]` | settings: base_dir, vpn_dir, scope_guard, scope_allow, author, web_tool, wordlist, auto_shot, pete_rules, ai_auto, ... |
| `ai install\|update\|remove [project]` | PeTe (optional): put it in a project, update it, take it out |
| `ai status [project\|--all]`, `ai update --all` | installed vs available, what is missing; update every project |
| `ai brief` / `ai hook pretooluse\|sessionstart` / `ai statusline` | PeTe: the session brief; the hooks and the status line Claude Code runs |
| `doctor`, `setup`, `update`, `uninstall`, `version`, `help` | housekeeping |

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Standard library only, under a throwaway `$HOME`, with no network traffic and no `sudo`. The
suite covers the scope guard and its exit codes, a real capture, parsing, password masking, the guardrail
hook, the session brief, and installing, merging and removing the AI layer. GitHub Actions
runs it on Python 3.8, 3.10 and 3.13 (`.github/workflows/tests.yml`).
