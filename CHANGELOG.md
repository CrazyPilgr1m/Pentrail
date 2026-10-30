# Changelog

All notable changes to pentrail are recorded here. pentrail uses **point
releases**: every update bumps the version (1.0 → 1.1 → 1.2 …). The version lives
in `pentrail.py` (`VERSION`) and `pentrail version` prints it; `pentrail update`
shows the old → new version when it reinstalls.

## 1.8

A test suite, PeTe in Claude Code's status line, and a launcher check.

Added
- `tests/test_pentrail.py`: 30 tests, standard library only, run under a throwaway `$HOME`
  with no network and no sudo (`python3 -m unittest discover -s tests -v`). It covers the
  scope check exit codes, a blocked shot that never runs, a real capture, nmap ingest,
  password masking, the guardrail hook's decisions, the session brief, the status line,
  and `ai install` (twice, merged with your files, removed again, after edits, on a bad
  settings.json, with `ai_auto`). It also checks that no top-level name in pentrail.py is
  defined twice, so one function can't silently replace another (that nearly shipped in
  1.7). `.github/workflows/tests.yml` runs the suite on Python 3.8, 3.10 and 3.13.
- `pentrail ai statusline`: Claude Code's status line while PeTe works: project, active box,
  phase, open leads, what runs now and the scope guard. Wired in `ai/claude/settings.json`
  (`statusLine`); a status line of your own is kept when PeTe is installed. It only reads,
  and prints a plain `PeTe` rather than an error.
- `pentrail doctor` has a Launcher section: whether `pentrail` is on your PATH, and whether
  that copy is older than the pentrail you run doctor from.

Fixed
- Passwords on a tool's command line in a note or a logbook line (`netexec ... -p <pw>`,
  `xfreerdp /p:<pw>`) reached PeTe's session brief unmasked: password options were only
  masked when the program was known. With no program given, the options of every tool the
  text names are masked now.

## 1.7

Installing the AI layer: from your checkout onto the machine, and from there into a
project. Without `--ai`, the new `ai` commands or `ai_auto`, nothing changes.

Added
- `pentrail ai install [project]` (default: the active project) puts PeTe in the project
  folder: `CLAUDE.md`, `.claude/skills/` (12 skills) and `.claude/settings.json`, whose env
  gets `PENTRAIL_PROJECT=<the project>` next to `PENTRAIL_ACTOR=pete`, so PeTe's commands
  land in this project whichever project is active elsewhere. It inserts the PeTe rules
  once under "Rules of engagement" in `0-scope/scope.md`, and writes
  `.claude/pentrail-ai.json`: the installed version, a SHA-256 of every file it wrote and
  every settings entry it added. Running it again changes nothing. An existing `CLAUDE.md`
  is kept as `CLAUDE.md.bak`; an existing `.claude/settings.json` is merged (allow, ask and
  deny lists and hook groups joined, your env values and other keys kept), never
  overwritten. The project folder stays mode 700; the files are the same for every project
  and hold no secrets.
- `pentrail ai status [project|--all]`: the installed and the available version, missing
  files, hooks, rules and `PENTRAIL_PROJECT`, files you changed, whether the `pentrail` on
  your PATH can run the hooks (1.6 or newer), and whether Claude Code is installed. Exit 1
  when something is missing. `--all` lists every project with PeTe.
- `pentrail ai update [project|--all]`: the available PeTe into a project. A file of
  PeTe's you changed is kept as `.bak`; a skill the layer no longer has is removed when you
  did not change it.
- `pentrail ai remove [project]`: removes only what `ai install` wrote and you did not
  change since, puts your `CLAUDE.md` back from `CLAUDE.md.bak`, and takes PeTe's entries
  out of `.claude/settings.json` (deleting the file only when PeTe created it and nothing
  else is left). The PeTe rules stay in `scope.md`.
- `pentrail new <name> ... --ai` puts PeTe in the new project; `pentrail config ai_auto on`
  makes that the default, and `--no-ai` skips it once. Off by default.
- `pentrail setup`, step 5 "AI layer for Claude Code": copies the checkout's `ai/` folder
  to `~/.local/share/pentrail/ai` with a `.stamp.json` (version, source, time); `--no-ai`
  skips it. `ai install` takes the layer next to the script it runs from, then this copy,
  then the `ai/` folder of `src_repo`; when there is none it says how to get it.
- `pentrail update` refreshes that copy when you have one and names the projects with an
  older PeTe (`pentrail ai update --all`). `pentrail uninstall` removes the copy and never
  touches the projects that have PeTe; its new `--no-launcher` keeps the launcher.
- Run interactively, `pentrail setup` asks whether to turn on `auto_shot` (and, with the AI
  layer, `ai_auto`). Both stay off unless you say yes; `--yes` leaves them off.

Changed
- The guardrail hook now also denies the pentrail commands that change PeTe's own
  guardrails or hand it your shell (`scope add|in|out|exclude|guard`,
  `config scope_guard|scope_allow|pete_rules`, `ai install|update|remove`, `capture`,
  `redact`, `setup`, `update`, `upgrade`, `uninstall`), whatever the permission rules say.
  `ai/claude/settings.json` denies the bare forms of these commands too (such as
  `pentrail ai remove` with no project).
- `config auto_shot|pete_rules|ai_auto` take on or off (true/false, yes/no and 1/0 work
  too) and store on or off.
- `setup` and `uninstall` mark their steps with section headers.
- The AI layer is version 1.7 (`ai/VERSION`).

## 1.6

The AI layer's guardrail and session brief, auto-shot for your own captures, and a
friendlier terminal. pentrail stays fully usable without the AI layer.

Added
- `pentrail ai hook pretooluse`: the guardrail Claude Code runs before every Bash command
  and web fetch PeTe makes. It reuses pentrail's scope guard on the command line and
  denies: commands aimed at hosts outside the scope (or with no scope set); commands aimed
  at in-scope hosts that do not go through `pentrail shot` (with the exact
  `pentrail shot -q --by pete -l <label> -- <cmd>` to use instead); scope overrides
  (`scope-ok`, `PENTRAIL_SCOPE_OK`); edits of `0-scope/`, the logbook, `state.json`,
  `CLAUDE.md` and `.claude/`; and tools the PeTe rules deny (hydra, medusa, sqlmap,
  msfconsole, impacket attack scripts, nmap brute, exploit and dos scripts, ...), also inside
  a `pentrail shot`. Tools the rules mark `ask` (nikto, nuclei, vuln scripts, `sudo`,
  credentials on the command line) get a permission prompt. pentrail's own commands, local
  work and tooling hosts get no decision, so Claude Code's permission rules decide. Every
  stop goes to the logbook as `hook blocked: ... (by pete)`. No project in the folder, or
  input it cannot read: a warning, nothing blocked. stdlib only; the only network use is
  the DNS lookups the scope guard already does.
- `pentrail ai hook sessionstart` and `pentrail ai brief`: the session brief, a compact
  factual page (under 60 lines, never credentials) with the project, phase, active box,
  scope and guard, the PeTe rules, the rules of engagement, hosts with open ports and their
  plan (per-port steps and coverage to do), what runs now, open leads, findings and the last
  ten logbook lines. The hook adds it to PeTe's context, greets you with a one-line status
  and names the session after the project.
- `ai/claude/settings.json` wires both hooks: PreToolUse (Bash and WebFetch) with
  `onFailure: block`, so a guard that fails blocks the call; SessionStart for every way a
  session starts, compaction included.
- `pentrail config auto_shot on`: in a capture, every command that finds something (a port,
  web path, hostname, lead, credential or fact) is kept as a screenshot of its command line
  and output (`<phase>/evidence/<box>_<date>_found-<tool>.txt`, and a PNG rendered in the
  background when termshot is installed). The command record links it, `pentrail trace`
  marks it, and a finding made from it lists it as evidence. Off by default; no AI needed.
- A friendlier terminal: a new logo, PeTe's face for the `ai` commands, a project card on
  the home screen and in `status` and `resume` with the next step to take, a checklist with
  progress bar and "next up" in `next`, a recording card when a capture starts, symbols
  (✔ ✖ ⚠ ➜ ○ ◉) with a plain `[+] [*] [!] [-]` fallback when the terminal is not UTF-8,
  and no colours when `NO_COLOR` is set.

Changed
- Messages, `doctor`, `scope check`, the capture shell's after-command line and the help
  overview use the symbols above. `scope check` ends with whether the guard clears it.

## 1.5

The AI layer itself: PeTe's prompt, skills, rules and Claude Code settings, in `ai/`.

Added
- `ai/claude/CLAUDE.md`: PeTe's master prompt. Rule 0 (pentrail decides what is in scope;
  every target command runs as `pentrail shot -q --by pete`), the learning-first style (why,
  a link to read more, what to look for), "PeTe drives / the tester drives", never
  repeating what `pentrail seen` reports, the ask-before and never lists.
- `ai/claude/skills/`: 12 skills, each `SKILL.md` with a name and a description of when to
  use it: `pentrail-session`, `methodology`, `scope-guard`, `pentrail`, `enum-run`,
  `recon-passive`, `recon-active`, `service-enum`, `web-enum`, `ad-enum`, `vuln-triage`,
  `report-finding`. Scope, recon, enumeration, triage and reporting only; no exploitation.
- `ai/claude/rules.md`: the PeTe rules, the allow / ask / deny list per activity that goes
  under "Rules of engagement" in `0-scope/scope.md`.
- `ai/claude/settings.json`: the Claude Code permissions for a project (allow pentrail's
  read-only commands and `pentrail shot -q --by pete`; ask for findings, the report,
  changes of phase, target or project, credentials and sudo; deny scope changes and
  overrides, `capture`, edits of the scope, logbook and PeTe's own instructions, and
  reading `state.json` and `loot/`), and `PENTRAIL_ACTOR=pete`.
- `ai/README.md` (what the layer is, how to install it, how the guardrails stack),
  `ai/TERMS.md` (authorized testing only; you own every command PeTe runs) and
  `ai/THIRD-PARTY-NOTICES.md` (the ideas adapted from four MIT-licensed projects, with
  their copyright lines).
- `pentrail config pete_rules on`: new projects get the PeTe rules in `0-scope/scope.md`
  without the AI layer.

Changed
- A command that carries an actor (`shot --by`, `PENTRAIL_ACTOR`) can no longer override
  the scope guard: `scope-ok` and `PENTRAIL_SCOPE_OK=1` are refused with exit 3, and the
  logbook records a "refused override".
- The report's rules of engagement leave the PeTe rules out.

## 1.4

Read back what ran, for you and for an AI assistant working next to you, without
rerunning anything.

Added
- `pentrail seen <host> <tool|nse-script|text>`: exit 0 and the matching commands when
  it already ran against that host, 1 when not. ffuf, feroxbuster, gobuster, dirsearch,
  dirb and wfuzz count as one tool (netexec/nxc/crackmapexec and enum4linux/-ng too); an
  nmap script name matches `--script` lists (`-sC` counts as `default`); anything else is
  looked for in the command line. `full-tcp`, `versions`, `udp` and `vhosts` ask the
  coverage checks.
- `pentrail trace [-H host] [-t tool] [--json]`: per host, every command with id, time,
  phase, who ran it, its source (capture = `evidence/*.log`, shot = `evidence/*.txt`,
  ingest = `scans/*`), exit code and output file. Range scans are listed under every
  host in them, and commands whose results landed on a host are listed under it.
- `pentrail show <id> [-n lines]`: the recorded output of one command, ANSI stripped,
  from its command line on (default 200 lines, `-n 0` for all). Commands from a capture
  now remember the lines they span in the recording; older ones are found by searching.
- Coverage checks next to the per-port playbook in `next`: full TCP port scan, service
  versions on every open TCP port, UDP top ports, and virtual host fuzzing when there is
  a web port, each with a ready command. `next` takes a host (`pentrail next 10.10.10.6`)
  and `--json` (the plan with every step's source, playbook or coverage, done or not, and
  the commands that did it).
- `pentrail hosts [host] --json`: hosts with ports, names, web paths, leads and notes.
- Commands in flight: a `shot` registers itself while its tool runs
  (`.pentrail-running.json` in the project), and the command running in your capture is
  read from its recording. `seen`, `trace` and `next` show them as running.
- `PENTRAIL_PROJECT=<path|name>` pins a shell or an AI session to a project; `use`,
  `new` and `resume` there warn that they only move your other terminals.
- No credentials in JSON: stored secrets, your redacted values and password arguments
  (`-p`, `-H <hash>`, `--password`, `user:pass@host`, `-U user%pass`, ...) are masked as
  `[secret]` in every JSON output and in `trace` and `seen`.

Changed
- `next` ticks a step only for commands aimed at that host: `10.10.10.5` no longer
  matches inside `10.10.10.50`, a host's DNS names count, and so does a range scan that
  holds the host (unless it `--exclude`s it). The same goes for the checklist in enum.md.
- `next` shows a Coverage block under the per-port steps, and its Progress line counts it.

Fixed
- Your own redacted secrets typed on a command line ended up in state.json, in the
  docs' "Commands run" tables and in the logbook: only the output was scrubbed. Command
  lines and logbook lines are now scrubbed too.
- `pentrail help` ran a 30-character command into its description (`pivot`).

## 1.3

The first building blocks of the AI layer for Claude Code: quiet runs, who ran a
command, and scope answers a script can read.

Added
- `pentrail shot -q` (`--quiet`): saves, redacts and parses as usual, but prints only
  "Saved:" and what was new, and exits with the tool's own exit code (a signal is
  128+n). Exit 3 always means "blocked by the scope guard": a tool's own 3 becomes 1,
  and BLOCKED still goes to stderr. Scope warnings that do not block go to stderr.
- Who ran a command: `shot --by <name>`, or the `PENTRAIL_ACTOR` environment variable
  for any pentrail command, records an actor (an AI assistant, a script) in the command
  record's existing `via` field. It shows in the logbook (`... (by pete)`), in "Found by"
  (docs, `pentrail hosts`, `pentrail names`) and as a By column in the commands tables of
  the phase docs and the report appendix. The column only appears once someone other
  than you ran something; older state.json files load unchanged.
- `pentrail scope check --json`: the verdicts as JSON (`status`, `exit`, `guard`, and per
  target its `verdict`, `text` and `why`).

Changed
- `pentrail scope check` exits with the result: 0 everything is in scope (or your own
  machine or a tooling host), 3 something is out of scope, not in scope or a conflict, 2
  no host found, 4 no scope set. It used to exit 0.
- `scope check` takes a command line with its options without quotes or `--`
  (`pentrail scope check nmap -sV 10.10.10.5`).

Fixed
- Two pentrail processes on one project at once (a capture and a `shot` or `note` in
  another terminal, or an AI assistant working next to you) overwrote each other's
  results in state.json: of 20 shots run in parallel, 2 were kept. Every
  read-change-save now holds a per-project lock (`.pentrail.lock`, an flock the
  kernel drops when a process dies), and all 20 are kept. The capture shell's check
  before each command does not wait for it, and long steps (the capture shell itself,
  the tool a `shot` runs, the PDF export) run without holding it.
- A capture's after-command update could undo a `scope guard` switch typed inside
  that capture, and `shot --last` could move the capture's read position back.
- `shot` crashed on tool output that is not valid UTF-8; it now keeps it with
  replacement characters.

## 1.2

Added
- Project folders per methodology phase (`0-scope` … `5-report`), each with a Markdown
  working doc. pentrail fills the auto blocks between its markers and never touches
  your own text. `pentrail phase` and `pentrail docs`.
- Scope in `0-scope/scope.md` (IPs, CIDRs, ranges, domains, `*.domain`, URLs; in and
  out of scope). `pentrail scope add|out|check|guard`. `new` accepts several targets,
  domains included, and `--no-vpn`.
- Scope guard in the capture shell (zsh and bash): commands aimed at hosts outside the
  scope are stopped before they run; `scope-ok <cmd>` overrides once. Blocks and
  overrides are logged. `shot` is checked too. `--exclude` lists are honoured.
- Guard modes: `strict` (stop), `warn` (report and log, let it run) and `off`. Set it
  with `pentrail scope guard` (the setting), per capture with `capture --warn` /
  `--guard`, or switch a running capture by typing `pentrail scope guard` inside it.
- Names and DNS: with an IP or range scope, hostnames are looked up (during captures,
  and for all known names with `pentrail scope resolve`). Names whose addresses all
  fall in scope join it ("Resolved into the scope" in scope.md). Conflicts are listed
  in scope.md and stopped by the guard: an out-of-scope name inside an in-scope range,
  an in-scope name pointing at an out-of-scope address, a name partly inside the
  scope, and entries that are both in and out.
- Per-command capture: each command is recorded with time, duration, exit code and
  folder, with variables filled in. Output is read after every command, so docs and
  lookups are current during the capture. Every port, path, name and lead keeps the
  command that found it ("Found by").
- More output understood: nmap versions/OS/hostnames (normal, greppable and XML),
  rustscan, masscan, ffuf (words and vhosts), dirsearch, dirb, wfuzz, gobuster
  vhost/dns, amass, dnsx, subdomain tool lists, httpx, whatweb, nuclei, nikto, and
  curl/wget status. Ports are now stored per host.
- Findings: `pentrail finding <vector-id|"title"|F01>` writes
  `5-report/findings/F01-….md` with severity, weakness, asset, the command, the output
  and the evidence. `F01` prints it clean for a bug bounty submission.
- Report template `5-report/report.md`, filled by `pentrail report`: details, scope and
  rules, findings overview and findings, a walkthrough from the phase docs, and an
  appendix. Your own sections are kept. `--html` exports a styled page and `--pdf`
  a PDF when chromium, wkhtmltopdf or pandoc is installed.
- Notes: `pentrail note [-t host] "<text>"` puts a note on the active box (or another
  host, or the project), with its phase and the last command in the capture. Notes
  show in `notes.md` by host and under "Logged notes" in the host's section of
  enum.md; hosts, leads (#3), findings (F01) and notes (N2) they mention become links,
  with "mentioned in" backlinks. `pentrail notes [host] | edit | rm`.
- `pentrail hosts <host>` (detail view) and `pentrail names [--plain]`.
- `pentrail ingest` and `next` read `1-enum/scans/` automatically; nmap files supply
  their own command line as "Found by".

Changed
- One command per noun: `vector`/`vectors`, `cred`/`creds`, `finding`/`findings`,
  `hosts`/`map` are aliases, and with no arguments each one lists.
- `.env` exports its variables; the capture shell sets `$TARGET` itself.
- `next` uses the ports pentrail knows per host and ticks steps from recorded commands
  against that host. The same checklist is in `1-enum/enum.md`.
- Web paths are all documented in `enum.md`. Only interesting ones (admin, backup,
  upload, .git, …) become leads.
- Help and home screen rebuilt around the five everyday commands.
- state.json schema 2, migrated automatically from older projects.

## 1.1

Added
- `pentrail setup` — guided install: put `pentrail` on `$PATH`, install missing
  tools via `apt`, set `vpn_dir`, discover a directory wordlist already on the
  machine, and add the `pcd` shell helper. `--yes`, `--core-only`, `--vpn-dir`,
  `--no-tools`/`--no-launcher`/`--no-shell`, `--dry-run`.
- `pentrail update` — `git pull` the source checkout and reinstall the launcher so
  the new version is the one that runs. Finds the checkout from where it runs, the
  current directory, or `src_repo` in config.
- `pentrail uninstall` — undo `setup`: remove the launcher and `pcd` helper;
  `--config` also removes config + VPN state. Offers to stop a running VPN first.
  Pentest projects are never deleted.
- Wordlist discovery (`find_wordlists`) across the known Kali/Linux dirs, used by
  `setup` and `doctor`.

Changed
- `doctor` shares one tool registry with `setup`, shows `apt` hints for the
  enumeration tools, and points at `pentrail setup` when tools are missing.
- `pentrail up` announces the root requirement and primes `sudo` best-effort;
  documented that openvpn runs as a persistent `--daemon` (no separate terminal).

Fixed
- Capture no longer re-ingests pentrail's own output: a command run inside a
  capture (e.g. `pentrail log`) is bracketed with an invisible marker and stripped
  before parsing, so reviewing findings mid-capture is never re-logged.
- `resolve --clean` was rejected by argparse and could never run.
- `load_config` / `load_state` crashed on valid-JSON-but-non-object files.
- `new .` / `new ..` scaffolded into and `chmod 700`'d the parent of `base_dir`.
- `new` left a half-made project (no `.env`/state/notes) when the VPN failed to
  come up; it now scaffolds fully before touching the VPN.
- `report` / `capture` crashed on a `use`-adopted project missing `report/` or
  `evidence/terminal/`.
- `parse_intel` stored junk credentials from URLs (`http://host:8080/x`) and
  comma/semicolon-joined `user=/pass=` fields.
- `pick_vpn` accepted `0`/negative picks; `capture` crashed on `os.kill` of
  another user's pid; removed a shadowed duplicate `cmd_flag`; `config <int-key>
  <non-int>` dumped a traceback; `resolve` claimed success before the sudo write.

## 1.0

- Initial pentrail: one-command engagement start (VPN + evidence folders), a
  running timestamped logbook, `capture`/`shot`/`ingest` that parse tool output
  into attack vectors, structured credentials, flags, hosts and lateral movement,
  project facts/focus, `next` enumeration suggestions, `check`/`watch` VPN
  diagnostics, operator-secret redaction, and `report`.
