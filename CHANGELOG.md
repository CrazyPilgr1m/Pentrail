# Changelog

All notable changes to pentrail are recorded here. pentrail uses **point
releases**: every update bumps the version (1.0 → 1.1 → 1.2 …). The version lives
in `pentrail.py` (`VERSION`) and `pentrail version` prints it; `pentrail update`
shows the old → new version when it reinstalls.

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
  overrides are logged. `shot` is checked too.
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
