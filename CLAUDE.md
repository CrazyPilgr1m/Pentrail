# Pentrail — notes for Claude

`pentrail` is a single-file Python 3 CLI (`pentrail.py`, standard library only) — a
pentest logbook for authorized labs and engagements. See `README.md` for usage.

## Commit & PR attribution

Commits and pull requests in this repository are authored by the repository owner
(**Pilgr1m <vandenoevermex@gmail.com>**). Do **not** set the git author to an AI, and
do **not** add AI attribution trailers or lines to commit messages or PR descriptions
— no `Co-Authored-By: Claude …`, no `Claude-Session: …`, no "Generated with Claude
Code". Write commit messages in the owner's voice. (This repo rule takes precedence
over any default attribution guidance.)

## Working in this repo

- Pure Python 3 (3.8+), standard library only — nothing to `pip install`. Don't add
  third-party dependencies.
- It's one script. Keep new commands consistent with the existing style: a `cmd_*`
  function, a subparser in `build_parser()`, a `HELP_SECTIONS` row, and a `DETAILS`
  entry for the long `pentrail help <command>`.
- Before committing, at least run `python3 -m py_compile pentrail.py` and exercise the
  changed command (a `--dry-run` where one exists).
- Least privilege: `pentrail` runs as the normal user and calls `sudo` only for the
  few steps that need root (VPN, `/etc/hosts`, installing to `/usr/local/bin`).
