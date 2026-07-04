# fortibleed-check

Offline exposure and IoC check for FortiGate devices against the **FortiBleed**
credential-harvesting campaign (disclosed June 2026).

FortiBleed is **not** a new CVE. It is a campaign exploiting weak hardening:
internet-facing management, missing MFA, weak (pre-PBKDF2) password hashing
and brute force. Source: Fortinet PSIRT (Carl Windsor, 2026-06-19), *"Analysis
of Reported Credential Compromise of FortiGate Devices"*.

These tools review a FortiGate **configuration** for the known exposure
factors, and look for IoC signs of actual compromise (suspicious admin
accounts, SSH keys, automation persistence). They are deliberately
conservative and are **not** an exhaustive security audit — a clean result
does not prove a device was never compromised.

## Tools

| Script | Input |
| --- | --- |
| `fortibleed_check_offline.py` | Terminal log or full config backup — file or directory |
| `fortibleed_check_fortimanager.py` | Pulls configs live from FortiManager (JSON-RPC API) |

Both are Python 3.9+ **standard library only** — no install step, runs on
air-gapped machines. `requirements.txt` and `make_venv.sh` exist for tooling
convenience; a plain `python3` works.

## Quick start (offline)

Collect input in one of two ways:

1. **Terminal log** — paste the commands from `fortibleed_commands.txt` into
   the FortiGate CLI while your SSH client logs the session, save as `.txt`.
2. **Config backup** — a full configuration backup/export works directly.

Then:

```console
$ python3 fortibleed_check_offline.py device.txt          # one device
$ python3 fortibleed_check_offline.py ./configs/           # a directory of them
$ python3 fortibleed_check_offline.py ./configs/ --details # + full per-device report
$ python3 fortibleed_check_offline.py device.txt --json    # machine-readable
$ python3 fortibleed_check_offline.py --list-checks        # what gets checked
```

## Quick start (FortiManager)

Fill in the CONFIGURATION block at the top of the script, or use flags/ENV
(`FMG_HOST`, `FMG_API_KEY`, `FMG_ADOM`). Requires an API key for an admin
with `rpc-permit` (FortiManager 7.2.2+).

```console
$ python3 fortibleed_check_fortimanager.py --host https://fmg.example.net --apikey KEY
$ python3 fortibleed_check_fortimanager.py --adom production --json
$ python3 fortibleed_check_fortimanager.py --selftest   # offline pipeline test, no network
```

## What is checked

Exposure: firmware vs. PBKDF2-capable password hashing, management protocols
on interfaces (allowaccess), admin and REST-API trusthost restrictions, admin
MFA, legacy-hash purge setting, residual `set old-password` SHA-256 hashes,
private-data-encryption, FortiCloud SSO login (CVE-2026-24858), password
policy, brute-force lockout, SSL-VPN exposure, VPN-user MFA, and local-in
policy lockdown. IoC: admin names on known suspicious lists, SSH public keys
on admins, and suspicious automation scripts/callbacks.

Run `--list-checks` for the ids, and skip checks that do not apply to your
environment with `--skip-checks id1,id2` (e.g. `--skip-checks admin-mfa`).

## Allowlist and `--review`

Deliberately exposed management interfaces (e.g. a dedicated, firewalled
mgmt port) can be acknowledged so they stop showing up as findings:

```console
$ python3 fortibleed_check_offline.py ./configs/ --review
```

Answers are stored in `mgmt_allowlist.txt` (`hostname:interface`, `*` for all
devices) next to the input, and can be edited by hand.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Not affected — no exposure or IoC signs found |
| 1 | Review warnings, or incomplete input |
| 2 | Exposed — one or more critical findings |
| 3 | Operational error (bad path, unreachable FortiManager, ...) |

In batch mode the exit code reflects the worst device, so the tools compose
into cron jobs and ticket automation.

## Caveats

The assessment is an automated snapshot of configuration state. It highlights
known FortiBleed exposure factors; it is neither an exhaustive audit nor a
guarantee that a device is not, or has not been, compromised. Keep monitoring
logs and check for direct notifications from Fortinet.

Config backups and terminal logs contain password hashes and other secrets —
treat collected input files as sensitive and do not commit them to the repo
(see `.gitignore`).

## License

MIT — see `LICENSE`.
