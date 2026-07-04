#!/usr/bin/env python3
"""
fortibleed_check_offline — FortiBleed exposure check for FortiGate configs (offline).

Reads terminal output collected with the commands in fortibleed_commands.txt,
or a full FortiGate configuration file (backup/export), and assesses whether a
FortiGate — based on its CURRENT CONFIGURATION — could be affected by the
"FortiBleed" campaign (disclosed June 2026).

FortiBleed is NOT a new CVE/vulnerability. It is a credential-harvesting
campaign exploiting weak hardening: internet-facing management, missing MFA,
weak password hashing and brute force. Source: Fortinet PSIRT (Carl Windsor,
2026-06-19), "Analysis of Reported Credential Compromise of FortiGate Devices".

This tool therefore assesses EXPOSURE (configuration) and looks for IoC signs
of actual compromise (unauthorized accounts etc.). It is deliberately
conservative: any management exposure without trusthost/MFA is flagged.
It is NOT an exhaustive security audit, and a clean result is not proof that a
device is, or has never been, compromised.

Input may be a terminal log (the commands from fortibleed_commands.txt run at
the CLI prompt) OR a full config file (backup/export without prompt lines).
Both formats — and a whole directory of them — are handled automatically.

Usage:
    python3 fortibleed_check_offline.py <file_or_directory>
    python3 fortibleed_check_offline.py <config.conf>
    python3 fortibleed_check_offline.py <directory> --recursive
    python3 fortibleed_check_offline.py <file> --no-color --json
    python3 fortibleed_check_offline.py <directory> --review
    python3 fortibleed_check_offline.py <file> --skip-checks admin-mfa,password-policy
    python3 fortibleed_check_offline.py --list-checks

Exit codes:
    0  not affected — no exposure or IoC signs found
    1  review warnings, or incomplete input (missing command output)
    2  exposed — one or more critical findings
    3  operational error (bad path, unreadable input, nothing matched)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Callable, NoReturn

__version__ = "2.0.1"

# ---------------------------------------------------------------------------
# FortiBleed campaign context
# ---------------------------------------------------------------------------

CAMPAIGN = "FortiBleed (June 2026)"

# Known suspicious admin account names (IoC). A match yields a WARN.
# Compiled from Fortinet advisories and community-published IoC lists.
SUSPICIOUS_ADMIN_NAMES = {
    "fortios", "forti_admin", "support", "tech_support",
    "admin_backup", "system", "watchtowr",
    "forticloud", "fortiuser", "fortinet-support", "fortinet-tech-support",
    "fortinet_support", "fortigate-support", "support-fortinet",
}

# Management protocols on allowaccess that expose login surfaces to
# brute force / credential reuse.
MGMT_PROTOCOLS = {"http", "https", "ssh", "telnet"}
# telnet is always plaintext. http is only plaintext when admin-https-redirect
# is disabled — by default FortiOS redirects http -> https before login, so the
# login itself happens encrypted.
PLAINTEXT_ALWAYS = {"telnet"}
PLAINTEXT_IF_NO_REDIRECT = {"http"}

# PBKDF2 hashing of admin credentials was backported to specific releases
# (not whole branches): 7.2.11, 7.4.8, 7.6.1, and everything in 8.0+. Older
# versions store weaker SHA-256 hashes that are easier to crack from an
# extracted config (the core of FortiBleed).
# Source: Fortinet Document Library / community KB 220652.
PBKDF2_MIN_VERSION = {
    (7, 2): (7, 2, 11),
    (7, 4): (7, 4, 8),
    (7, 6): (7, 6, 1),
}

# The "purge old hashes" setting. Its name depends on the FortiOS version:
#   - login-lockout-upon-downgrade          -> FortiOS 7.2 and 7.4
#   - login-lockout-upon-weaker-encryption  -> FortiOS 7.6+
# It lives under 'config system password-policy' (not system global).
WEAKER_LOCKOUT_KEYS = ("login-lockout-upon-weaker-encryption",
                       "login-lockout-upon-downgrade")

# Interface-name fragments that suggest an internet-facing interface.
WAN_NAME_HINTS = ("wan", "internet", "outside", "isp", "ppp", "ext")

# Exit codes — two families, kept apart so automation can tell "the tool
# found something" from "the tool could not run". Mirrored in the docstring.
# (argparse itself exits 2 on bad flags; if that collision matters to your
# wrapper scripts, branch on stderr as well.)
EXIT_OK = 0      # not affected
EXIT_WARN = 1    # review warnings / incomplete
EXIT_FAIL = 2    # exposed — critical findings
EXIT_ERROR = 3   # operational failure — bad path, no matches, unreadable

# ANSI colour codes. RESET closes any code; the *_C names tag severities.
RESET = "\033[0m"
BOLD = "\033[1m"
OK_C = "\033[92m"
WARN_C = "\033[93m"
BAD_C = "\033[91m"
INFO_C = "\033[94m"
DIM_C = "\033[90m"


def col(text: str, code: str, color: bool) -> str:
    """Wrap text in an ANSI code, or return it untouched when colour is off."""
    return f"{code}{text}{RESET}" if color else text


def want_color(no_color_flag: bool) -> bool:
    """Colour only on a live terminal; honour both --no-color and the
    NO_COLOR environment convention (https://no-color.org)."""
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def die(message: str, code: int = EXIT_ERROR) -> NoReturn:
    """Report an operational failure on stderr and exit — no traceback."""
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(code)


def now_iso() -> str:
    """One timestamp format everywhere, so reports and JSON never drift."""
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(parts) != 4:
        return True
    a, b = parts[0], parts[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or a == 127
            or (a == 169 and b == 254)
            or (a == 100 and 64 <= b <= 127)
            or a == 0)


def parse_sections(content: str) -> dict[str, str]:
    """Split FortiGate terminal output into one section per command.
    Prompt shape: <hostname> [(<mode>)] # <command>"""
    sections: dict[str, list[str]] = {}
    current_cmd: str | None = None
    for line in content.splitlines():
        line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
        line = line.rstrip('\r')
        m = re.match(r'^\S+\s+(?:\(\S+\)\s+)?#\s+(.+)', line)
        if m:
            current_cmd = m.group(1).strip()
            sections.setdefault(current_cmd, [])
        elif current_cmd is not None:
            sections[current_cmd].append(line)
    return {cmd: '\n'.join(lines).strip() for cmd, lines in sections.items()}


def parse_full_config(content: str) -> dict[str, str]:
    """Parse a full FortiGate configuration file (backup/export, no prompt lines).

    Extracts top-level 'config <path> ... end' blocks and stores them under
    synthetic keys ('show <path>' and 'show full-configuration <path>') so the
    same checks work unchanged. Also synthesizes a 'get system status' section
    from the #config-version header and hostname. Returns {} when the content
    does not look like a FortiGate config.
    """
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', content)
    lines = text.splitlines()

    sections: dict[str, str] = {}
    depth = 0
    cur_path: str | None = None
    buf: list[str] = []

    def store(path: str, body: str):
        for key in (f"show {path}", f"show full-configuration {path}"):
            sections.setdefault(key, body.strip())

    for raw in lines:
        line = raw.rstrip('\r')
        if re.match(r'^\s*config\s+\S', line):
            if depth == 0:
                cur_path = re.match(r'^\s*config\s+(.+?)\s*$', line).group(1).strip().strip('"')
                cur_path = re.sub(r'\s+', ' ', cur_path)
                buf = []
                depth = 1
                continue
            depth += 1
        elif re.match(r'^\s*end\s*$', line):
            if depth == 1:
                if cur_path is not None:
                    store(cur_path, "\n".join(buf))
                depth = 0
                cur_path = None
                buf = []
                continue
            if depth > 1:
                depth -= 1
        if depth >= 1 and cur_path is not None:
            buf.append(line)

    has_header = "#config-version=" in text
    if not sections:
        return {}

    if has_header:
        # Synthesize 'get system status' from #config-version + hostname.
        m = re.search(r'#config-version=(\S+?)-(\d+)\.(\d+)\.(\d+)', text)
        if m:
            model = m.group(1)
            ver = f"v{m.group(2)}.{m.group(3)}.{m.group(4)}"
            gl = sections.get("show full-configuration system global", "")
            hm = re.search(r'set hostname\s+"?([^"\n]+?)"?\s*$', gl, re.MULTILINE)
            host = hm.group(1).strip() if hm else "unknown"
            sections.setdefault(
                "get system status",
                f"Version: {model} {ver},build0000 (GA)\nHostname: {host}")

        # In a full config an absent section means "not configured" (not
        # "not collected") -> mark expected sections as empty so the checks
        # report INFO/PASS instead of SKIP.
        for path in ("system interface", "system admin", "system api-user",
                     "system password-policy", "system global", "vpn ssl settings",
                     "user local", "firewall local-in-policy",
                     "system automation-action", "system automation-trigger"):
            sections.setdefault(f"show {path}", "")
            sections.setdefault(f"show full-configuration {path}", "")

    return sections


def find_section(sections: dict[str, str], *candidates: str) -> tuple[str | None, str | None]:
    """Return (key, output) for the first command that matches (also partially)."""
    for cmd in candidates:
        for key, val in sections.items():
            if key == cmd or key.startswith(cmd + " ") or key.startswith(cmd):
                return key, val
    return None, None


def _split_edit_blocks(out: str) -> dict[str, str]:
    """Split a 'config ... edit "x" ... next ... end' body into {name: block}.

    Depth-aware: entries can contain nested 'config ... end' sub-tables (e.g.
    'config gui-dashboard' inside an admin account in full-configuration
    output) whose own 'edit N'/'next' lines must NOT be mistaken for
    top-level entries. Only edit/next at nesting depth 0 are boundaries;
    nested lines stay part of the surrounding entry's block."""
    result: dict[str, str] = {}
    name = None
    buf: list[str] = []
    depth = 0  # nesting depth of 'config ... end' INSIDE the current entry
    for line in out.splitlines():
        if re.match(r'\s*config\s+\S', line):
            # A 'config' line outside any entry is the section's own outer
            # wrapper (terminal output includes it; extracted config bodies
            # do not) — it does not count as nesting.
            if name is not None or depth > 0:
                depth += 1
        elif re.match(r'\s*end\s*$', line) and depth > 0:
            depth -= 1
        elif depth == 0:
            m = re.match(r'\s*edit\s+"?([^"\n]+?)"?\s*$', line)
            if m:
                if name is not None:
                    result[name] = "\n".join(buf)
                name = m.group(1).strip()
                buf = []
                continue
            if re.match(r'\s*next\s*$', line) and name is not None:
                result[name] = "\n".join(buf)
                name = None
                buf = []
                continue
        if name is not None:
            buf.append(line)
    if name is not None:
        result[name] = "\n".join(buf)
    return result


def _get_set(block: str, key: str) -> str | None:
    """Fetch the value of 'set <key> ...' in a config block (unquoted)."""
    m = re.search(rf'set\s+{re.escape(key)}\s+(.+)', block)
    if not m:
        return None
    return m.group(1).strip().strip('"')


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------

class CheckResult:
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"

    def __init__(self, name: str, status: str, detail: str):
        self.name = name
        self.status = status
        self.detail = detail


def missing(name: str) -> CheckResult:
    return CheckResult(name, CheckResult.SKIP,
                       "Command output not found in the file — was the command run?")


# ---------------------------------------------------------------------------
# Checks — EXPOSURE
# ---------------------------------------------------------------------------

def parse_firmware(sections: dict[str, str]) -> tuple[int, int, int] | None:
    _, out = find_section(sections, "get system status")
    if out is None:
        return None
    m = re.search(r"Version\s*:\s*\S+\s+v(\d+)\.(\d+)\.(\d+)", out, re.IGNORECASE)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def pbkdf2_supported(ver: tuple[int, int, int]) -> bool:
    """Does this exact version support PBKDF2 hashing of admin credentials?
    Backported to 7.2.11, 7.4.8, 7.6.1; everything in 8.0+ supports it."""
    if ver[0] >= 8:
        return True
    branch = (ver[0], ver[1])
    minv = PBKDF2_MIN_VERSION.get(branch)
    return minv is not None and ver >= minv


def check_firmware(sections: dict[str, str]) -> CheckResult:
    """Older versions store weaker SHA-256 admin hashes (no PBKDF2)."""
    if find_section(sections, "get system status")[1] is None:
        return missing("Firmware / password hash strength")
    ver = parse_firmware(sections)
    if ver is None:
        return CheckResult("Firmware / password hash strength", CheckResult.INFO,
                           "Could not parse the firmware version")
    ver_str = "v{}.{}.{}".format(*ver)
    if not pbkdf2_supported(ver):
        return CheckResult(
            "Firmware / password hash strength", CheckResult.WARN,
            f"Running {ver_str} — this version stores admin credentials as SHA-256 "
            f"(pre-PBKDF2). An extracted config is therefore easier to crack (the "
            f"core of FortiBleed). Upgrade to at least 7.2.11 / 7.4.8 / 7.6.1 or 8.0+.",
        )
    return CheckResult(
        "Firmware / password hash strength", CheckResult.PASS,
        f"Running {ver_str} — PBKDF2-capable firmware (verify old hashes are "
        f"purged; see 'Legacy password hashing' and 'Residual SHA-256 hash').",
    )


def _interface_blocks(sections: dict[str, str]) -> dict[str, str] | None:
    _, out = find_section(sections, "show system interface", "show full system interface")
    if out is None:
        return None
    return _split_edit_blocks(out)


def https_redirect_enabled(sections: dict[str, str]) -> bool:
    """Does FortiOS redirect http -> https? Default (no explicit setting) = yes."""
    _, g = find_section(sections, "show full-configuration system global", "show system global")
    if not g:
        return True  # FortiOS default is enable
    return _get_set(g, "admin-https-redirect") != "disable"


def exposed_mgmt_interfaces(sections: dict[str, str]) -> list[dict] | None:
    """Find interfaces that allow http/https/ssh/telnet management.
    Return a list of dicts, or None when interface output is missing."""
    blocks = _interface_blocks(sections)
    if blocks is None:
        return None
    # http only counts as plaintext when https redirect is disabled.
    plaintext_protos = set(PLAINTEXT_ALWAYS)
    if not https_redirect_enabled(sections):
        plaintext_protos |= PLAINTEXT_IF_NO_REDIRECT
    out = []
    for ifname, block in blocks.items():
        allow = _get_set(block, "allowaccess")
        if not allow:
            continue
        mgmt = {p.lower() for p in allow.split()} & MGMT_PROTOCOLS
        if not mgmt:
            continue
        ip = _get_set(block, "ip")
        ip_addr = ip.split()[0] if ip else None
        name_lower = ifname.lower()
        looks_wan = (
            any(h in name_lower for h in WAN_NAME_HINTS)
            or _get_set(block, "role") == "wan"
            or (ip_addr is not None and not _is_private_ip(ip_addr))
        )
        out.append({
            "ifname": ifname,
            "ip": ip_addr,
            "mgmt": sorted(mgmt),
            "plaintext": sorted(mgmt & plaintext_protos),
            "looks_wan": looks_wan,
        })
    return out


def admins_all_trusthost(sections: dict[str, str]) -> bool:
    """True when admin accounts exist AND all have a real trusthost restriction."""
    _, out = find_section(sections, "show system admin")
    if out is None:
        return False
    admins = _split_edit_blocks(out)
    if not admins:
        return False
    for block in admins.values():
        ths = re.findall(r'set trusthost\d+\s+([0-9.]+)\s+([0-9.]+)', block)
        if not ths or any(net == "0.0.0.0" and mask == "0.0.0.0" for net, mask in ths):
            return False
    return True


def sslvpn_interfaces(sections: dict[str, str]) -> tuple[bool, set[str]]:
    """Return (sslvpn_active, set of source interfaces). Empty set + active =
    could not determine the interface (treated conservatively = may be on all)."""
    _, out = find_section(sections, "show vpn ssl settings")
    if not out or _get_set(out, "status") != "enable":
        return False, set()
    src = _get_set(out, "source-interface") or ""
    ifs = {tok.strip().strip('"') for tok in src.split() if tok.strip()}
    return True, ifs


def management_locked_down(sections: dict[str, str], hostname: str | None,
                           allowlist: set[tuple[str, str]] | None) -> bool:
    """True when there is no internet-facing admin surface: every management
    interface is either internal (private IP) or acknowledged in the allowlist.
    Returns False when interface output is missing (cannot be confirmed)."""
    allowlist = allowlist or set()
    ifaces = exposed_mgmt_interfaces(sections)
    if ifaces is None:
        return False
    for i in ifaces:
        if is_mgmt_approved(hostname, i["ifname"], allowlist):
            continue
        if i["looks_wan"]:
            return False
    return True


def check_mgmt_exposure(sections: dict[str, str], hostname: str | None = None,
                        allowlist: set[tuple[str, str]] | None = None) -> CheckResult:
    """Management protocols (https/ssh/http/telnet) allowed on interfaces.
    Conservative: anything not clearly internal (private IP) is flagged;
    plaintext always. Two ways an internet-facing surface can reach PASS:
    acknowledge it in the allowlist (--review), OR admin access is trusthost-
    mitigated (all admins trusthost-locked, no plaintext, and no SSL-VPN on
    the interface — Fortinet 'good')."""
    allowlist = allowlist or set()
    ifaces = exposed_mgmt_interfaces(sections)
    if ifaces is None:
        return missing("Management exposure (allowaccess)")
    if not ifaces:
        return CheckResult("Management exposure (allowaccess)", CheckResult.PASS,
                           "No interfaces allow http/https/ssh/telnet management")

    all_th = admins_all_trusthost(sections)
    sslvpn_on, sslvpn_ifs = sslvpn_interfaces(sections)

    def vpn_on(ifname: str) -> bool:
        # VPN-bearing when SSL-VPN is active and either matches this interface,
        # or the source interface could not be determined (conservative).
        return sslvpn_on and (ifname in sslvpn_ifs or not sslvpn_ifs)

    plaintext_findings = []   # FAIL
    exposed_findings = []     # WARN — internet-facing, not mitigated
    mitigated = []            # internet-facing but trusthost-mitigated -> PASS
    internal_only = []        # internal, not acknowledged
    acknowledged = []         # approved in allowlist -> PASS

    for i in ifaces:
        label = f"{i['ifname']} (ip={i['ip'] or '?'}): {', '.join(i['mgmt'])}"
        if is_mgmt_approved(hostname, i["ifname"], allowlist):
            acknowledged.append(label + " [OK/acknowledged]")
            continue
        if i["plaintext"]:
            plaintext_findings.append(
                f"{i['ifname']} (ip={i['ip'] or '?'}): plaintext management "
                f"{', '.join(i['plaintext'])}")
            continue
        if i["looks_wan"]:
            if all_th and not vpn_on(i["ifname"]):
                mitigated.append(label + " [trusthost-mitigated]")
            else:
                exposed_findings.append(label
                    + (" (SSL-VPN on this interface — trusthost does not cover VPN login)"
                       if vpn_on(i["ifname"]) else ""))
        else:
            internal_only.append(label)

    name = "Management exposure (allowaccess)"
    ack_block = ("\nAcknowledged as OK (allowlist):\n  " + "\n  ".join(acknowledged)
                 if acknowledged else "")
    mit_block = ("\nTrusthost-mitigated (Fortinet 'good'):\n  " + "\n  ".join(mitigated)
                 if mitigated else "")

    if plaintext_findings:
        detail = "Plaintext management active (must be removed):\n  " + "\n  ".join(plaintext_findings)
        if exposed_findings:
            detail += "\nPossibly internet-facing management interfaces:\n  " + "\n  ".join(exposed_findings)
        return CheckResult(name, CheckResult.FAIL, detail + mit_block + ack_block)
    if exposed_findings:
        return CheckResult(
            name, CheckResult.WARN,
            "Management allowed on possibly internet-facing interfaces without "
            "trusthost coverage — close it down, set trusthost, or mark as OK "
            "with --review:\n  "
            + "\n  ".join(exposed_findings) + mit_block + ack_block)

    # Only internal, mitigated and/or acknowledged left -> PASS
    parts = []
    if mitigated:
        parts.append("Trusthost-mitigated (all admins trusthost-locked): "
                     + "; ".join(mitigated))
    if acknowledged:
        parts.append("Acknowledged as OK: " + "; ".join(acknowledged))
    if internal_only:
        parts.append("Internal only (private IP), verify against local-in policy: "
                     + "; ".join(internal_only))
    if not parts:
        parts.append("No remaining management exposure")
    return CheckResult(name, CheckResult.PASS, "\n  ".join(parts))


def check_admin_trusthost(sections: dict[str, str], hostname: str | None = None,
                          allowlist: set[tuple[str, str]] | None = None) -> CheckResult:
    """Admin accounts without trusthost are open to brute force. When management
    is fully locked down (no internet-facing admin surface), missing trusthost
    is only defense-in-depth -> WARN instead of FAIL."""
    _, out = find_section(sections, "show system admin")
    if out is None:
        return missing("Admin trusted hosts (trusthost)")
    admins = _split_edit_blocks(out)
    if not admins:
        return CheckResult("Admin trusted hosts (trusthost)", CheckResult.INFO,
                           "No admin accounts could be parsed")

    no_trusthost = []
    open_trusthost = []
    for name, block in admins.items():
        ths = re.findall(r'set trusthost\d+\s+([0-9.]+)\s+([0-9.]+)', block)
        if not ths:
            no_trusthost.append(name)
            continue
        # 0.0.0.0 0.0.0.0 = "the whole world" = no real restriction
        if any(net == "0.0.0.0" and mask == "0.0.0.0" for net, mask in ths):
            open_trusthost.append(name)

    bad = no_trusthost + open_trusthost
    if bad:
        detail = []
        if no_trusthost:
            detail.append("Without trusthost (open to all sources): " + ", ".join(no_trusthost))
        if open_trusthost:
            detail.append("Trusthost set to 0.0.0.0/0 (no restriction): "
                          + ", ".join(open_trusthost))
        if management_locked_down(sections, hostname, allowlist):
            detail.append("Management is locked down (no internet-facing admin "
                          "surface), so this is defense-in-depth — set trusthost "
                          "when possible.")
            return CheckResult("Admin trusted hosts (trusthost)", CheckResult.WARN,
                               "\n  ".join(detail))
        return CheckResult("Admin trusted hosts (trusthost)", CheckResult.FAIL,
                           "\n  ".join(detail))
    return CheckResult("Admin trusted hosts (trusthost)", CheckResult.PASS,
                       f"All {len(admins)} admin accounts have a trusthost restriction")


def check_api_admins(sections: dict[str, str]) -> CheckResult:
    """REST API admins (api-user) are credentials too; should be trusthost-locked."""
    _, out = find_section(sections, "show system api-user")
    if out is None:
        return missing("REST API admins (api-user)")
    apis = _split_edit_blocks(out)
    if not apis:
        return CheckResult("REST API admins (api-user)", CheckResult.PASS,
                           "No REST API admins configured")
    no_trusthost = []
    for name, block in apis.items():
        ths = re.findall(r'set trusthost\d+\s+.*?([0-9.]+)\s+([0-9.]+)', block)
        if not ths or any(net == "0.0.0.0" and mask == "0.0.0.0" for net, mask in ths):
            no_trusthost.append(name)
    if no_trusthost:
        return CheckResult(
            "REST API admins (api-user)", CheckResult.FAIL,
            "API admins without a trusthost restriction (the API key can be "
            "abused from any source): " + ", ".join(no_trusthost))
    return CheckResult("REST API admins (api-user)", CheckResult.PASS,
                       f"All {len(apis)} API admins are trusthost-restricted")


def _has_residual_hash(sections: dict[str, str]) -> bool:
    """True when 'set old-password' (retained SHA-256 hash) appears in admin output."""
    _, out = find_section(sections, "show full-configuration system admin",
                          "show system admin")
    return bool(out and "set old-password" in out)


def check_residual_hash(sections: dict[str, str]) -> CheckResult:
    """'set old-password' = retained SHA-256 hash crackable from the config."""
    key, out = find_section(sections, "show full-configuration system admin",
                            "show system admin")
    if out is None:
        return missing("Residual SHA-256 hash (old-password)")
    accounts = [n for n, b in _split_edit_blocks(out).items()
                if "set old-password" in b]
    if accounts:
        return CheckResult(
            "Residual SHA-256 hash (old-password)", CheckResult.WARN,
            "Retained SHA-256 hash ('set old-password') on account(s): "
            + ", ".join(accounts) + ".\n  Crackable from an extracted config. "
            "Force a purge: enable login-lockout-upon-weaker-encryption and have "
            "every admin log in again.")
    note = ("" if key and key.startswith("show full-configuration")
            else "  (run 'show full-configuration system admin' to be certain)")
    return CheckResult("Residual SHA-256 hash (old-password)", CheckResult.PASS,
                       "No 'set old-password' (residual SHA-256) found." + note)


def check_admin_mfa(sections: dict[str, str]) -> CheckResult:
    """Admins without two-factor are the primary target in FortiBleed
    (reused credentials)."""
    _, out = find_section(sections, "show system admin")
    if out is None:
        return missing("Admin MFA (two-factor)")
    admins = _split_edit_blocks(out)
    if not admins:
        return CheckResult("Admin MFA (two-factor)", CheckResult.INFO,
                           "No admin accounts could be parsed")
    no_mfa = []
    for name, block in admins.items():
        tf = _get_set(block, "two-factor")
        if not tf or tf == "disable":
            no_mfa.append(name)
    if no_mfa:
        return CheckResult(
            "Admin MFA (two-factor)", CheckResult.FAIL,
            "Admin accounts without two-factor (MFA) — Fortinet requires MFA on "
            "all admins:\n  " + ", ".join(no_mfa),
        )
    return CheckResult("Admin MFA (two-factor)", CheckResult.PASS,
                       f"All {len(admins)} admin accounts have two-factor enabled")


def _weaker_lockout_setting(sections: dict[str, str]) -> tuple[str | None, str | None]:
    """Return (key name, value) for the purge setting. It lives under
    'config system password-policy'; we also search global as a fallback."""
    for cmd in ("show full-configuration system password-policy",
                "show system password-policy",
                "show full-configuration system global",
                "show system global"):
        _, out = find_section(sections, cmd)
        if out is None:
            continue
        for key in WEAKER_LOCKOUT_KEYS:
            val = _get_set(out, key)
            if val is not None:
                return key, val
    return None, None


def check_legacy_hashing(sections: dict[str, str]) -> CheckResult:
    """Should enforce PBKDF2 and purge old SHA-256 hashes."""
    have_source = any(find_section(sections, c)[1] is not None for c in (
        "show full-configuration system password-policy", "show system password-policy",
        "show full-configuration system global", "show system global"))
    if not have_source:
        return missing("Legacy password hashing")
    key, setting = _weaker_lockout_setting(sections)
    if setting is None:
        ver = parse_firmware(sections)
        if ver and not pbkdf2_supported(ver):
            return CheckResult(
                "Legacy password hashing", CheckResult.WARN,
                "The firmware is pre-PBKDF2, so the purge setting does not exist. "
                "Upgrade to a PBKDF2-capable version (7.2.11/7.4.8/7.6.1/8.0+).")
        return CheckResult(
            "Legacy password hashing", CheckResult.WARN,
            "The purge setting (login-lockout-upon-downgrade on 7.2/7.4, "
            "login-lockout-upon-weaker-encryption on 7.6+) was not found. Run "
            "'show full-configuration system password-policy' to see the default "
            "value, and enable it to purge old SHA-256 hashes.")
    if setting == "enable":
        return CheckResult("Legacy password hashing", CheckResult.PASS,
                           f"{key} is enabled (old hashes are purged, PBKDF2 enforced)")
    # setting == disable: only an active exposure when old hashes actually
    # remain (residual 'set old-password') or the firmware is pre-PBKDF2.
    ver = parse_firmware(sections)
    pre_pbkdf2 = bool(ver and not pbkdf2_supported(ver))
    if _has_residual_hash(sections) or pre_pbkdf2:
        why = ("the firmware is pre-PBKDF2" if pre_pbkdf2
               else "residual SHA-256 hashes ('set old-password') remain")
        return CheckResult(
            "Legacy password hashing", CheckResult.FAIL,
            f"{key} is disabled, and {why} — old/weak SHA-256 hashes can be cracked "
            f"from an extracted config. Enable the purge setting and log in to "
            f"every admin account.")
    return CheckResult(
        "Legacy password hashing", CheckResult.WARN,
        f"{key} is disabled, but no residual SHA-256 hashes were found. Low "
        f"exposure right now; enable it as future-proofing so new legacy hashes "
        f"are purged automatically.")


def _forticloud_sso_setting(sections: dict[str, str]) -> str | None:
    """Return the value of admin-forticloud-sso-login (enable/disable) or None."""
    _, out = find_section(sections, "show full-configuration system global",
                          "show system global")
    if out is None:
        return None
    return _get_set(out, "admin-forticloud-sso-login")


def check_forticloud_sso(sections: dict[str, str]) -> CheckResult:
    """FortiGate Cloud single sign-on for admin login. Related to
    CVE-2026-24858 (FortiCloud SSO SAML auth bypass, CVSS 9.8). Should be
    disabled unless actively used and the firmware is patched."""
    setting = _forticloud_sso_setting(sections)
    if setting is None:
        return CheckResult(
            "FortiCloud SSO login", CheckResult.INFO,
            "'admin-forticloud-sso-login' not found. Run "
            "'show full-configuration system global' to see the default value.")
    if setting == "disable":
        return CheckResult("FortiCloud SSO login", CheckResult.PASS,
                           "admin-forticloud-sso-login is disabled")
    return CheckResult(
        "FortiCloud SSO login", CheckResult.WARN,
        "admin-forticloud-sso-login is ENABLED — admins can log in via FortiCloud "
        "SSO. Verify that it is actively used and that the firmware is patched "
        "for CVE-2026-24858 (FortiCloud SSO SAML auth bypass). Otherwise disable it.")


def check_private_data_encryption(sections: dict[str, str]) -> CheckResult:
    """Encrypts sensitive data in config backups — protects against offline
    cracking of an extracted config (the very FortiBleed technique)."""
    _, out = find_section(sections, "show full-configuration system global",
                          "show system global")
    if out is None:
        return missing("Private-data-encryption")
    val = _get_set(out, "private-data-encryption")
    if val == "enable":
        return CheckResult("Private-data-encryption", CheckResult.PASS,
                           "private-data-encryption is enabled")
    return CheckResult(
        "Private-data-encryption", CheckResult.INFO,
        "private-data-encryption is not enabled — sensitive data in an extracted "
        "config is in a more recoverable form. Consider enabling it (requires "
        "managing the encryption key at restore time).")


def check_password_policy(sections: dict[str, str]) -> CheckResult:
    """Weak password hygiene is the direct precondition for FortiBleed."""
    _, out = find_section(sections, "show system password-policy")
    if out is None:
        return missing("Password policy")
    status = _get_set(out, "status")
    if status is None or status == "disable":
        return CheckResult("Password policy", CheckResult.WARN,
                           "No password policy active (set status enable). Weak "
                           "passwords are the core of FortiBleed's brute-force leg.")
    min_len = _get_set(out, "minimum-length")
    detail = "Password policy active"
    if min_len:
        detail += f", minimum-length={min_len}"
        try:
            if int(min_len) < 12:
                return CheckResult("Password policy", CheckResult.WARN,
                                   detail + " — consider a minimum of 12-14 characters.")
        except ValueError:
            pass
    return CheckResult("Password policy", CheckResult.PASS, detail)


def check_admin_lockout(sections: dict[str, str]) -> CheckResult:
    """A low lockout threshold slows brute force down."""
    _, out = find_section(sections, "show full-configuration system global",
                          "show system global")
    if out is None:
        return missing("Brute-force lockout")
    threshold = _get_set(out, "admin-lockout-threshold")
    duration = _get_set(out, "admin-lockout-duration")
    if threshold is None and duration is None:
        return CheckResult(
            "Brute-force lockout", CheckResult.WARN,
            "Lockout settings not in the output. Use 'show full-configuration "
            "system global'. The default threshold is 3 and duration 60s.",
        )
    try:
        t = int(threshold) if threshold else 3
        if t > 5:
            return CheckResult("Brute-force lockout", CheckResult.WARN,
                               f"admin-lockout-threshold={t} is high — lower it to 3-5.")
    except ValueError:
        pass
    return CheckResult("Brute-force lockout", CheckResult.PASS,
                       f"Lockout configured (threshold={threshold or 'default 3'}, "
                       f"duration={duration or 'default 60'})")


def check_sslvpn(sections: dict[str, str]) -> CheckResult:
    """Internet-facing SSL-VPN is a primary login surface in FortiBleed."""
    _, out = find_section(sections, "show vpn ssl settings")
    if out is None:
        return missing("SSL-VPN exposure")
    status = _get_set(out, "status")
    if status != "enable":
        return CheckResult("SSL-VPN exposure", CheckResult.PASS,
                           "SSL-VPN is not enabled")

    src_if = _get_set(out, "source-interface") or "?"
    port = _get_set(out, "port") or "10443/443"
    src_lower = src_if.lower()
    looks_wan = any(h in src_lower for h in WAN_NAME_HINTS)
    detail = f"SSL-VPN is enabled (source-interface={src_if}, port={port})."
    if looks_wan:
        return CheckResult(
            "SSL-VPN exposure", CheckResult.WARN,
            detail + " The interface looks internet-facing — ensure MFA on all "
            "SSL-VPN users and consider geo/local-in restrictions.",
        )
    return CheckResult(
        "SSL-VPN exposure", CheckResult.WARN,
        detail + " Verify that the source interface is not internet-facing and "
        "that all VPN users have MFA.",
    )


def check_vpn_user_mfa(sections: dict[str, str]) -> CheckResult:
    """Local VPN users without two-factor."""
    _, ssl = find_section(sections, "show vpn ssl settings")
    sslvpn_on = bool(ssl and _get_set(ssl, "status") == "enable")

    _, out = find_section(sections, "show user local")
    if out is None:
        return missing("VPN user MFA")
    users = _split_edit_blocks(out)
    if not users:
        return CheckResult("VPN user MFA", CheckResult.INFO,
                           "No local users found")
    no_mfa = []
    for name, block in users.items():
        # only password-based local users are relevant
        if _get_set(block, "type") not in (None, "password"):
            continue
        tf = _get_set(block, "two-factor")
        if not tf or tf == "disable":
            no_mfa.append(name)
    if no_mfa:
        status = CheckResult.FAIL if sslvpn_on else CheckResult.WARN
        note = ("SSL-VPN is active — these accounts can log in without MFA:"
                if sslvpn_on else
                "SSL-VPN does not look active, but verify IPsec/other VPN use:")
        return CheckResult("VPN user MFA", status,
                           note + "\n  " + ", ".join(no_mfa))
    return CheckResult("VPN user MFA", CheckResult.PASS,
                       f"All {len(users)} local users have two-factor")


def check_local_in_policy(sections: dict[str, str]) -> CheckResult:
    """Local-in policy / trusthost locks management down (Fortinet's 'better')."""
    _, out = find_section(sections, "show firewall local-in-policy")
    if out is None:
        return missing("Management lockdown (local-in policy)")
    if not out.strip() or "edit" not in out:
        return CheckResult(
            "Management lockdown (local-in policy)", CheckResult.INFO,
            "No local-in policy configured. Not critical when trusthosts and "
            "internal management interfaces are in place, but Fortinet recommends "
            "it to lock management access down.",
        )
    n = len(_split_edit_blocks(out))
    return CheckResult("Management lockdown (local-in policy)", CheckResult.PASS,
                       f"{n} local-in policy rule(s) configured")


# ---------------------------------------------------------------------------
# Checks — IoC (signs of actual compromise)
# ---------------------------------------------------------------------------

def check_suspicious_admins(sections: dict[str, str]) -> CheckResult:
    """Warns ONLY when an admin account name matches a known suspicious list
    (SUSPICIOUS_ADMIN_NAMES). 'Unknown' accounts are not flagged, since no
    reliable ground-truth list of legitimate accounts exists."""
    _, out = find_section(sections, "show system admin")
    if out is None:
        return missing("Suspicious admin accounts (IoC)")
    admins = _split_edit_blocks(out)
    if not admins:
        return CheckResult("Suspicious admin accounts (IoC)", CheckResult.INFO,
                           "No admin accounts could be parsed")

    flagged = [n for n in admins if n.lower() in SUSPICIOUS_ADMIN_NAMES]
    if flagged:
        return CheckResult(
            "Suspicious admin accounts (IoC)", CheckResult.WARN,
            "Admin accounts with names from known suspicious lists — verify they "
            "are legitimate: " + ", ".join(flagged),
        )
    return CheckResult("Suspicious admin accounts (IoC)", CheckResult.PASS,
                       f"No known suspicious account names among {len(admins)} admin accounts")


def check_ssh_keys(sections: dict[str, str]) -> CheckResult:
    """SSH public keys on admins can be backdoors."""
    _, out = find_section(sections, "show system admin")
    if out is None:
        return missing("SSH keys on admins (IoC)")
    if "ssh-public-key" in out:
        keys = [l.strip() for l in out.splitlines() if "ssh-public-key" in l]
        return CheckResult("SSH keys on admins (IoC)", CheckResult.WARN,
                           "SSH public keys on admin accounts — verify they are authorized:\n  "
                           + "\n  ".join(keys))
    return CheckResult("SSH keys on admins (IoC)", CheckResult.PASS,
                       "No SSH public keys on admin accounts")


def check_automation(sections: dict[str, str]) -> CheckResult:
    """Automation actions with external callbacks/scripts can be persistence."""
    _, actions = find_section(sections, "show system automation-action")
    _, triggers = find_section(sections, "show system automation-trigger")
    if actions is None and triggers is None:
        return missing("Automation (IoC)")
    warnings = []
    if actions:
        for script in re.findall(r'set script\s+"([^"]+)"', actions):
            if any(x in script for x in ["curl", "wget", "nc ", "ncat", "bash",
                                          "sh -c", "python", "perl", "/tmp"]):
                warnings.append(f"Suspicious CLI script: {script!r}")
        if re.search(r"set\s+uri\s+https?://(?![\w.]*fortinet|[\w.]*forticloud)", actions):
            warnings.append("Automation action points at an external non-Fortinet URI")
    if warnings:
        return CheckResult("Automation (IoC)", CheckResult.WARN, "\n  ".join(warnings))
    return CheckResult("Automation (IoC)", CheckResult.PASS,
                       "No suspicious automation scripts or external callbacks")


# ---------------------------------------------------------------------------
# Allowlist for management exposure ("is this interface OK?")
# ---------------------------------------------------------------------------

DEFAULT_ALLOWLIST = "mgmt_allowlist.txt"


def is_mgmt_approved(hostname: str | None, ifname: str,
                     allowlist: set[tuple[str, str]]) -> bool:
    """Is (host, interface) marked OK? '*' as host applies to all devices."""
    if ("*", ifname) in allowlist:
        return True
    if hostname and (hostname, ifname) in allowlist:
        return True
    return False


def load_allowlist(path: Path) -> set[tuple[str, str]]:
    """Line format: 'hostname:interface'. Without a colon -> '*:interface'
    (all devices). '#' starts a comment."""
    result: set[tuple[str, str]] = set()
    if not path.exists():
        return result
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            host, ifn = line.split(":", 1)
            host, ifn = host.strip(), ifn.strip()
        else:
            host, ifn = "*", line
        if ifn:
            result.add((host or "*", ifn))
    return result


def save_allowlist(path: Path, allowlist: set[tuple[str, str]]):
    header = (
        "# FortiBleed — approved (acknowledged) management exposures\n"
        "# Format: hostname:interface  (use * as hostname for all devices)\n"
        "# Generated/updated by --review, but can also be edited by hand.\n"
    )
    lines = [f"{host}:{ifn}" for host, ifn in sorted(allowlist)]
    path.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")


def review_interfaces(devices_data: list[tuple[str | None, dict[str, str]]],
                      allowlist: set[tuple[str, str]], path: Path) -> int:
    """Interactively ask, for each exposed and not-yet-approved interface,
    whether it is OK. Updates and saves the allowlist. Returns the number of
    new approvals."""
    added = 0
    print("\n" + "=" * 72)
    print("  MANAGEMENT EXPOSURE REVIEW")
    print("  Answer y = OK/acknowledged (PASS from now on), n = keep as a finding.")
    print("=" * 72)
    any_prompt = False
    for hostname, sections in devices_data:
        ifaces = exposed_mgmt_interfaces(sections) or []
        pending = [i for i in ifaces
                   if not is_mgmt_approved(hostname, i["ifname"], allowlist)]
        if not pending:
            continue
        host_label = hostname or "(unknown hostname)"
        print(f"\n  Device: {host_label}")
        for i in pending:
            any_prompt = True
            flags = []
            if i["plaintext"]:
                flags.append("PLAINTEXT " + ",".join(i["plaintext"]))
            if i["looks_wan"]:
                flags.append("possibly internet-facing")
            flag_str = f"  [{'; '.join(flags)}]" if flags else ""
            try:
                ans = input(f"    {i['ifname']} (ip={i['ip'] or '?'}, "
                            f"access={', '.join(i['mgmt'])}){flag_str}\n"
                            f"      Is this management exposure OK? [y/N]: ").strip().lower()
            except EOFError:
                ans = ""
            if ans in ("y", "yes", "j", "ja"):
                allowlist.add((hostname or "*", i["ifname"]))
                added += 1
                print("      -> marked OK")
            else:
                print("      -> kept as a finding")
    if not any_prompt:
        print("\n  No new exposed interfaces to review.")
    if added:
        save_allowlist(path, allowlist)
        print(f"\n  Saved {added} new approval(s) to {path}")
    print("=" * 72)
    return added


# ---------------------------------------------------------------------------
# Check registry and runner
# ---------------------------------------------------------------------------

# Every check with a short, stable id (used by --skip-checks / --list-checks).
# Fixed order so reports are stable run-to-run. Runners share one signature:
# (sections, hostname, allowlist) -> CheckResult.
CHECK_REGISTRY: dict[str, Callable[[dict, str | None, set | None], CheckResult]] = {
    "firmware":               lambda s, h, a: check_firmware(s),
    "mgmt-exposure":          check_mgmt_exposure,
    "admin-trusthost":        check_admin_trusthost,
    "api-users":              lambda s, h, a: check_api_admins(s),
    "admin-mfa":              lambda s, h, a: check_admin_mfa(s),
    "legacy-hashing":         lambda s, h, a: check_legacy_hashing(s),
    "residual-hash":          lambda s, h, a: check_residual_hash(s),
    "private-data-encryption": lambda s, h, a: check_private_data_encryption(s),
    "forticloud-sso":         lambda s, h, a: check_forticloud_sso(s),
    "password-policy":        lambda s, h, a: check_password_policy(s),
    "admin-lockout":          lambda s, h, a: check_admin_lockout(s),
    "sslvpn":                 lambda s, h, a: check_sslvpn(s),
    "vpn-user-mfa":           lambda s, h, a: check_vpn_user_mfa(s),
    "local-in-policy":        lambda s, h, a: check_local_in_policy(s),
    "suspicious-admins":      lambda s, h, a: check_suspicious_admins(s),
    "ssh-keys":               lambda s, h, a: check_ssh_keys(s),
    "automation":             lambda s, h, a: check_automation(s),
}

# Human-readable one-liners for --list-checks (id -> description).
CHECK_DESCRIPTIONS = {
    "firmware":               "Firmware version vs. PBKDF2-capable password hashing",
    "mgmt-exposure":          "Management protocols (allowaccess) on interfaces",
    "admin-trusthost":        "Trusthost restrictions on admin accounts",
    "api-users":              "Trusthost restrictions on REST API admins",
    "admin-mfa":              "Two-factor authentication on admin accounts",
    "legacy-hashing":         "Purge setting for legacy SHA-256 password hashes",
    "residual-hash":          "Residual 'set old-password' SHA-256 hashes",
    "private-data-encryption": "Encryption of sensitive data in config backups",
    "forticloud-sso":         "FortiCloud SSO admin login (CVE-2026-24858)",
    "password-policy":        "Password policy status and minimum length",
    "admin-lockout":          "Brute-force lockout threshold",
    "sslvpn":                 "SSL-VPN enablement and exposure",
    "vpn-user-mfa":           "Two-factor on local (VPN) users",
    "local-in-policy":        "Management lockdown via local-in policy",
    "suspicious-admins":      "IoC: admin names on known suspicious lists",
    "ssh-keys":               "IoC: SSH public keys on admin accounts",
    "automation":             "IoC: suspicious automation scripts/callbacks",
}


def run_checks(sections: dict[str, str], hostname: str | None = None,
               allowlist: set[tuple[str, str]] | None = None,
               skip: frozenset[str] | set[str] = frozenset()) -> list[CheckResult]:
    """Run all checks in fixed order; skip ids listed in `skip`."""
    return [fn(sections, hostname, allowlist)
            for cid, fn in CHECK_REGISTRY.items() if cid not in skip]


def parse_skip_arg(raw: str | None) -> frozenset[str]:
    """Validate a comma-separated --skip-checks value against the registry."""
    if not raw:
        return frozenset()
    ids = {tok.strip() for tok in raw.split(",") if tok.strip()}
    unknown = ids - set(CHECK_REGISTRY)
    if unknown:
        die("unknown check id(s) for --skip-checks: " + ", ".join(sorted(unknown))
            + ". Use --list-checks to see valid ids.")
    return frozenset(ids)


def print_check_list():
    print(f"Available checks ({len(CHECK_REGISTRY)}) — skip with "
          f"--skip-checks id1,id2,...\n")
    for cid in CHECK_REGISTRY:
        print(f"  {cid:<24} {CHECK_DESCRIPTIONS.get(cid, '')}")


# ---------------------------------------------------------------------------
# Device facts (for the batch overview)
# ---------------------------------------------------------------------------

def device_facts(sections: dict[str, str], hostname: str | None,
                 allowlist: set[tuple[str, str]] | None = None) -> dict:
    """Extract the key facts shown in the combined overview."""
    allowlist = allowlist or set()

    # Firmware + PBKDF2 support (version-exact)
    ver = parse_firmware(sections)
    firmware = "v{}.{}.{}".format(*ver) if ver else None
    pbkdf2 = pbkdf2_supported(ver) if ver else None

    # Enforced purge of old hashes (both variants of the setting)
    _, weaker_lockout = _weaker_lockout_setting(sections)

    # Residual SHA-256 hash (set old-password)
    _, adm = find_section(sections, "show full-configuration system admin", "show system admin")
    residual = bool(adm and "set old-password" in adm)

    # Management exposure (list)
    all_th_mgmt = admins_all_trusthost(sections)
    sslvpn_on, sslvpn_ifs = sslvpn_interfaces(sections)
    mgmt = []
    for i in (exposed_mgmt_interfaces(sections) or []):
        vpn_here = sslvpn_on and (i["ifname"] in sslvpn_ifs or not sslvpn_ifs)
        if is_mgmt_approved(hostname, i["ifname"], allowlist):
            tag = " [OK]"
        elif i["plaintext"]:
            tag = " [PLAINTEXT]"
        elif i["looks_wan"] and all_th_mgmt and not vpn_here:
            tag = " [trusthost-mit.]"
        elif i["looks_wan"]:
            tag = " [WAN?]"
        else:
            tag = ""
        mgmt.append(f"{i['ifname']}:{'/'.join(i['mgmt'])}{tag}")

    # Admin accounts + trusthost
    _, a = find_section(sections, "show system admin")
    admins = _split_edit_blocks(a) if a else {}
    no_trusthost = []
    for name, block in admins.items():
        ths = re.findall(r'set trusthost\d+\s+([0-9.]+)\s+([0-9.]+)', block)
        if not ths or any(net == "0.0.0.0" and mask == "0.0.0.0" for net, mask in ths):
            no_trusthost.append(name)
    all_trusthost = bool(admins) and not no_trusthost

    # FortiCloud SSO
    sso = _forticloud_sso_setting(sections)

    return {
        "firmware": firmware,
        "pbkdf2_supported": pbkdf2,
        "weaker_lockout": weaker_lockout,
        "residual_sha256": residual,
        "mgmt_exposed": mgmt,
        "admins": list(admins.keys()),
        "admins_without_trusthost": no_trusthost,
        "all_admins_trusthost": all_trusthost,
        "forticloud_sso": sso,
    }


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

VERDICT_EXPOSED = "EXPOSED"
VERDICT_REVIEW = "REVIEW WARNINGS"
VERDICT_INCOMPLETE = "INCOMPLETE"
VERDICT_CLEAN = "NOT AFFECTED"

# Ranking used to pick the "worst" verdict across multiple devices.
VERDICT_ORDER = {VERDICT_EXPOSED: 0, VERDICT_REVIEW: 1,
                 VERDICT_INCOMPLETE: 2, VERDICT_CLEAN: 3}


def count_statuses(results: list[CheckResult]) -> dict[str, int]:
    return {s: sum(1 for r in results if r.status == s)
            for s in (CheckResult.PASS, CheckResult.WARN, CheckResult.FAIL,
                      CheckResult.SKIP, CheckResult.INFO)}


def compute_verdict(results: list[CheckResult]) -> str:
    c = count_statuses(results)
    if c[CheckResult.FAIL]:
        return VERDICT_EXPOSED
    if c[CheckResult.WARN]:
        return VERDICT_REVIEW
    if c[CheckResult.SKIP]:
        return VERDICT_INCOMPLETE
    return VERDICT_CLEAN


def worst_verdict(verdicts) -> str:
    return min(verdicts, key=lambda v: VERDICT_ORDER.get(v, 9), default=VERDICT_CLEAN)


def verdict_exit_code(verdicts) -> int:
    """Map verdicts to the exit-code scheme (worst wins in batch mode)."""
    worst = worst_verdict(verdicts)
    if worst == VERDICT_EXPOSED:
        return EXIT_FAIL
    if worst in (VERDICT_REVIEW, VERDICT_INCOMPLETE):
        return EXIT_WARN
    return EXIT_OK


def extract_hostname(sections: dict[str, str]) -> str | None:
    _, out = find_section(sections, "get system status")
    if not out:
        return None
    m = re.search(r"Hostname\s*:\s*(\S+)", out)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Assessment & caveats (verdict-dependent)
# ---------------------------------------------------------------------------

_DISCLAIMER_BASE = (
    "Caveat: This assessment is an automated review of the collected FortiGate "
    "configuration and is a snapshot at the time of review. It highlights known "
    "exposure factors for the FortiBleed technique and is neither an exhaustive "
    "security audit nor a guarantee that a device is not, or has not been, "
    "compromised."
)

_DISCLAIMER_CONCLUSION = {
    VERDICT_EXPOSED:
        "ASSESSMENT: The configuration review shows one or more known FortiBleed "
        "exposure factors on at least one device. The devices in scope should be "
        "considered at elevated risk. The concrete measures are listed in the "
        "action plan above; check them off as they are completed.",
    VERDICT_REVIEW:
        "ASSESSMENT: No critical exposure factors were found, but a few items "
        "should be reviewed manually before an overall conclusion is drawn.",
    VERDICT_INCOMPLETE:
        "ASSESSMENT: The collected data is not yet complete for all devices. "
        "Collect the missing command output and re-run before drawing overall "
        "conclusions about exposure.",
    VERDICT_CLEAN:
        "ASSESSMENT: Based on the reviewed configuration, none of the known "
        "FortiBleed exposure factors are present, and the devices appear hardened "
        "in line with Fortinet's recommendations. The assessment covers the "
        "configuration state at the time of review and cannot by itself rule out "
        "a compromise predating or outside the configuration. Continued log "
        "monitoring is recommended, along with checking for any direct "
        "notification from Fortinet.",
}


def disclaimer_lines(verdict: str) -> list[str]:
    return [_DISCLAIMER_CONCLUSION.get(verdict, ""), "", _DISCLAIMER_BASE]


def print_disclaimer(verdict: str, color: bool = True, width: int = 78):
    code = VERDICT_COLOR.get(verdict, "") if color else ""
    reset = RESET if color else ""
    print(f"  {code}ASSESSMENT & CAVEATS{reset}")
    print(f"  {'-' * (width - 4)}")
    for para in disclaimer_lines(verdict):
        if not para:
            print()
            continue
        # soft-wrap to ~width characters
        line = ""
        for word in para.split():
            if len(line) + len(word) + 1 > width - 4:
                print(f"  {line}")
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            print(f"  {line}")


# ---------------------------------------------------------------------------
# Action plan — concrete to-dos per finding (for ticket follow-up)
# ---------------------------------------------------------------------------

# The order here is prioritized (most critical first). Only checks that can
# yield FAIL/WARN are listed; keys MUST match the check names exactly.
ACTION_FOR_CHECK = {
    "Management exposure (allowaccess)":
        "Close management on internet-facing interfaces: remove telnet/http where "
        "unneeded, set trusthost or a local-in policy (mark deliberate exceptions "
        "with --review)",
    "Admin trusted hosts (trusthost)":
        "Set trusthost on all admin accounts (not 0.0.0.0/0)",
    "REST API admins (api-user)":
        "Set trusthost on all REST API admins (config system api-user)",
    "Admin MFA (two-factor)":
        "Enable two-factor authentication on all admin accounts",
    "Legacy password hashing":
        "Enable purging of old hashes under 'config system password-policy': "
        "login-lockout-upon-downgrade (FortiOS 7.2/7.4) or "
        "login-lockout-upon-weaker-encryption (7.6+), then log in to every admin",
    "Residual SHA-256 hash (old-password)":
        "Purge residual SHA-256 hashes: enable the purge setting (see above) and "
        "log in to every admin account until 'set old-password' is gone",
    "Firmware / password hash strength":
        "Upgrade firmware to a PBKDF2-capable version (at least 7.2.11 / 7.4.8 / 7.6.1 / 8.0+)",
    "FortiCloud SSO login":
        "Disable admin-forticloud-sso-login (or confirm the firmware is patched for CVE-2026-24858)",
    "Password policy":
        "Enable a password policy (minimum 12-14 characters) under 'config system password-policy'",
    "VPN user MFA":
        "Restrict SSL-VPN access (source/geo/local-in) for users without two-factor",
    "SSL-VPN exposure":
        "Review SSL-VPN: restrict the source interface and geo, and confirm the access need",
    "Brute-force lockout":
        "Set admin-lockout-threshold to 3-5",
    "Suspicious admin accounts (IoC)":
        "Verify the flagged admin accounts and remove them if they are not legitimate",
    "SSH keys on admins (IoC)":
        "Verify that SSH public keys on admin accounts are authorized",
    "Automation (IoC)":
        "Review automation actions for unknown scripts or external callbacks",
}


def action_items(results: list[CheckResult]) -> list[str]:
    """Concrete actions derived from FAIL/WARN findings on one device (deduped)."""
    out: list[str] = []
    for r in results:
        if r.status in (CheckResult.FAIL, CheckResult.WARN):
            a = ACTION_FOR_CHECK.get(r.name)
            if a and a not in out:
                out.append(a)
    # sort by the prioritized order in ACTION_FOR_CHECK
    order = list(ACTION_FOR_CHECK.values())
    return sorted(out, key=order.index)


def build_action_plan(devices: list[dict]) -> list[tuple[str, list[str]]]:
    """Aggregate actions across devices -> [(action, [device names])]."""
    by_action: dict[str, list[str]] = {}
    for d in devices:
        nm = d.get("hostname") or Path(d["source"]).name
        for r in d["results"]:
            if r["status"] in (CheckResult.FAIL, CheckResult.WARN):
                a = ACTION_FOR_CHECK.get(r["name"])
                if a:
                    by_action.setdefault(a, [])
                    if nm not in by_action[a]:
                        by_action[a].append(nm)
    return [(a, by_action[a]) for a in ACTION_FOR_CHECK.values() if a in by_action]


def print_action_plan(plan: list[tuple[str, list[str]]], color: bool = True,
                      width: int = 78, show_devices: bool = True):
    if not plan:
        return
    bold = BOLD if color else ""
    reset = RESET if color else ""
    print(f"\n  {bold}ACTION PLAN{reset} (check off as completed)")
    print(f"  {'-' * (width - 4)}")
    for action, devs in plan:
        print(f"  [ ] {action}")
        if show_devices and devs:
            print(f"        Devices: {', '.join(devs)}")


# ---------------------------------------------------------------------------
# Report (single device)
# ---------------------------------------------------------------------------

ICONS_COLOR = {
    CheckResult.PASS: f"{OK_C}[PASS]{RESET}",
    CheckResult.WARN: f"{WARN_C}[WARN]{RESET}",
    CheckResult.FAIL: f"{BAD_C}[FAIL]{RESET}",
    CheckResult.INFO: f"{INFO_C}[INFO]{RESET}",
    CheckResult.SKIP: f"{DIM_C}[SKIP]{RESET}",
}
ICONS_PLAIN = {k: f"[{k}]" for k in ICONS_COLOR}

VERDICT_COLOR = {
    VERDICT_EXPOSED: BAD_C,
    VERDICT_REVIEW: WARN_C,
    VERDICT_INCOMPLETE: DIM_C,
    VERDICT_CLEAN: OK_C,
}

VERDICT_LINE = {
    VERDICT_EXPOSED: "VERDICT: EXPOSED — critical findings, act per Fortinet PSIRT guidance",
    VERDICT_REVIEW: "VERDICT: REVIEW WARNINGS before declaring the device unaffected",
    VERDICT_INCOMPLETE: "VERDICT: INCOMPLETE — run the missing commands and try again",
    VERDICT_CLEAN: "VERDICT: NOT AFFECTED — no exposure or IoC signs found",
}


def device_doc(results: list[CheckResult], source: str, hostname: str | None,
               facts: dict | None = None) -> dict:
    c = count_statuses(results)
    return {
        "source": source,
        "hostname": hostname,
        "facts": facts or {},
        "results": [{"name": r.name, "status": r.status, "detail": r.detail}
                    for r in results],
        "summary": {"pass": c[CheckResult.PASS], "warn": c[CheckResult.WARN],
                    "fail": c[CheckResult.FAIL], "skip": c[CheckResult.SKIP],
                    "verdict": compute_verdict(results)},
        "action_plan": action_items(results),
        "disclaimer": " ".join(p for p in disclaimer_lines(compute_verdict(results)) if p),
    }


def print_report(results: list[CheckResult], source: str,
                 color: bool = True, as_json: bool = False,
                 hostname: str | None = None, facts: dict | None = None):
    timestamp = now_iso()
    c = count_statuses(results)
    verdict = compute_verdict(results)

    if as_json:
        doc = {"timestamp": timestamp, "campaign": CAMPAIGN,
               **device_doc(results, source, hostname, facts)}
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return

    icons = ICONS_COLOR if color else ICONS_PLAIN
    label = f"{hostname} ({source})" if hostname else source
    print(f"\n{'=' * 72}")
    print(f"  FortiBleed exposure check (offline) — {label}")
    print(f"  {timestamp}")
    print(f"{'=' * 72}")
    for r in results:
        print(f"\n{icons[r.status]} {r.name}")
        for line in r.detail.splitlines():
            print(f"       {line}")
    print(f"\n{'-' * 72}")
    print(f"  PASS: {c[CheckResult.PASS]}  WARN: {c[CheckResult.WARN]}  "
          f"FAIL: {c[CheckResult.FAIL]}  SKIP: {c[CheckResult.SKIP]}")
    print(f"  {VERDICT_LINE[verdict]}")
    print(f"{'=' * 72}")
    # action plan (without the device list — this is the one device)
    acts = action_items(results)
    if acts:
        print_action_plan([(a, []) for a in acts], color=color, width=72,
                          show_devices=False)
        print(f"{'=' * 72}")
    print()
    print_disclaimer(verdict, color=color, width=72)
    print(f"{'=' * 72}\n")


# ---------------------------------------------------------------------------
# Combined overview of multiple devices (batch / directory mode)
# ---------------------------------------------------------------------------

def print_summary(devices: list[dict], color: bool = True):
    """Combined overview table for all reviewed devices."""
    timestamp = now_iso()
    reset = RESET if color else ""

    # sort most critical first
    devices = sorted(devices, key=lambda d: (VERDICT_ORDER.get(
        d["summary"]["verdict"], 9), d.get("hostname") or d["source"]))

    name_w = max([len("Device")] + [len(d.get("hostname") or
                 Path(d["source"]).name) for d in devices])
    name_w = min(name_w, 32)

    print(f"\n{'=' * 78}")
    print(f"  FORTIBLEED — COMBINED OVERVIEW ({len(devices)} devices)")
    print(f"  {timestamp}")
    print(f"{'=' * 78}")
    header = f"  {'Device':<{name_w}}  {'PASS':>4} {'WARN':>4} {'FAIL':>4} {'SKIP':>4}  Verdict"
    print(header)
    print(f"  {'-' * (len(header) - 2)}")
    for d in devices:
        s = d["summary"]
        nm = (d.get("hostname") or Path(d["source"]).name)[:name_w]
        v = s["verdict"]
        vc = VERDICT_COLOR.get(v, "") if color else ""
        print(f"  {nm:<{name_w}}  {s['pass']:>4} {s['warn']:>4} {s['fail']:>4} "
              f"{s['skip']:>4}  {vc}{v}{reset}")
    print(f"  {'-' * (len(header) - 2)}")

    # aggregate counts
    agg = {v: 0 for v in VERDICT_ORDER}
    for d in devices:
        agg[d["summary"]["verdict"]] = agg.get(d["summary"]["verdict"], 0) + 1
    print(f"  Exposed: {agg[VERDICT_EXPOSED]}   "
          f"Review warnings: {agg[VERDICT_REVIEW]}   "
          f"Incomplete: {agg[VERDICT_INCOMPLETE]}   "
          f"Not affected: {agg[VERDICT_CLEAN]}")
    print(f"{'=' * 78}")

    # ---- per-device details: firmware, mgmt list, admins/trusthost, SSO ----
    def c(text: str, code: str) -> str:
        return f"{code}{text}{reset}" if color else text

    print("\n  PER-DEVICE DETAILS")
    print(f"  {'-' * 74}")
    for d in devices:
        f = d.get("facts") or {}
        nm = d.get("hostname") or Path(d["source"]).name
        print(f"\n  {c(nm, BOLD)}")

        # Firmware / password hash strength
        fw = f.get("firmware") or "?"
        lockout = f.get("weaker_lockout")
        if f.get("pbkdf2_supported") is True:
            # PBKDF2-capable is only truly safe once old hashes are purged
            if lockout == "enable":
                hashtxt = c("PBKDF2-capable", OK_C)
            else:
                hashtxt = c("PBKDF2-capable (purge unconfirmed)", WARN_C)
        elif f.get("pbkdf2_supported") is False:
            hashtxt = c("pre-PBKDF2 (SHA-256)", BAD_C)
        else:
            hashtxt = "?"
        lock_txt = (c("lockout: enable", OK_C) if lockout == "enable"
                    else c(f"lockout: {lockout or '?'}", BAD_C if lockout == "disable" else WARN_C))
        residual_txt = c("  RESIDUAL SHA-256!", BAD_C) if f.get("residual_sha256") else ""
        print(f"    Firmware/hash : {fw}  ({hashtxt}, {lock_txt}){residual_txt}")

        # Management exposure (list)
        mgmt = f.get("mgmt_exposed") or []
        mgmt_txt = c("none", OK_C) if not mgmt else ", ".join(mgmt)
        print(f"    Mgmt exposure : {mgmt_txt}")

        # Admin accounts + trusthost
        admins = f.get("admins") or []
        admins_txt = ", ".join(admins) if admins else "?"
        if not admins:
            th_txt = c("?", WARN_C)
        elif f.get("all_admins_trusthost"):
            th_txt = c("YES — all have trusthost", OK_C)
        else:
            missing_th = f.get("admins_without_trusthost") or []
            th_txt = c(f"NO — missing: {', '.join(missing_th)}", BAD_C)
        print(f"    Admin accounts: {admins_txt}")
        print(f"    All trusthost : {th_txt}")

        # FortiCloud SSO
        sso = f.get("forticloud_sso")
        if sso == "disable":
            sso_txt = c("disabled", OK_C)
        elif sso == "enable":
            sso_txt = c("ENABLED — verify against CVE-2026-24858", WARN_C)
        else:
            sso_txt = c("unknown (not in output)", WARN_C)
        print(f"    FortiCloud SSO: {sso_txt}")
    print(f"{'=' * 78}")

    # ---- triggering findings: which checks gave FAIL/WARN on which devices ----
    flagged = [d for d in devices
               if d["summary"]["fail"] or d["summary"]["warn"]]
    if flagged:
        print("\n  TRIGGERING FINDINGS (why the verdict is not clean)")
        print(f"  {'-' * 74}")
        for d in flagged:
            nm = d.get("hostname") or Path(d["source"]).name
            fails = [r["name"] for r in d["results"] if r["status"] == CheckResult.FAIL]
            warns = [r["name"] for r in d["results"] if r["status"] == CheckResult.WARN]
            print(f"\n  {c(nm, BOLD)}")
            for n in fails:
                print(f"    {c('[FAIL]', BAD_C)} {n}")
            for n in warns:
                print(f"    {c('[WARN]', WARN_C)} {n}")
        print(f"\n{'=' * 78}")

    # ---- action plan for follow-up ----
    plan = build_action_plan(devices)
    if plan:
        print_action_plan(plan, color=color)
        print(f"{'=' * 78}")

    # ---- verdict-dependent assessment & caveats ----
    overall = worst_verdict([d["summary"]["verdict"] for d in devices])
    print()
    print_disclaimer(overall, color=color)
    print(f"{'=' * 78}\n")


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def collect_files(path: Path, pattern: str, recursive: bool) -> list[Path]:
    """Find config files in a directory, skipping the tool's own artifacts so
    a re-run in place never feeds the tool its own output."""
    skip_names = {"fortibleed_commands.txt", "requirements.txt", DEFAULT_ALLOWLIST,
                  "README.md", "LICENSE"}
    skip_suffix = {".py", ".md", ".sh", ".json"}
    globber = path.rglob if recursive else path.glob
    files = []
    for p in sorted(globber(pattern)):
        if not p.is_file():
            continue
        # pathlib's glob matches dotfiles — skip hidden/tool directories
        # (.git, .venv, __pycache__, ...) and hidden files.
        rel = p.relative_to(path)
        if any(part.startswith(".") or part == "__pycache__" for part in rel.parts):
            continue
        if p.name in skip_names or p.suffix.lower() in skip_suffix:
            continue
        files.append(p)
    return files


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_device(path: Path) -> tuple[str | None, dict[str, str]] | None:
    """Read and parse one file. Return (hostname, sections) or None when the
    file does not look like FortiGate output/config."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"ERROR: could not read {path} — {e}", file=sys.stderr)
        return None
    sections = parse_sections(content)
    # Also understand a full config file (backup/export without prompt lines)
    # and hybrid dumps (prompt + embedded 'show full-configuration').
    for k, v in parse_full_config(content).items():
        sections.setdefault(k, v)
    if not sections:
        return None
    return extract_hostname(sections), sections


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?",
                        help="File OR directory with FortiGate output(s)/config(s)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour (for pipes, logs, CI)")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Emit structured JSON instead of the report")
    parser.add_argument("--glob", default="*",
                        help="File pattern in directory mode (default: * — all "
                             "files; anything that isn't FortiGate output/config "
                             "is skipped automatically)")
    parser.add_argument("--recursive", action="store_true",
                        help="Descend into subdirectories (directory mode)")
    parser.add_argument("--details", action="store_true",
                        help="In directory mode, also print the full per-device report")
    parser.add_argument("--allowlist", default=None,
                        help=f"Path to the allowlist of approved mgmt interfaces "
                             f"(default: {DEFAULT_ALLOWLIST} next to the input)")
    parser.add_argument("--review", action="store_true",
                        help="Interactively ask whether each exposed mgmt interface "
                             "is OK and save approvals to the allowlist (PASS from then on)")
    parser.add_argument("--skip-checks", default=None, metavar="ID,ID,...",
                        help="Comma-separated check ids to skip (see --list-checks). "
                             "E.g. environments without admin MFA: "
                             "--skip-checks admin-mfa")
    parser.add_argument("--list-checks", action="store_true",
                        help="List all check ids and exit")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.list_checks:
        print_check_list()
        sys.exit(EXIT_OK)

    if not args.path:
        parser.error("path is required (or use --list-checks)")

    skip = parse_skip_arg(args.skip_checks)
    color = want_color(args.no_color)
    target = Path(args.path)

    if not target.exists():
        die(f"path not found — {target}")

    # Allowlist: the default lives next to the input (dir, or the file's dir)
    base_dir = target if target.is_dir() else target.parent
    allowlist_path = Path(args.allowlist) if args.allowlist else base_dir / DEFAULT_ALLOWLIST
    allowlist = load_allowlist(allowlist_path)

    # ---------- single file ----------
    if target.is_file():
        dev = load_device(target)
        if dev is None:
            die("neither FortiGate prompt lines nor config blocks found. "
                "Is the file a FortiGate terminal log or config file?")
        hostname, sections = dev
        if args.review:
            review_interfaces([(hostname, sections)], allowlist, allowlist_path)
        results = run_checks(sections, hostname, allowlist, skip)
        facts = device_facts(sections, hostname, allowlist)
        print_report(results, str(target), color=color,
                     as_json=args.json_out, hostname=hostname, facts=facts)
        sys.exit(verdict_exit_code([compute_verdict(results)]))

    # ---------- directory / batch ----------
    files = collect_files(target, args.glob, args.recursive)
    if not files:
        die(f"no files matched '{args.glob}' in {target}"
            + ("" if args.recursive else " (try --recursive)"))

    loaded: list[tuple[Path, str | None, dict[str, str]]] = []
    skipped: list[str] = []
    for path in files:
        dev = load_device(path)
        if dev is None:
            skipped.append(path.name)
            continue
        loaded.append((path, dev[0], dev[1]))

    if not loaded:
        die("none of the files looked like FortiGate output. "
            "Skipped: " + ", ".join(skipped))

    if args.review:
        review_interfaces([(h, s) for _, h, s in loaded], allowlist, allowlist_path)

    devices: list[dict] = []
    for path, hostname, sections in loaded:
        results = run_checks(sections, hostname, allowlist, skip)
        facts = device_facts(sections, hostname, allowlist)
        devices.append(device_doc(results, str(path), hostname, facts))
        if args.details and not args.json_out:
            print_report(results, str(path), color=color, hostname=hostname, facts=facts)

    if args.json_out:
        agg = {v: 0 for v in VERDICT_ORDER}
        for d in devices:
            agg[d["summary"]["verdict"]] = agg.get(d["summary"]["verdict"], 0) + 1
        overall = worst_verdict([d["summary"]["verdict"] for d in devices])
        print(json.dumps({
            "timestamp": now_iso(),
            "campaign": CAMPAIGN,
            "scanned": str(target),
            "device_count": len(devices),
            "skipped_files": skipped,
            "aggregate": agg,
            "overall_verdict": overall,
            "action_plan": [{"action": a, "devices": devs}
                            for a, devs in build_action_plan(devices)],
            "disclaimer": " ".join(p for p in disclaimer_lines(overall) if p),
            "devices": devices,
        }, indent=2, ensure_ascii=False))
    else:
        print_summary(devices, color=color)
        if skipped:
            print(f"  Skipped (not FortiGate output): {', '.join(skipped)}\n")

    sys.exit(verdict_exit_code([d["summary"]["verdict"] for d in devices]))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)          # conventional 128 + SIGINT
    except BrokenPipeError:
        # Output was piped into something that closed early (e.g. `head`).
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)          # conventional 128 + SIGPIPE
