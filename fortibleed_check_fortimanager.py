#!/usr/bin/env python3
"""
fortibleed_check_fortimanager — FortiBleed exposure check via FortiManager.

Same analysis as fortibleed_check_offline.py, but instead of reading a file
this script pulls the configuration straight from FortiManager over the
JSON-RPC API and runs the checks for every managed FortiGate in an ADOM.

The analysis engine is reused 1:1 from fortibleed_check_offline.py (imported),
so the assessments are identical to the file-based edition. Only the INPUT
layer is new: instead of parsing a backup file, we build a FortiGate config
text from the FortiManager device DB and feed it through the existing parser.

Requires a FortiManager API key (token) for an admin with rpc-permit
(FortiManager 7.2.2+). Standard library only — no third-party dependencies.

Configuration: fill in the fields in the CONFIGURATION block below, or
override with flags / environment variables (FMG_HOST, FMG_API_KEY,
FMG_ADMIN, FMG_ADOM).

Usage:
    python3 fortibleed_check_fortimanager.py --host https://fmg.example.net --apikey KEY
    python3 fortibleed_check_fortimanager.py --adom production --details
    python3 fortibleed_check_fortimanager.py --device FGT-BRANCH-01 --json
    python3 fortibleed_check_fortimanager.py --selftest

Exit codes:
    0  not affected — no exposure or IoC signs found
    1  review warnings, or incomplete data for some devices
    2  exposed — one or more critical findings
    3  operational error (no API key, unreachable FortiManager, unknown device)
"""

from __future__ import annotations

# ============================================================================
# >>> CONFIGURATION (edit here) <<<
# ============================================================================
FMG_HOST   = "https://fortimanager.example.com"  # FortiManager URL (https://host[:port])
API_KEY    = "PUT-API-KEY-HERE"                   # API key (token) for an admin with rpc-permit
ADMIN      = "admin"                              # Admin user the key belongs to (login/log)
ADOM       = "root"                               # ADOM to review
# ----------------------------------------------------------------------------
VERIFY_SSL = False        # Verify FortiManager's TLS certificate (recommended: True
                          # once a proper certificate is in place)
DEVICE     = None         # None = all devices in the ADOM. Otherwise a device name (str).
# ============================================================================

import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import NoReturn

__version__ = "2.0.1"

EXIT_ERROR = 3


def die(message: str, code: int = EXIT_ERROR) -> NoReturn:
    """Report an operational failure on stderr and exit — no traceback."""
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(code)


# Import the existing analysis engine (must live in the same directory).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import fortibleed_check_offline as fb
except ImportError as e:
    die("cannot import fortibleed_check_offline.py — it must live in the same "
        "directory as this script.\n  " + str(e))


# ---------------------------------------------------------------------------
# FortiManager JSON-RPC client (stdlib only, no external dependencies)
# ---------------------------------------------------------------------------

class FMGError(RuntimeError):
    pass


class FortiManager:
    """Minimal JSON-RPC client for FortiManager.

    Uses token / API-key authentication: the key is sent in the HTTP header
    'Authorization: Bearer <key>' (FortiManager 7.2.2+). With a token there is
    no separate login/session — the key authorizes every call.
    """

    def __init__(self, host: str, api_key: str, verify_ssl: bool = False,
                 timeout: int = 30):
        self.url = host.rstrip("/") + "/jsonrpc"
        self.api_key = api_key
        self.timeout = timeout
        self._id = 0
        if verify_ssl:
            self._ctx = ssl.create_default_context()
        else:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _post(self, method: str, params: list) -> list:
        self._id += 1
        body = json.dumps({"method": method, "params": params,
                           "id": self._id}).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ctx) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise FMGError(f"HTTP {e.code} from FortiManager: {e.reason}. "
                           "Check the URL, the API key, and that the admin user "
                           "has rpc-permit.")
        except urllib.error.URLError as e:
            raise FMGError(f"cannot reach FortiManager at {self.url}: {e.reason}")
        results = payload.get("result", [])
        if not results:
            raise FMGError(f"empty response from FortiManager ({method}).")
        return results

    def get(self, url: str, **data) -> object:
        """JSON-RPC 'get' on a device-DB/dvmdb path. Returns the 'data' part.
        Raises FMGError on a non-zero status code."""
        params = [{"url": url, **data}]
        res = self._post("get", params)[0]
        status = res.get("status", {})
        code = status.get("code", -1)
        if code != 0:
            raise FMGError(f"FortiManager error on '{url}': "
                           f"{status.get('message', 'unknown')} (code {code})")
        return res.get("data")

    def try_get(self, url: str, **data) -> tuple[object, str | None]:
        """Like get(), but returns (data, None) or (None, error text) instead
        of raising — so a single missing section does not stop the whole run."""
        try:
            return self.get(url, **data), None
        except FMGError as e:
            return None, str(e)


# ---------------------------------------------------------------------------
# JSON -> FortiGate-CLI rendering
# ---------------------------------------------------------------------------
#
# The existing engine understands a FortiGate backup/config text
# (parse_full_config). We therefore build such a text from the structured JSON
# objects FortiManager returns, and let the proven parser do the rest.

# Sections and their scope on the FortiGate (global vs. per-VDOM). The key is
# the CLI name (what parse_full_config stores under "show <name>"), the value
# is the FMG path fragment.
GLOBAL_SECTIONS = {
    "system global":              "system/global",
    "system admin":               "system/admin",
    "system api-user":            "system/api-user",
    "system password-policy":     "system/password-policy",
    "system interface":           "system/interface",
    "system automation-action":   "system/automation-action",
    "system automation-trigger":  "system/automation-trigger",
}
VDOM_SECTIONS = {
    "vpn ssl settings":           "vpn/ssl/settings",
    "user local":                 "user/local",
    "firewall local-in-policy":   "firewall/local-in-policy",
}

# Table sections (list of edit blocks) vs. single-object sections (set lines).
TABLE_SECTIONS = {
    "system admin", "system api-user", "system interface",
    "system automation-action", "system automation-trigger",
    "user local", "firewall local-in-policy",
}


def _render_value(v) -> str | None:
    """Render one attribute value to CLI form. Return None for complex values
    (nested tables) that should be dropped."""
    if v is None:
        return None
    if isinstance(v, bool):
        return "enable" if v else "disable"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        # A list of scalars -> space-separated (allowaccess, ip [addr mask],
        # trusthostN [addr mask] etc.). Lists of dicts/lists are dropped.
        if all(not isinstance(x, (list, dict)) for x in v):
            return " ".join("" if x is None else str(x) for x in v).strip()
        return None
    return None


def _edit_name(item: dict) -> str:
    for key in ("name", "policyid", "id", "_seq"):
        if key in item and item[key] not in (None, ""):
            return str(item[key])
    return "0"


def _render_set_lines(obj: dict, indent: str) -> list[str]:
    lines = []
    for key, val in obj.items():
        if key in ("q_origin_key", "oid", "obj seq"):
            continue
        rendered = _render_value(val)
        if rendered is None or rendered == "":
            continue
        # Quote where the CLI would (names, scripts, keys).
        if any(s in rendered for s in (" ", "/", "\n")) and \
                key in ("script", "ssh-public-key", "hostname", "comment", "comments"):
            lines.append(f'{indent}set {key} "{rendered}"')
        else:
            lines.append(f"{indent}set {key} {rendered}")
    return lines


def _render_section(cli_name: str, data) -> str:
    """Render a fetched section as a 'config ... end' block."""
    out = [f"config {cli_name}"]
    if cli_name in TABLE_SECTIONS:
        items = data if isinstance(data, list) else ([data] if data else [])
        for item in items:
            if not isinstance(item, dict):
                continue
            out.append(f'    edit "{_edit_name(item)}"')
            out.extend(_render_set_lines(item, "        "))
            out.append("    next")
    else:
        obj = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
        out.extend(_render_set_lines(obj, "    "))
    out.append("end")
    return "\n".join(out)


def _device_version(dev: dict) -> tuple[int, int, int, bool]:
    """Derive (major, minor, patch, patch_known) from a dvmdb device record."""
    def _int(x, default=0):
        try:
            return int(x)
        except (TypeError, ValueError):
            return default
    major = _int(dev.get("os_ver"))
    minor = _int(dev.get("mr"))
    patch = dev.get("patch")
    patch_known = patch is not None
    return major, minor, _int(patch), patch_known


# ---------------------------------------------------------------------------
# Fetch and analyse one device
# ---------------------------------------------------------------------------

def fetch_device_sections(fmg: FortiManager, adom: str, dev: dict,
                          verbose: bool = False) -> tuple[dict[str, str], list[str]]:
    """Fetch all relevant sections for one device; return (sections, errors).

    `sections` has the shape fortibleed_check_offline expects
    ('show <path>' / 'show full-configuration <path>' + 'get system status').
    """
    name = dev["name"]
    base = f"/pm/config/device/{name}"
    vdoms = dev.get("vdom")
    if isinstance(vdoms, list) and vdoms:
        vdom_names = [v.get("name", "root") if isinstance(v, dict) else str(v)
                      for v in vdoms]
    else:
        vdom_names = ["root"]

    fetched_ok: set[str] = set()
    errors: list[str] = []
    blocks: list[str] = []

    # ---- Global-scope sections ----
    for cli_name, frag in GLOBAL_SECTIONS.items():
        data, err = fmg.try_get(f"{base}/global/{frag}")
        if err is not None:
            errors.append(f"{cli_name}: {err}")
            continue
        fetched_ok.add(cli_name)
        blocks.append(_render_section(cli_name, data))
        if verbose:
            print(f"    [ok] global/{frag}", file=sys.stderr)

    # ---- VDOM-scope sections (merged across VDOMs) ----
    for cli_name, frag in VDOM_SECTIONS.items():
        merged: list = []
        single = None
        any_ok = False
        for vd in vdom_names:
            data, err = fmg.try_get(f"{base}/vdom/{vd}/{frag}")
            if err is not None:
                continue
            any_ok = True
            if cli_name in TABLE_SECTIONS:
                if isinstance(data, list):
                    merged.extend(data)
                elif isinstance(data, dict):
                    merged.append(data)
            else:
                # single object: take the first VDOM where it exists/is enabled
                obj = data[0] if isinstance(data, list) and data else data
                if single is None and isinstance(obj, dict):
                    single = obj
            if verbose:
                print(f"    [ok] vdom/{vd}/{frag}", file=sys.stderr)
        if not any_ok:
            errors.append(f"{cli_name}: not fetched from any VDOM")
            continue
        fetched_ok.add(cli_name)
        blocks.append(_render_section(cli_name, merged if cli_name in TABLE_SECTIONS else single))

    # ---- Build a config text with a #config-version header (drives the
    #      firmware check) ----
    model = dev.get("platform_str") or dev.get("os_type") or "FGT"
    maj, minr, patch, patch_known = _device_version(dev)
    hostname = dev.get("hostname") or name
    header = (f"#config-version={model}-{maj}.{minr}.{patch}"
              f"-FW-build0000-000000:opmode=0:vdom=0")
    text = header + "\n" + "\n".join(blocks) + "\n"

    sections = fb.parse_full_config(text)

    # parse_full_config sets empty placeholders for expected sections. That is
    # correct for "absent from the config" (= not configured), but NOT for
    # sections we genuinely could not fetch. Remove the unfetched ones so the
    # checks report SKIP instead of a false PASS.
    expected = set(GLOBAL_SECTIONS) | set(VDOM_SECTIONS)
    for cli_name in expected - fetched_ok:
        sections.pop(f"show {cli_name}", None)
        sections.pop(f"show full-configuration {cli_name}", None)

    # Ensure the synthetic 'get system status' carries the right hostname/firmware.
    ver_note = "" if patch_known else "  (patch level unknown from FortiManager)"
    sections["get system status"] = (
        f"Version: {model} v{maj}.{minr}.{patch},build0000 (GA){ver_note}\n"
        f"Hostname: {hostname}")

    return sections, errors


# ---------------------------------------------------------------------------
# Selftest (offline) — run the engine against mock FMG data, no network
# ---------------------------------------------------------------------------

def _selftest() -> int:
    """Mini-mock of FMG responses -> rendering -> engine. Verifies the
    pipeline without network access."""
    class MockFMG:
        DATA = {
            "system global": {"hostname": "FGT-SELFTEST", "admin-https-redirect": "enable",
                              "admin-lockout-threshold": "3", "admin-forticloud-sso-login": "disable"},
            "system admin": [
                {"name": "admin", "trusthost1": ["10.0.0.0", "255.0.0.0"], "two-factor": "disable"},
                {"name": "support", "two-factor": "disable"},  # suspicious name + no trusthost
            ],
            "system api-user": [{"name": "tmp-api", "trusthost1": ["0.0.0.0", "0.0.0.0"]}],
            "system password-policy": {"status": "enable", "minimum-length": "8",
                                       "login-lockout-upon-downgrade": "disable"},
            "system interface": [
                {"name": "wan1", "ip": ["203.0.113.10", "255.255.255.0"],
                 "allowaccess": ["ping", "https", "ssh"], "role": "wan"},
                {"name": "internal", "ip": ["10.10.0.1", "255.255.255.0"],
                 "allowaccess": ["ping", "https"], "role": "lan"},
            ],
            "system automation-action": [],
            "system automation-trigger": [],
            "vpn ssl settings": {"status": "enable", "source-interface": "wan1", "port": "10443"},
            "user local": [{"name": "vpnuser", "type": "password", "two-factor": "disable"}],
            "firewall local-in-policy": [],
        }

        def try_get(self, url, **data):
            for cli, frag in {**GLOBAL_SECTIONS, **VDOM_SECTIONS}.items():
                if url.endswith("/" + frag):
                    return self.DATA.get(cli), None
            return None, "not in mock"

    dev = {"name": "FGT-SELFTEST", "platform_str": "FortiGate-60F",
           "os_ver": 7, "mr": 4, "patch": 3, "vdom": [{"name": "root"}]}
    sections, errors = fetch_device_sections(MockFMG(), "root", dev, verbose=False)
    results = fb.run_checks(sections, "FGT-SELFTEST", set())
    facts = fb.device_facts(sections, "FGT-SELFTEST", set())
    fb.print_report(results, "selftest (mock FMG)", color=fb.want_color(False),
                    hostname="FGT-SELFTEST", facts=facts)
    if errors:
        print("Fetch notes:", "; ".join(errors))
    # Expected findings as a sanity check
    names = {r.name: r.status for r in results}
    assert names.get("Management exposure (allowaccess)") in (fb.CheckResult.WARN,
        fb.CheckResult.FAIL), "expected mgmt exposure on wan1"
    assert names.get("REST API admins (api-user)") == fb.CheckResult.FAIL, \
        "expected FAIL on api-user without a real trusthost"
    print("\nSELFTEST OK — pipeline (FMG JSON -> render -> engine) works.")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=os.environ.get("FMG_HOST", FMG_HOST),
                        help="FortiManager URL (default from config/ENV FMG_HOST)")
    parser.add_argument("--apikey", default=os.environ.get("FMG_API_KEY", API_KEY),
                        help="API key (default from config/ENV FMG_API_KEY)")
    parser.add_argument("--admin", default=os.environ.get("FMG_ADMIN", ADMIN),
                        help="Admin user the key belongs to (for the log)")
    parser.add_argument("--adom", default=os.environ.get("FMG_ADOM", ADOM),
                        help="ADOM to review")
    parser.add_argument("--device", default=DEVICE,
                        help="Only this device (default: all in the ADOM)")
    parser.add_argument("--insecure", action="store_true", default=not VERIFY_SSL,
                        help="Skip TLS certificate verification (default follows config)")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Force TLS certificate verification on")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour (for pipes, logs, CI)")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Emit structured JSON instead of the report")
    parser.add_argument("--details", action="store_true",
                        help="Also print the full per-device report next to the overview")
    parser.add_argument("--skip-checks", default=None, metavar="ID,ID,...",
                        help="Comma-separated check ids to skip (see the offline "
                             "script's --list-checks)")
    parser.add_argument("--verbose", action="store_true",
                        help="Log every fetched section to stderr")
    parser.add_argument("--selftest", action="store_true",
                        help="Run an offline pipeline test against mock data (no network)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.selftest:
        sys.exit(_selftest())

    skip = fb.parse_skip_arg(args.skip_checks)

    if not args.apikey or args.apikey == "PUT-API-KEY-HERE":
        die("no API key. Fill in API_KEY at the top, set ENV FMG_API_KEY, "
            "or use --apikey.")
    if not args.host or "example.com" in args.host:
        die("FortiManager host not set. Fill in FMG_HOST at the top or use --host.")

    verify = args.verify_ssl or not args.insecure
    color = fb.want_color(args.no_color)
    fmg = FortiManager(args.host, args.apikey, verify_ssl=verify)

    # ---- Fetch the device list for the ADOM ----
    try:
        dev_data = fmg.get(f"/dvmdb/adom/{args.adom}/device")
    except FMGError as e:
        die(f"fetching the device list failed (ADOM '{args.adom}', admin "
            f"'{args.admin}'): {e}")
    devices_raw = dev_data if isinstance(dev_data, list) else [dev_data] if dev_data else []
    if args.device:
        devices_raw = [d for d in devices_raw if d.get("name") == args.device]
        if not devices_raw:
            die(f"device '{args.device}' not found in ADOM '{args.adom}'.")
    if not devices_raw:
        die(f"no devices in ADOM '{args.adom}'.")

    if not args.json_out:
        print(f"FortiManager {args.host} — ADOM '{args.adom}' — "
              f"{len(devices_raw)} device(s)\n")

    devices: list[dict] = []
    for dev in devices_raw:
        name = dev.get("name", "?")
        if args.verbose:
            print(f"  Fetching {name} ...", file=sys.stderr)
        sections, fetch_errors = fetch_device_sections(fmg, args.adom, dev,
                                                       verbose=args.verbose)
        hostname = fb.extract_hostname(sections) or name
        results = fb.run_checks(sections, hostname, set(), skip)
        facts = fb.device_facts(sections, hostname, set())
        doc = fb.device_doc(results, f"FMG:{args.adom}/{name}", hostname, facts)
        if fetch_errors:
            doc["fetch_errors"] = fetch_errors
        devices.append(doc)
        if args.details and not args.json_out:
            fb.print_report(results, f"FMG:{args.adom}/{name}", color=color,
                            hostname=hostname, facts=facts)
            if fetch_errors:
                print("  Unfetched sections (reported as SKIP): "
                      + "; ".join(fetch_errors) + "\n")

    # ---- Output ----
    if args.json_out:
        agg = {v: 0 for v in fb.VERDICT_ORDER}
        for d in devices:
            agg[d["summary"]["verdict"]] = agg.get(d["summary"]["verdict"], 0) + 1
        overall = fb.worst_verdict([d["summary"]["verdict"] for d in devices])
        print(json.dumps({
            "timestamp": fb.now_iso(),
            "campaign": fb.CAMPAIGN,
            "source": "FortiManager",
            "fortimanager": args.host,
            "adom": args.adom,
            "device_count": len(devices),
            "aggregate": agg,
            "overall_verdict": overall,
            "action_plan": [{"action": a, "devices": devs}
                            for a, devs in fb.build_action_plan(devices)],
            "disclaimer": " ".join(p for p in fb.disclaimer_lines(overall) if p),
            "devices": devices,
        }, indent=2, ensure_ascii=False))
    else:
        if len(devices) == 1 and not args.details:
            d = devices[0]
            results = [fb.CheckResult(r["name"], r["status"], r["detail"])
                       for r in d["results"]]
            fb.print_report(results, d["source"], color=color,
                            hostname=d.get("hostname"), facts=d.get("facts"))
            if d.get("fetch_errors"):
                print("  Unfetched sections (reported as SKIP): "
                      + "; ".join(d["fetch_errors"]) + "\n")
        else:
            fb.print_summary(devices, color=color)

    sys.exit(fb.verdict_exit_code([d["summary"]["verdict"] for d in devices]))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)          # conventional 128 + SIGINT
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)          # conventional 128 + SIGPIPE
