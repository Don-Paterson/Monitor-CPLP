"""
Collects a CPLP (Check Point Live Patch, sk185114) snapshot from one Gaia host.

Snapshot layout:
{
  "host": "A-GW-01", "ip": "10.1.1.2", "role": "Gateway",
  "collected_at": "2026-10-01T15:00:00Z", "ok": true, "error": null,
  "login_shell": "clish",
  "sections": {
     "<section>": {"ok": bool, "rc": int, "data": <parsed>, "raw": "<text>", "error": str|None}
  }
}
"""
import time
import logging
from datetime import datetime, timezone

from cplpmon.gaia_shell import GaiaShell, GaiaShellError
from cplpmon import parsers

logger = logging.getLogger("cplpmon.collector")

AU = "${AU_DIR:-/opt/AutoUpdater}"

# Section -> (command, description). Commands run in expert mode.
COMMANDS = {
    "system": (
        'echo "HOST=$(hostname)"; echo "REL=$(cat /etc/cp-release 2>/dev/null)"; '
        'echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
        "Hostname / release",
    ),
    "cplp_list": (
        "cplp list",
        "Live Patches (cplp list)",
    ),
    "bundles": (
        "cpinfo -y all 2>/dev/null | egrep -i 'URGENT|JUMBO'",
        "CPLP bundle + Jumbo take (cpinfo -y all | egrep URGENT|JUMBO)",
    ),
    "au_component": (
        "autoupdatercli show urgent_security_updates 2>&1; "
        f"grep -i 'urgent_security_updates' {AU}/productsConfig/products_config.xml 2>/dev/null",
        "AutoUpdater CPLP component (urgent_security_updates)",
    ),
    "consent": (
        "for p in AllowReceivingDataFromCheckPoint AllowReceivingDataFromCheckPointNonSecurity "
        "AllowSendingDataToCheckPoint AllowSendingSensitiveDataToCheckPoint; do "
        "echo \"GAIA $p=$(dbget $p 2>/dev/null)\"; done; "
        "grep -A 10 DownloadAccess $CPDIR/tmp/umis_objects.C 2>/dev/null | grep ':allow' | "
        "sed 's/^[[:space:]]*/EFFECTIVE /'",
        "Consent flags (sk175504) - Download Security delivers CPLP",
    ),
    "cplp_logs": (
        f"find /var/log {AU} $CPDIR/log $FWDIR/log -maxdepth 3 -type f "
        "\\( -iname '*cplp*' -o -iname '*livepatch*' -o -iname '*live_patch*' -o -iname '*urgent*' \\) "
        "-printf '%TY-%Tm-%TdT%TH:%TM:%TS %s %p\\n' 2>/dev/null | sort -r | head -25",
        "CPLP log files",
    ),
}

SECTION_TITLES = {k: v[1] for k, v in COMMANDS.items()}
SECTION_TITLES["cplp_log_tail"] = "Newest CPLP log (tail)"
SECTION_TITLES["au_cplp_lines"] = "AutoUpdater log lines for urgent_security_updates"


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(section, raw, settings):
    if section == "system":
        return parsers.parse_system(raw)
    if section == "cplp_list":
        return parsers.parse_cplp_list(raw)
    if section == "bundles":
        return parsers.parse_bundles(raw)
    if section == "au_component":
        return parsers.parse_au_component(raw)
    if section == "consent":
        return parsers.parse_consent(raw)
    if section == "cplp_logs":
        return parsers.parse_file_list(raw)
    return None


def collect_host(host_cfg: dict, creds: dict, settings: dict) -> dict:
    col = settings.get("collection", {})
    timeout = int(col.get("command_timeout_seconds", 240))
    skip = set(col.get("skip_sections", []))
    ssh = dict(creds.get("ssh", {}))
    ssh.update(host_cfg.get("ssh", {}))  # optional per-host override

    snap = {
        "host": host_cfg["name"],
        "ip": host_cfg["ip"],
        "role": host_cfg.get("role", ""),
        "collected_at": _utc_now(),
        "ok": False,
        "error": None,
        "login_shell": None,
        "duration_s": None,
        "sections": {},
    }
    t0 = time.time()
    shell = GaiaShell(host_cfg["ip"], ssh.get("user", "admin"), ssh.get("password", ""),
                      ssh.get("expert_password"), port=host_cfg.get("ssh_port", 22),
                      login_timeout=int(col.get("login_timeout_seconds", 90)))
    try:
        shell.open()
        snap["login_shell"] = shell.login_shell
        for section, (cmd, _title) in COMMANDS.items():
            if section in skip:
                continue
            try:
                r = shell.run(cmd, timeout=timeout)
                raw = r["output"]
                sec = {"ok": not r["timed_out"], "rc": r["rc"], "raw": raw,
                       "error": "timed out" if r["timed_out"] else None, "data": None}
                if not r["timed_out"]:
                    sec["data"] = _parse(section, raw, settings)
                    if section == "cplp_list":
                        # 'command not found' etc. must not be diffed as "every patch removed"
                        d = sec["data"]
                        if r["rc"] not in (0, None) and not d["patches"]:
                            sec["ok"] = False
                            sec["error"] = ("cplp not found - CPLP not installed?"
                                            if r["rc"] == 127 or "not found" in raw.lower()
                                            else f"exit code {r['rc']}")
                    elif r["rc"] not in (0, None) and not sec["data"]:
                        sec["ok"] = False
                        sec["error"] = f"exit code {r['rc']}"
                snap["sections"][section] = sec
            except GaiaShellError as e:
                snap["sections"][section] = {"ok": False, "rc": None, "raw": "", "data": None, "error": str(e)}
                raise

        n = int(col.get("log_tail_lines", 60))
        # Tail of the newest CPLP log file, if there is one
        logs = (snap["sections"].get("cplp_logs") or {}).get("data") or []
        if logs:
            path = logs[0]["path"].replace("'", "")
            r = shell.run(f"tail -n {n} '{path}'", timeout=30)
            snap["sections"]["cplp_log_tail"] = {"ok": not r["timed_out"], "rc": r["rc"],
                                                 "raw": r["output"], "data": {"path": path}, "error": None}
        # What AutoUpdater logged about the CPLP component (downloads / installs / failures)
        if "au_cplp_lines" not in skip:
            r = shell.run(
                f"find /var/log {AU} $CPDIR/log -maxdepth 3 -type f -iname '*autoupdat*' 2>/dev/null "
                f"| xargs -r grep -ih 'urgent' 2>/dev/null | tail -n {n}", timeout=60)
            snap["sections"]["au_cplp_lines"] = {"ok": not r["timed_out"], "rc": r["rc"],
                                                 "raw": r["output"], "data": None, "error": None}
        snap["ok"] = True
    except GaiaShellError as e:
        snap["error"] = str(e)
        logger.error(f"{host_cfg['name']}: {e}")
    except Exception as e:  # never let one host kill the poller
        snap["error"] = f"{type(e).__name__}: {e}"
        logger.exception(f"{host_cfg['name']}: unexpected error")
    finally:
        shell.close()
        snap["duration_s"] = round(time.time() - t0, 1)
    return snap
