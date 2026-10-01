"""
Parsers for the CPLP-related command output collected from Gaia hosts.
Kept separate from the SSH code so they can be unit-tested with sample output.
"""
import re

PIDS_RE = re.compile(r"^\d+/\d+$")
DATE_RE = re.compile(r"^\d{4}-\d\d-\d\d$")
TIME_RE = re.compile(r"^\d\d:\d\d(:\d\d)?$")
SK_RE = re.compile(r"(?i)\bsk\d{5,8}\b")
CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def parse_system(raw: str) -> dict:
    out = {"hostname": None, "release": None, "utc_time": None}
    for l in (x.strip() for x in raw.split("\n")):
        if l.startswith("HOST="):
            out["hostname"] = l[5:]
        elif l.startswith("REL="):
            out["release"] = l[4:]
        elif l.startswith("UTC="):
            out["utc_time"] = l[4:]
    return out


def version_from_release(release: str):
    """'Check Point Gaia R82.10' -> 'R82.10'"""
    m = re.search(r"\bR\d{2}(?:\.\d{1,2})?\b", release or "")
    return m.group(0) if m else None


def parse_cplp_list(raw: str) -> dict:
    """'cplp list' (sk185114):

    ID(PATCH:PROC)        STATUS     MODE        PIDS    INSTALLED            COMMENT
    --------------------------------------------------------------------------
    cpm:fwm               armed      livepatch   1/1     2026-08-11 14:09:33  sk185152 sk185169
    vpn1:iked             ready      livepatch   0/0     2026-08-11 14:07:19

    -> {"patches": {id: {...}}, "unparsed": [lines], "header": bool}
    Tolerant of missing columns: PIDS and INSTALLED are found by shape, not position.
    """
    patches, unparsed, header = {}, [], False
    for line in raw.split("\n"):
        s = line.strip()
        if not s or re.fullmatch(r"[-=_ ]+", s):
            continue
        if s.upper().startswith("ID") and "STATUS" in s.upper():
            header = True
            continue
        if s.lower().startswith("no recorded patches"):
            continue                      # R82.20 on a host with nothing in the manifest
        if s.startswith("*"):
            continue                      # footnote: "* reports to the management audit trail ..."
        toks = s.split()
        if (len(toks) < 2 or not re.fullmatch(r"[\w.+-]+:[\w.+-]+\*?", toks[0])
                or not re.fullmatch(r"[A-Za-z]+", toks[1])):
            unparsed.append(s)
            continue
        pid, status = toks[0], toks[1].lower()
        audit = pid.endswith("*")         # '*' = reports to the management audit trail
        pid = pid.rstrip("*")
        rest = toks[2:]
        mode = pids = installed = None
        if rest and not PIDS_RE.match(rest[0]) and not DATE_RE.match(rest[0]):
            mode = rest.pop(0)
        if rest and PIDS_RE.match(rest[0]):
            pids = rest.pop(0)
        if rest and DATE_RE.match(rest[0]):
            installed = rest.pop(0)
            if rest and TIME_RE.match(rest[0]):
                installed += " " + rest.pop(0)
        comment = " ".join(rest)
        patch, _, proc = pid.partition(":")
        running = total = None
        if pids:
            running, total = (int(x) for x in pids.split("/"))
        patches[pid] = {
            "patch": patch, "process": proc, "status": status, "mode": mode,
            "pids": pids, "pids_applied": running, "pids_total": total,
            "installed": installed, "comment": comment,
            "sks": sorted({m.lower() for m in SK_RE.findall(comment)}),
            "cves": sorted({m.upper() for m in CVE_RE.findall(comment)}),
            "audit": audit,
        }
    return {"patches": patches, "unparsed": unparsed, "header": header}


def parse_bundles(raw: str) -> dict:
    """grep of 'cpinfo -y all' -> URGENT (CPLP) bundle + Jumbo take."""
    out = {"cplp_bundle": None, "cplp_take": None, "cplp_version": None,
           "jumbo_bundle": None, "jumbo_take": None}
    for line in raw.split("\n"):
        m = re.match(r"^\s*(\S+)\s+Take:\s*(\d+)", line)
        if not m:
            continue
        name, take = m.group(1), int(m.group(2))
        if "URGENT" in name.upper():
            out["cplp_bundle"], out["cplp_take"] = name, take
            v = re.search(r"_R(\d{2})(?:_(\d{1,2}))?_AUTOUPDATE", name.upper())
            if v:
                out["cplp_version"] = f"R{v.group(1)}" + (f".{v.group(2)}" if v.group(2) else "")
        elif "JUMBO" in name.upper() and (out["jumbo_take"] is None or take > out["jumbo_take"]):
            out["jumbo_bundle"], out["jumbo_take"] = name, take
    return out


def parse_au_component(raw: str) -> dict:
    """AutoUpdater view of the CPLP component, from 'autoupdatercli show urgent_security_updates'.

    R82.20 prints key: value lines:
        download-scheduler-active: true      install-scheduler-active: true
        download-action: idle                install-revert-action: idle
        installation-date: 2026-10-01_16:25:59
        package-version: 29
        package-name: urgent_security_updates_R82_20_Bundle_T29_FULL.tgz
        package-installed: true
    plus the component's line from products_config.xml. 'state' is enabled when the
    download and install schedulers are both active, disabled when both are off."""
    kv = {}
    for line in raw.replace("\r", "").split("\n"):
        m = re.match(r"^\s*([a-z][\w-]*)\s*:\s*(.*?)\s*$", line, re.I)
        if m:
            kv.setdefault(m.group(1).lower(), m.group(2))

    def flag(key):
        v = (kv.get(key) or "").lower()
        return True if v == "true" else False if v == "false" else None

    dl, inst = flag("download-scheduler-active"), flag("install-scheduler-active")
    state = None
    if dl is not None or inst is not None:
        state = "enabled" if (dl and inst) else "disabled" if (dl is False and inst is False) else "partial"
    ver = kv.get("package-version")
    if ver is None:
        m = re.search(r'(?i)name="urgent_security_updates"[^>]*?\bversion="([^"]+)"', raw)
        ver = m.group(1) if m else None
    return {"state": state, "version": ver, "package": kv.get("package-name"),
            "installed": flag("package-installed"), "installed_at": kv.get("installation-date"),
            "download_action": kv.get("download-action"), "install_action": kv.get("install-revert-action"),
            "listed": "urgent_security_updates" in raw.lower()}


def parse_coverage(raw: str) -> dict:
    """'cplp coverage' (R82.20): one '<CVE or SK>  <state>' line per tracked item, e.g.
        CVE-2026-91843  patched
    or '(no tracked SK/CVE)' when nothing applies to this machine."""
    items, unparsed = {}, []
    for line in raw.replace("\r", "").split("\n"):
        s = line.strip()
        if not s or s.lower().startswith("rc="):
            continue
        m = re.match(r"^((?:CVE-\d{4}-\d{4,7})|(?:sk\d{5,8}))\s+(.+?)\s*$", s, re.I)
        if m:
            items[m.group(1).upper() if m.group(1).upper().startswith("CVE") else m.group(1).lower()] = m.group(2).lower()
        elif not s.lower().startswith("(no tracked"):
            unparsed.append(s)
    return {"items": items, "none": "(no tracked" in raw.lower(), "unparsed": unparsed}


CONSENT_NAMES = {
    "AllowReceivingDataFromCheckPoint": "Download Security",
    "AllowReceivingDataFromCheckPointNonSecurity": "Download Non-Security",
    "AllowSendingDataToCheckPoint": "Upload Information",
    "AllowSendingSensitiveDataToCheckPoint": "Upload Crash Data",
    "allow_download_content": "Download Security",
    "allow_download_non_security_content": "Download Non-Security",
    "allow_upload_content": "Upload Information",
    "allow_upload_sensitive_content": "Upload Crash Data",
}


def parse_consent(raw: str) -> dict:
    """dbget values and effective DownloadAccess values (sk175504 section 4)."""
    out = {"gaia_db": {}, "effective": {}}
    for line in raw.split("\n"):
        s = line.strip()
        m = re.match(r"^GAIA (\w+)=(.*)$", s)
        if m:
            val = m.group(2).strip()
            out["gaia_db"][CONSENT_NAMES.get(m.group(1), m.group(1))] = (
                {"1": "true", "0": "false"}.get(val, val or "unset"))
            continue
        m = re.match(r"^EFFECTIVE :(\w+) \((\w+)\)", s)
        if m:
            out["effective"][CONSENT_NAMES.get(m.group(1), m.group(1))] = m.group(2)
    return out


def parse_file_list(raw: str) -> list:
    """'<mtime> <size> <path>' lines -> [{mtime, size, path}] newest first"""
    files = []
    for line in raw.split("\n"):
        parts = line.strip().split(" ", 2)
        if len(parts) == 3 and parts[1].isdigit():
            files.append({"mtime": parts[0].split(".")[0], "size": int(parts[1]), "path": parts[2]})
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return files
