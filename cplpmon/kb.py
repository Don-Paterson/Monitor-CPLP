"""
CPLP knowledge base (cplp_kb.json, from sk185114) and the per-host assessment
built from a snapshot: take vs latest, status counts, CVE coverage, alerts.
"""
import os
import json

from cplpmon.parsers import version_from_release

_KB = None


def load(base_dir):
    global _KB
    with open(os.path.join(base_dir, "cplp_kb.json"), encoding="utf-8") as f:
        _KB = json.load(f)
    return _KB


def kb():
    return _KB or {"latest_take": {}, "releases": [], "statuses": {}}


def release_for_take(take):
    """Highest CPLP 'Patch N' release whose first take is <= take."""
    if take is None:
        return None
    best = None
    for r in kb()["releases"]:
        if min(r["takes"]) <= take and (best is None or r["patch"] > best["patch"]):
            best = r
    return best


def cve_items():
    """Unique (cve, sk) across releases, newest release first."""
    seen, out = set(), []
    for r in sorted(kb()["releases"], key=lambda r: -r["patch"]):
        for it in r["items"]:
            if it["cve"] not in seen:
                seen.add(it["cve"])
                first = min(min(x["takes"]) for x in kb()["releases"]
                            if any(i["cve"] == it["cve"] for i in x["items"]))
                out.append({**it, "patch": r["patch"], "first_take": first})
    return out


def _sec(snap, name):
    s = (snap or {}).get("sections", {}).get(name) or {}
    return s.get("data") if s.get("ok") and s.get("data") is not None else None


def assess(snap):
    """Everything the dashboard shows for one host, derived from its last good snapshot."""
    out = {"version": None, "take": None, "latest_take": None, "behind": None,
           "release": None, "jumbo_take": None, "cplp_present": None,
           "counts": {}, "patches": {}, "coverage": {}, "alerts": [],
           "au_state": None, "consent_dl_security": None}
    if not snap:
        return out
    system = _sec(snap, "system") or {}
    bundles = _sec(snap, "bundles") or {}
    cl = _sec(snap, "cplp_list")
    cl_sec = (snap.get("sections") or {}).get("cplp_list") or {}
    au = _sec(snap, "au_component") or {}
    consent = _sec(snap, "consent") or {}

    out["version"] = bundles.get("cplp_version") or version_from_release(system.get("release"))
    out["take"] = bundles.get("cplp_take")
    out["jumbo_take"] = bundles.get("jumbo_take")
    out["latest_take"] = kb()["latest_take"].get(out["version"]) if out["version"] else None
    if out["take"] is not None and out["latest_take"] is not None:
        out["behind"] = out["take"] < out["latest_take"]
    rel = release_for_take(out["take"])
    out["release"] = {"patch": rel["patch"], "date": rel["date"]} if rel else None

    patches = (cl or {}).get("patches") or {}
    out["patches"] = patches
    out["cplp_present"] = bool(cl_sec.get("ok")) if cl_sec else None
    for p in patches.values():
        out["counts"][p["status"]] = out["counts"].get(p["status"], 0) + 1

    # CVE coverage, by the SKs listed in the COMMENT column
    for item in cve_items():
        sk = item["sk"].lower()
        hits = [p["status"] for p in patches.values() if sk in p["sks"]]
        if out["cplp_present"] is False:
            state = "no_cplp"
        elif hits and "reverted" in hits and ("armed" in hits or "ready" in hits):
            state = "partial"        # covered on some processes, reverted on others
        elif hits:
            for st in ("armed", "jumbofix", "ready", "reverted", "unsupp", "nopatch", "nolib"):
                if st in hits:
                    state = st
                    break
            else:
                state = hits[0]
        elif out["take"] is not None and out["take"] < item["first_take"]:
            state = "not_delivered"
        else:
            state = "not_listed"
        out["coverage"][item["cve"]] = state

    out["au_state"] = au.get("state")
    eff = consent.get("effective") or {}
    db = consent.get("gaia_db") or {}
    out["consent_dl_security"] = eff.get("Download Security") or db.get("Download Security")

    # Alerts, worst first
    A = out["alerts"]
    if cl_sec and not cl_sec.get("ok"):
        A.append(("alert", f"cplp list failed: {cl_sec.get('error')}"))
    rev = [k for k, p in patches.items() if p["status"] == "reverted"]
    if rev:
        A.append(("alert", f"Reverted: {', '.join(rev)}"))
    partial = [k for k, p in patches.items() if p["status"] == "armed"
               and p["pids_total"] and p["pids_applied"] is not None and p["pids_applied"] < p["pids_total"]]
    if partial:
        A.append(("warn", f"Armed on only some PIDs: {', '.join(partial)}"))
    unsupp = [k for k, p in patches.items() if p["status"] == "unsupp"]
    if unsupp:
        A.append(("warn", f"Build not covered yet: {', '.join(unsupp)}"))
    if out["behind"]:
        A.append(("warn", f"CPLP take {out['take']} - latest for {out['version']} is {out['latest_take']}"))
    if out["take"] is None and bundles is not None and _sec(snap, "bundles") is not None:
        A.append(("warn", "No URGENT (CPLP) bundle in cpinfo"))
    if out["au_state"] == "disabled":
        A.append(("warn", "AutoUpdater CPLP component disabled"))
    if out["consent_dl_security"] == "false":
        A.append(("warn", "Consent 'Download Security' is off - CPLP updates blocked"))
    return out
