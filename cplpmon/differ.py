"""
Compare two CPLP snapshots of the same host and describe what changed.

Only sections that collected successfully in BOTH snapshots are compared,
so a transient SSH/command failure never shows up as "every patch removed".
Each event carries a severity: alert (patch reverted / lost), warn, info.
"""

CATEGORY = {
    "system": "Version",
    "cplp_list": "Live Patch",
    "bundles": "CPLP bundle",
    "au_component": "AutoUpdater",
    "consent": "Consent flags",
}

STATUS_RANK = {"armed": 0, "jumbofix": 1, "ready": 2, "nolib": 3, "nopatch": 4, "unsupp": 5, "reverted": 6}


def _sec(snap, name):
    s = (snap or {}).get("sections", {}).get(name)
    return s if s and s.get("ok") and s.get("data") is not None else None


def _ev(section, item, change, old=None, new=None, severity="info", detail=None):
    return {"category": CATEGORY.get(section, section), "section": section, "item": item,
            "change": change, "old": old, "new": new, "severity": severity, "detail": detail}


def _status_severity(old, new):
    if new == "reverted":
        return "alert"
    if old == "armed" and new not in ("jumbofix",):
        return "warn"
    if new in ("armed", "jumbofix"):
        return "ok"
    return "info"


def baseline_summary(snap):
    cl = (_sec(snap, "cplp_list") or {}).get("data") or {}
    n = len(cl.get("patches") or {})
    take = ((_sec(snap, "bundles") or {}).get("data") or {}).get("cplp_take")
    counts = {}
    for p in (cl.get("patches") or {}).values():
        counts[p["status"]] = counts.get(p["status"], 0) + 1
    c = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: STATUS_RANK.get(kv[0], 9)))
    return f"CPLP take {take if take is not None else '-'}; {n} patch(es){': ' + c if c else ''}"


def diff_snapshots(old: dict, new: dict) -> list:
    events = []

    a, b = _sec(old, "system"), _sec(new, "system")
    if a and b and a["data"].get("release") != b["data"].get("release"):
        events.append(_ev("system", "Release", "changed", a["data"].get("release"), b["data"].get("release"), "warn"))

    # CPLP bundle take / Jumbo take
    a, b = _sec(old, "bundles"), _sec(new, "bundles")
    if a and b:
        da, db = a["data"], b["data"]
        if da.get("cplp_take") != db.get("cplp_take"):
            if da.get("cplp_take") is None:
                ch, sev = "added", "ok"
            elif db.get("cplp_take") is None:
                ch, sev = "removed", "alert"
            else:
                ch, sev = "changed", "ok" if db["cplp_take"] > da["cplp_take"] else "warn"
            events.append(_ev("bundles", db.get("cplp_bundle") or da.get("cplp_bundle") or "CPLP bundle", ch,
                              f"Take {da['cplp_take']}" if da.get("cplp_take") is not None else None,
                              f"Take {db['cplp_take']}" if db.get("cplp_take") is not None else None, sev))
        if da.get("jumbo_take") != db.get("jumbo_take"):
            events.append(_ev("bundles", db.get("jumbo_bundle") or da.get("jumbo_bundle") or "Jumbo", "changed",
                              f"Take {da.get('jumbo_take')}", f"Take {db.get('jumbo_take')}", "info",
                              "A newer Jumbo makes CPLP stand down for fixes it contains (status 'jumbofix')"))

    # cplp list: per patch id
    a, b = _sec(old, "cplp_list"), _sec(new, "cplp_list")
    sa, sb = (old or {}).get("sections", {}).get("cplp_list"), (new or {}).get("sections", {}).get("cplp_list")
    if sa and sb and sa.get("ok") and not sb.get("ok"):
        events.append(_ev("cplp_list", "cplp list", "failed", "ok", sb.get("error"), "alert"))
    if sa and sb and not sa.get("ok") and sb.get("ok"):
        pb = (sb.get("data") or {}).get("patches") or {}
        events.append(_ev("cplp_list", "cplp list", "available", sa.get("error"),
                          f"{len(pb)} patch(es): " + ", ".join(f"{k} {v['status']}" for k, v in sorted(pb.items())),
                          "ok"))
    if a and b:
        pa, pb = a["data"]["patches"], b["data"]["patches"]
        for pid in sorted(set(pb) - set(pa)):
            p = pb[pid]
            events.append(_ev("cplp_list", pid, "added", None,
                              f"{p['status']} {p['pids'] or ''} {p['comment']}".strip(),
                              "alert" if p["status"] == "reverted" else "ok" if p["status"] == "armed" else "info"))
        for pid in sorted(set(pa) - set(pb)):
            p = pa[pid]
            events.append(_ev("cplp_list", pid, "removed", f"{p['status']} {p['comment']}".strip(), None,
                              "warn" if p["status"] == "armed" else "info"))
        for pid in sorted(set(pa) & set(pb)):
            x, y = pa[pid], pb[pid]
            if x["status"] != y["status"]:
                events.append(_ev("cplp_list", pid, "status", x["status"], y["status"],
                                  _status_severity(x["status"], y["status"])))
            if x["pids"] != y["pids"] and x["status"] == y["status"]:
                sev = "warn" if (y["status"] == "armed" and y["pids_applied"] is not None
                                 and y["pids_total"] and y["pids_applied"] < y["pids_total"]) else "info"
                events.append(_ev("cplp_list", pid, "pids", x["pids"], y["pids"], sev,
                                  "PIDS = patched / running processes"))
            if x["installed"] != y["installed"]:
                events.append(_ev("cplp_list", pid, "reinstalled", x["installed"], y["installed"], "info"))
            rx, ry = x["sks"] + x.get("cves", []), y["sks"] + y.get("cves", [])
            if rx != ry:
                events.append(_ev("cplp_list", pid, "coverage", " ".join(rx) or "-",
                                  " ".join(ry) or "-", "ok" if len(ry) > len(rx) else "warn"))

    # AutoUpdater CPLP component
    a, b = _sec(old, "au_component"), _sec(new, "au_component")
    if a and b:
        for key, label in (("state", "urgent_security_updates state"), ("version", "urgent_security_updates version")):
            va, vb = a["data"].get(key), b["data"].get(key)
            if va != vb and (va or vb):
                sev = "warn" if (key == "state" and vb in ("disabled", "partial")) else "info"
                events.append(_ev("au_component", label, "changed", va, vb, sev))

    # Consent flags - Download Security is what delivers CPLP
    a, b = _sec(old, "consent"), _sec(new, "consent")
    if a and b:
        for layer, label in (("effective", "effective"), ("gaia_db", "Gaia DB")):
            fa, fb = a["data"].get(layer, {}), b["data"].get(layer, {})
            for k in sorted(set(fa) | set(fb)):
                if fa.get(k) != fb.get(k):
                    sev = "warn" if (k == "Download Security" and fb.get(k) == "false") else "info"
                    events.append(_ev("consent", f"{k} ({label})", "changed", fa.get(k), fb.get(k), sev))

    return events
