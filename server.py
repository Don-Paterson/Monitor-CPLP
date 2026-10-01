"""
Monitor-CPLP - watches Check Point Live Patch (CPLP, sk185114) on lab Gaia hosts:
'cplp list' status per patch, the URGENT bundle take vs the latest in the SK,
CVE coverage, and the AutoUpdater / consent settings that deliver CPLP.

  python server.py                     menu (lab + machines), then poller + dashboard
  python server.py --last              skip the menu, reuse the last lab/machines
  python server.py --lab ccte --hosts A-SMS,A-GW-01
  python server.py --once [...]        one collection, print status + changes, exit
"""
import io
import os
import sys
import csv
import json
import time
import logging
import argparse
import threading
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from cplpmon.engine import Monitor            # noqa: E402
from cplpmon import menu, kb                  # noqa: E402
from cplpmon.differ import diff_snapshots     # noqa: E402
from cplpmon.collector import SECTION_TITLES  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                    datefmt="%H:%M:%S")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger("cplpmon")


def load_json(name, required=True):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        if required:
            logger.error(f"{name} not found in {BASE_DIR}. Run bootstrap.ps1 or copy {name}.example")
            sys.exit(1)
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


CONFIG = load_json("config.json")
CREDS = load_json("credentials.json")
kb.load(BASE_DIR)
monitor = None  # created in main() after the lab / machine menu


def host_view(h):
    name = h["name"]
    with monitor.lock:
        status = dict(monitor.status.get(name, {}))
    good = monitor.store.get(name, "last_good") or {}
    base = monitor.store.get(name, "baseline") or {}
    a = kb.assess(good)
    system = ((good.get("sections") or {}).get("system") or {}).get("data") or {}
    failed = [k for k, v in (good.get("sections") or {}).items() if not v.get("ok")]
    return {
        "name": name, "ip": h["ip"], "role": h.get("role", ""), **status,
        "hostname": system.get("hostname"), "release": system.get("release"),
        "last_good": good.get("collected_at"), "baseline": base.get("collected_at"),
        "drift": len(diff_snapshots(base, good)) if base and good else 0,
        "failed_sections": failed, **a,
        "alerts": [{"level": l, "text": t} for l, t in a["alerts"]],
    }


def create_app():
    from flask import Flask, jsonify, send_from_directory, Response, abort

    app = Flask(__name__, static_folder="static")

    @app.route("/")
    def index():
        return send_from_directory(os.path.join(BASE_DIR, "static"), "dashboard.html")

    @app.route("/api/state")
    def api_state():
        with monitor.lock:
            gen, collecting = monitor.generation, monitor.collecting
        hosts = [host_view(h) for h in monitor.hosts]
        return jsonify({
            "generation": gen,
            "collecting": collecting,
            "last_cycle": monitor.last_cycle,
            "next_run": monitor.next_run,
            "server_time": time.time(),
            "lab": {"id": monitor.lab["id"], "name": monitor.lab["name"]},
            "interval_minutes": monitor.interval // 60,
            "ui_refresh_seconds": CONFIG.get("dashboard", {}).get("ui_refresh_seconds", 5),
            "kb": {"sk_revision": kb.kb().get("sk_revision"), "latest_take": kb.kb()["latest_take"],
                   "statuses": kb.kb()["statuses"], "cves": kb.cve_items(),
                   "releases": kb.kb()["releases"]},
            "hosts": hosts,
            "changes": monitor.store.read_events(limit=400),
        })

    @app.route("/api/host/<name>")
    def api_host(name):
        if name not in monitor.status:
            abort(404)
        good = monitor.store.get(name, "last_good")
        base = monitor.store.get(name, "baseline")
        return jsonify({
            "latest": monitor.store.get(name, "latest"),
            "last_good": good,
            "baseline_at": (base or {}).get("collected_at"),
            "drift": diff_snapshots(base, good) if base and good else [],
            "events": monitor.store.read_events(host=name, limit=500),
            "titles": SECTION_TITLES,
        })

    @app.route("/api/collect", methods=["POST"])
    def api_collect():
        monitor.trigger()
        return jsonify({"triggered": True})

    @app.route("/api/rebaseline/<name>", methods=["POST"])
    def api_rebaseline(name):
        if name not in monitor.status:
            abort(404)
        snap = monitor.store.rebaseline(name)
        with monitor.lock:
            monitor.generation += 1
        return jsonify({"ok": bool(snap), "baseline": (snap or {}).get("collected_at")})

    @app.route("/api/changes.csv")
    def api_changes_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["time", "host", "severity", "category", "change", "item", "old", "new"])
        for e in reversed(monitor.store.read_events()):
            w.writerow([e.get("ts"), e.get("host"), e.get("severity", ""), e.get("category"),
                        e.get("change"), e.get("item"), e.get("old") or "", e.get("new") or ""])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=cplp-changes.csv"})

    @app.route("/api/status.csv")
    def api_status_csv():
        """Patch x host status matrix - handy for a lab report."""
        buf = io.StringIO()
        w = csv.writer(buf)
        views = [host_view(h) for h in monitor.hosts]
        ids = sorted({pid for v in views for pid in v["patches"]})
        w.writerow(["patch:process"] + [v["name"] for v in views])
        w.writerow(["CPLP take"] + [v["take"] if v["take"] is not None else "" for v in views])
        for pid in ids:
            w.writerow([pid] + [v["patches"].get(pid, {}).get("status", "") for v in views])
        for c in kb.cve_items():
            w.writerow([f"{c['cve']} ({c['sk']})"] + [v["coverage"].get(c["cve"], "") for v in views])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=cplp-status.csv"})

    return app


def run_once():
    results = monitor.run_once()
    print()
    for snap, events in results:
        state = "OK" if snap.get("ok") else f"ERROR: {snap.get('error')}"
        print(f"== {snap['host']} ({snap['ip']}) {state}  [{snap.get('duration_s')}s]")
        if snap.get("ok"):
            a = kb.assess(snap)
            latest = f" (latest {a['latest_take']})" if a["latest_take"] is not None else ""
            print(f"   CPLP take {a['take'] if a['take'] is not None else '-'}{latest}, "
                  f"version {a['version'] or '-'}, Jumbo take {a['jumbo_take'] or '-'}")
            for pid, p in sorted(a["patches"].items()):
                print(f"   {pid:<22} {p['status']:<9} {p['pids'] or '':<6} {p['comment']}")
            for lvl, t in a["alerts"]:
                print(f"   !! {lvl.upper()}: {t}")
        for e in events:
            if e["change"] == "baseline":
                print(f"   baseline: {e['new']}")
            else:
                print(f"   [{e.get('severity', '')}] {e['category']:<13} {e['change']:<11} {e['item']}  "
                      f"[{e.get('old') or '-'} -> {e.get('new') or '-'}]")
    print(f"\nLogs: {monitor.store.log_dir}")


def main():
    ap = argparse.ArgumentParser(description="Monitor-CPLP")
    ap.add_argument("--once", action="store_true", help="collect once, print status + changes and exit")
    ap.add_argument("--no-browser", action="store_true", help="don't open the dashboard in a browser")
    ap.add_argument("--lab", help="lab id from labs.json (skips the menu), e.g. ccte, ctps, ccse-elasticxl")
    ap.add_argument("--hosts", help="comma-separated machine names to monitor (with --lab)")
    ap.add_argument("--last", action="store_true", help="skip the menu and reuse the last selection")
    ap.add_argument("--list-labs", action="store_true", help="list the known labs and exit")
    args = ap.parse_args()

    if args.list_labs:
        from cplpmon.labs import load_labs
        for lab in load_labs(BASE_DIR):
            print(f"{lab['id']:<18} {lab['name']:<20} " + ", ".join(
                f"{h['name']}={'/'.join(h['ips'])}" for h in lab["hosts"]))
        return

    global monitor
    lab, hosts = menu.select(BASE_DIR, lab_arg=args.lab, hosts_arg=args.hosts,
                             use_last=args.last, interactive=sys.stdin.isatty())
    monitor = Monitor(CONFIG, CREDS, BASE_DIR, hosts, lab)

    if args.once:
        run_once()
        return

    dash = CONFIG.get("dashboard", {})
    host, port = dash.get("host", "127.0.0.1"), int(dash.get("port", 8091))
    url = f"http://{'localhost' if host in ('0.0.0.0', '127.0.0.1') else host}:{port}"

    logger.info("=" * 60)
    logger.info(f"Monitor-CPLP starting - lab: {lab['name']}")
    for h in monitor.hosts:
        logger.info(f"  {h['name']:<10} {h['ip']}  ({h.get('role', '')})")
    logger.info(f"  Poll interval: {monitor.interval // 60} min   KB: sk185114 rev {kb.kb().get('sk_revision')}")
    logger.info(f"  Dashboard: {url}")
    logger.info("=" * 60)

    monitor.start()
    if dash.get("open_browser", True) and not args.no_browser:
        threading.Timer(2.0, lambda: webbrowser.open(url)).start()

    app = create_app()
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
