"""
Polling engine shared by the web server and the command-line runner.
"""
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from cplpmon.collector import collect_host
from cplpmon.differ import diff_snapshots, baseline_summary
from cplpmon.store import Store, now_local

logger = logging.getLogger("cplpmon.engine")


class Monitor:
    def __init__(self, config, creds, base_dir, hosts, lab=None):
        self.config = config
        self.creds = creds
        self.lab = lab or {"id": "default", "name": "Lab"}
        self.store = Store(base_dir, self.lab["id"])
        self.hosts = hosts
        self.interval = max(1, int(config.get("collection", {}).get("interval_minutes", 15))) * 60
        self.lock = threading.Lock()
        self.generation = 0
        self.collecting = False
        self.last_cycle = None
        self.next_run = None
        self._wake = threading.Event()
        self.status = {}
        for h in self.hosts:
            latest = self.store.get(h["name"], "latest")
            self.status[h["name"]] = {
                "state": "pending" if not latest else ("ok" if latest.get("ok") else "error"),
                "last_run": latest.get("collected_at") if latest else None,
                "error": latest.get("error") if latest else None,
                "last_events": 0,
            }

    # ---------- one poll ----------
    def _collect_one(self, h):
        name = h["name"]
        with self.lock:
            self.status[name]["state"] = "collecting"
            self.generation += 1

        prev = self.store.get(name, "last_good")
        snap = collect_host(h, self.creds, self.config)
        ts = now_local()

        events = []
        if snap.get("ok"):
            if prev:
                events = diff_snapshots(prev, snap)
            else:
                events = [{"category": "Monitor", "section": "baseline", "item": "Baseline captured",
                           "change": "baseline", "old": None,
                           "new": baseline_summary(snap),
                           "detail": None}]
            for e in events:
                e["ts"] = ts
                e["host"] = name

        self.store.save_snapshot(snap, [e for e in events if e["change"] != "baseline"])
        self.store.append_events(events)
        self.store.log_run(snap, len(events))

        real = [e for e in events if e["change"] != "baseline"]
        if real:
            logger.warning(f"{name}: {len(real)} change(s) detected")
        with self.lock:
            self.status[name].update({
                "state": "ok" if snap.get("ok") else "error",
                "last_run": snap["collected_at"],
                "error": snap.get("error"),
                "last_events": len(real),
            })
            self.generation += 1
        return snap, events

    def run_once(self):
        with self.lock:
            if self.collecting:
                return []
            self.collecting = True
            self.generation += 1
        results = []
        try:
            workers = len(self.hosts) if self.config.get("collection", {}).get("parallel", True) else 1
            with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
                results = list(pool.map(self._collect_one, self.hosts))
        finally:
            with self.lock:
                self.collecting = False
                self.last_cycle = now_local()
                self.generation += 1
        return results

    # ---------- background loop ----------
    def trigger(self):
        self._wake.set()

    def loop(self):
        while True:
            try:
                self.run_once()
            except Exception:
                logger.exception("Collection cycle failed")
            self.next_run = time.time() + self.interval
            self._wake.wait(self.interval)
            self._wake.clear()

    def start(self):
        t = threading.Thread(target=self.loop, name="cplp-poller", daemon=True)
        t.start()
        return t
