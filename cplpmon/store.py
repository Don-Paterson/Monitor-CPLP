"""
On-disk store for snapshots and the change log.

data/<lab>/
  <host>/baseline.json     first good snapshot (or last "re-baseline")
  <host>/latest.json       most recent snapshot (good or failed)
  <host>/last_good.json    most recent successful snapshot (diff reference)
  <host>/history/*.json    a copy of every snapshot that contained changes
  changes.jsonl            every change event, all hosts (machine readable)
logs/<lab>/
  changes.log              the same events, human readable
  runs.log                 one line per host per poll
"""
import os
import json
import threading
from datetime import datetime

_lock = threading.Lock()


def _safe(name):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


class Store:
    def __init__(self, base_dir, lab_id="default"):
        # One folder per lab, so A-SMS in CCTE and A-SMS in CTPS never share a baseline
        self.data_dir = os.path.join(base_dir, "data", _safe(lab_id))
        self.log_dir = os.path.join(base_dir, "logs", _safe(lab_id))
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        self.changes_path = os.path.join(self.data_dir, "changes.jsonl")

    def _host_dir(self, host):
        d = os.path.join(self.data_dir, _safe(host))
        os.makedirs(os.path.join(d, "history"), exist_ok=True)
        return d

    @staticmethod
    def _read(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _write(path, obj):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
        os.replace(tmp, path)

    def get(self, host, which):
        return self._read(os.path.join(self._host_dir(host), f"{which}.json"))

    def save_snapshot(self, snap, events):
        host = snap["host"]
        d = self._host_dir(host)
        with _lock:
            self._write(os.path.join(d, "latest.json"), snap)
            if snap.get("ok"):
                self._write(os.path.join(d, "last_good.json"), snap)
                if not os.path.exists(os.path.join(d, "baseline.json")):
                    self._write(os.path.join(d, "baseline.json"), snap)
                if events:
                    stamp = snap["collected_at"].replace(":", "").replace("-", "")
                    self._write(os.path.join(d, "history", f"{stamp}.json"), snap)

    def rebaseline(self, host):
        d = self._host_dir(host)
        good = self._read(os.path.join(d, "last_good.json"))
        if good:
            with _lock:
                self._write(os.path.join(d, "baseline.json"), good)
        return good

    def append_events(self, events):
        if not events:
            return
        with _lock:
            with open(self.changes_path, "a", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
            with open(os.path.join(self.log_dir, "changes.log"), "a", encoding="utf-8") as f:
                for e in events:
                    arrow = f"{e.get('old') or '-'}  ->  {e.get('new') or '-'}"
                    sev = (e.get("severity") or "").upper()
                    f.write(f"{e['ts']}  {sev:<5} {e['host']:<10} {e['category']:<14} {e['change']:<11} "
                            f"{e['item']}   [{arrow}]\n")

    def log_run(self, snap, n_events):
        line = (f"{snap['collected_at']}  {snap['host']:<10} "
                f"{'OK ' if snap.get('ok') else 'ERR'} {snap.get('duration_s')}s "
                f"changes={n_events}"
                f"{'  ' + snap['error'] if snap.get('error') else ''}\n")
        with _lock:
            with open(os.path.join(self.log_dir, "runs.log"), "a", encoding="utf-8") as f:
                f.write(line)

    def read_events(self, host=None, limit=None):
        out = []
        try:
            with open(self.changes_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if host is None or e.get("host") == host:
                        out.append(e)
        except FileNotFoundError:
            pass
        out.reverse()  # newest first
        return out[:limit] if limit else out


def now_local():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
