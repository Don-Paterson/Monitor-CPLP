"""
Install or update CPLP on one Gaia host, as sk185114 describes
("How to trigger a Check Point Live Patch (CPLP) Update").

Steps, all in Expert mode over SSH:
  1. Record the URGENT bundle take now installed (cpinfo -y all).
  2. Check that AutoUpdater knows the urgent_security_updates component.
     AutoUpdater reads its component list only when it starts. A machine whose
     component list was updated after AutoUpdater started (typical on a lab
     image older than CPLP) reports "Component not found" until AutoUpdater
     restarts. "autoupdatercli stop" restarts it (it comes back by itself).
  3. autoupdatercli update_component urgent_security_updates. This only queues
     the request and prints its Id, so the job polls
     "autoupdatercli get_status <Id>" (s_in_queue ... s_installation_finished)
     and shows the AutoUpdater.log lines for the component as they appear.
  4. Show the result: cpinfo URGENT take, autoupdatercli show and cplp list.

One job per host at a time. The log lines are kept for the dashboard.
"""
import re
import time
import threading
import logging
from datetime import datetime

from cplpmon.gaia_shell import GaiaShell, GaiaShellError

logger = logging.getLogger("cplpmon.installer")

COMPONENT = "urgent_security_updates"
TAKE_RE = re.compile(r"URGENT\S*\s+Take:\s*(\d+)", re.I)
NOT_FOUND = "component not found"
AU_LOG = "/opt/CPInstLog/AutoUpdater.log"
FINISHED_RE = re.compile(r"Installation (succeeded|failed) for component " + COMPONENT, re.I)
REQ_ID_RE = re.compile(r"Id:\s*(\S+)")
DONE_WORDS = ("finished", "fail", "error", "abort", "not_found")


def _take(text):
    takes = [int(t) for t in TAKE_RE.findall(text or "")]
    return max(takes) if takes else None


class InstallJob:
    def __init__(self, host_cfg, creds, settings, on_done=None):
        self.host = host_cfg
        self.creds = creds
        self.settings = settings
        self.on_done = on_done
        self.state = "running"          # running | done | failed
        self.started = time.time()
        self.finished = None
        self.lines = []
        self.before = None
        self.after = None
        self.lock = threading.Lock()

    # ---------- reporting ----------
    def log(self, text, level="info"):
        with self.lock:
            self.lines.append({"t": datetime.now().strftime("%H:%M:%S"), "level": level, "text": text})
        logger.info(f"[{self.host['name']}] {text}")

    def view(self):
        with self.lock:
            return {"host": self.host["name"], "state": self.state, "started_at": self.started,
                    "finished": self.finished, "before": self.before, "after": self.after,
                    "lines": list(self.lines)}

    # ---------- work ----------
    def _shell(self):
        col = self.settings.get("collection", {})
        ssh = dict(self.creds.get("ssh", {}))
        ssh.update(self.host.get("ssh", {}))
        sh = GaiaShell(self.host["ip"], ssh.get("user", "admin"), ssh.get("password", ""),
                       ssh.get("expert_password"), port=self.host.get("ssh_port", 22),
                       login_timeout=int(col.get("login_timeout_seconds", 90)))
        sh.open()
        return sh

    def _run(self, sh, cmd, timeout=120, show=True):
        r = sh.run(cmd, timeout=timeout)
        out = r["output"].strip()
        if show and out:
            self.log(out, "out")
        if r["timed_out"]:
            self.log(f"Timed out after {timeout} s: {cmd}", "warn")
        return out

    def _component_known(self, sh):
        out = self._run(sh, f"autoupdatercli show {COMPONENT} 2>&1 | head -20", show=False)
        return NOT_FOUND not in out.lower() and "product-name" in out.lower(), out

    def run(self):
        sh = None
        try:
            self.log(f"Connecting to {self.host['name']} ({self.host['ip']})")
            sh = self._shell()

            self.log("1. CPLP bundle installed now (cpinfo -y all | grep URGENT)")
            self.before = _take(self._run(sh, "cpinfo -y all 2>/dev/null | grep -i URGENT"))
            self.log(f"   Take before: {self.before if self.before is not None else 'none'}")

            self.log(f"2. Does AutoUpdater know the CPLP component? (autoupdatercli show {COMPONENT})")
            known, out = self._component_known(sh)
            if not known:
                self.log("   No: " + (out.splitlines()[0] if out else "no answer"), "warn")
                self.log("   AutoUpdater reads its component list only when it starts. Restarting it "
                         "(autoupdatercli stop - it starts again by itself) so it loads the current list.")
                self._run(sh, "autoupdatercli stop 2>&1", timeout=120)
                deadline = time.time() + 300
                while time.time() < deadline:
                    time.sleep(15)
                    known, out = self._component_known(sh)
                    if known:
                        break
                    self.log("   Waiting for AutoUpdater to come back with the CPLP component...")
                if not known:
                    self.log("AutoUpdater still does not list the CPLP component after 5 minutes. Check "
                             "Global Properties > Data Access Control (Download Security, sk175504), Internet "
                             "access from this machine, and /opt/CPInstLog/AutoUpdater.log.", "error")
                    self.state = "failed"
                    return
                self.log("   AutoUpdater now lists the CPLP component.")
            else:
                self.log("   Yes.")

            self.log(f"3. Download and install the latest CPLP (autoupdatercli update_component {COMPONENT})")
            mark = self._run(sh, f"wc -l < {AU_LOG}", show=False).strip()
            mark = int(mark) if mark.isdigit() else 0
            queued = self._run(sh, f"autoupdatercli update_component {COMPONENT} 2>&1 | tail -5", timeout=120)
            m = REQ_ID_RE.search(queued)
            req = m.group(1) if m else None
            self.log("   Queued. Waiting for AutoUpdater (usually 1-3 minutes)...")
            finished, seen, last_status = None, 0, None
            deadline = time.time() + 900
            while time.time() < deadline and not finished:
                time.sleep(10)
                new = self._run(sh, f"tail -n +{mark + 1} {AU_LOG} | grep -i {COMPONENT}", show=False)
                lines = [l.strip() for l in new.splitlines() if l.strip()]
                for l in lines[seen:]:
                    self.log("   " + re.sub(r"^\*\w\* %[^%]*% :\s*", "", l), "out")
                seen = len(lines)
                if req:
                    st = self._run(sh, f"autoupdatercli get_status {req} 2>&1 | tr '\\r' '\\n' | tail -1",
                                   show=False).strip()
                    if st and st != last_status:
                        self.log(f"   Request status: {st}")
                        last_status = st
                    if st and any(w in st.lower() for w in DONE_WORDS):
                        finished = st
                m = FINISHED_RE.search(new)
                if m:
                    finished = finished or m.group(0)
            if not finished:
                self.log("   No result after 15 minutes; checking what is installed.", "warn")

            self.log("4. Result")
            self.after = _take(self._run(sh, "cpinfo -y all 2>/dev/null | grep -i URGENT"))
            self._run(sh, f"autoupdatercli show {COMPONENT} 2>&1 | grep -E 'package-(name|installed|version)|installation-date' | tail -5")
            self._run(sh, "CPLP=$(command -v cplp || echo /usr/local/bin/cplp); "
                          "[ -x \"$CPLP\" ] && $CPLP list 2>&1 | head -30 || echo 'cplp command not found yet'")
            if self.after is None:
                self.log("No CPLP bundle is installed. See the output above and AutoUpdater.log.", "error")
                self.state = "failed"
            elif self.before is not None and self.after <= self.before:
                self.log(f"CPLP take {self.after} - already the latest this machine was offered.", "ok")
                self.state = "done"
            else:
                self.log(f"CPLP installed: take {self.before if self.before is not None else 'none'} -> {self.after}.", "ok")
                self.state = "done"
        except (GaiaShellError, OSError, Exception) as e:   # noqa: B014 - report anything to the UI
            self.log(f"Failed: {e}", "error")
            self.state = "failed"
        finally:
            if sh:
                try:
                    sh.close()
                except Exception:
                    pass
            self.finished = time.time()
            if self.on_done:
                try:
                    self.on_done()
                except Exception:
                    pass


class Installer:
    """Keeps the latest install job per host."""

    def __init__(self, creds, settings, on_done=None):
        self.creds = creds
        self.settings = settings
        self.on_done = on_done
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, host_cfg):
        name = host_cfg["name"]
        with self.lock:
            job = self.jobs.get(name)
            if job and job.state == "running":
                return job, False
            job = InstallJob(host_cfg, self.creds, self.settings, self.on_done)
            self.jobs[name] = job
        threading.Thread(target=job.run, daemon=True, name=f"cplp-install-{name}").start()
        return job, True

    def get(self, name):
        with self.lock:
            return self.jobs.get(name)
