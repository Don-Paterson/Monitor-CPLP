"""
Lab profiles, SSH reachability probing, lab detection and the saved selection.

labs.json        shipped profiles (replaced by the bootstrap on every run)
labs.local.json  your own labs / overrides, same format, matched on "id" (never replaced)
selection.json   the last lab + machines chosen in the menu
"""
import os
import json
import socket
from concurrent.futures import ThreadPoolExecutor


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def load_labs(base_dir):
    labs, order = {}, []
    for name in ("labs.json", "labs.local.json"):
        data = _read_json(os.path.join(base_dir, name)) or {}
        for lab in data.get("labs", []):
            if lab["id"] not in labs:
                order.append(lab["id"])
            lab["source"] = name
            for h in lab.get("hosts", []):
                if "ips" not in h and "ip" in h:
                    h["ips"] = [h["ip"]]
            labs[lab["id"]] = lab
    return [labs[i] for i in order]


def save_local_lab(base_dir, lab):
    path = os.path.join(base_dir, "labs.local.json")
    data = _read_json(path) or {"labs": []}
    data["labs"] = [l for l in data["labs"] if l["id"] != lab["id"]]
    clean = {k: v for k, v in lab.items() if k != "source"}
    data["labs"].append(clean)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_selection(base_dir):
    return _read_json(os.path.join(base_dir, "selection.json"))


def save_selection(base_dir, lab_id, host_names, extra_hosts=None):
    with open(os.path.join(base_dir, "selection.json"), "w", encoding="utf-8") as f:
        json.dump({"lab": lab_id, "hosts": host_names, "extra_hosts": extra_hosts or []}, f, indent=2)


# ---------------------------------------------------------------- probing --
def port_open(ip, port=22, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def split_addr(addr, default_port=22):
    """'10.1.1.2' -> ('10.1.1.2', 22); '127.0.0.1:2202' -> ('127.0.0.1', 2202)"""
    if ":" in addr:
        ip, port = addr.rsplit(":", 1)
        return ip, int(port)
    return addr, default_port


def probe(ips, timeout=1.5):
    """{addr: bool} for a set of 'ip' or 'ip:port' strings, in parallel."""
    ips = sorted(set(ips))
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=min(32, len(ips))) as pool:
        res = list(pool.map(lambda a: port_open(*split_addr(a), timeout), ips))
    return dict(zip(ips, res))


def all_ips(labs):
    return {ip for lab in labs for h in lab["hosts"] for ip in h["ips"]}


def reachable_ip(host, reach):
    for ip in host["ips"]:
        if reach.get(ip):
            return ip
    return None


def detect_lab(labs, reach):
    """Best-matching lab: most reachable hosts, then highest fraction reachable."""
    best, best_key = None, (0, 0.0)
    for lab in labs:
        n = sum(1 for h in lab["hosts"] if reachable_ip(h, reach))
        key = (n, n / max(1, len(lab["hosts"])))
        if n and key > best_key:
            best, best_key = lab, key
    return best


def to_monitor_hosts(lab, names, reach, extra=None):
    """Selected host names -> [{name, ip, role, ssh_port}] for the engine."""
    out = []
    for h in lab["hosts"]:
        if h["name"] in names:
            ip, port = split_addr(reachable_ip(h, reach) or h["ips"][0], h.get("ssh_port", 22))
            out.append({"name": h["name"], "ip": ip, "role": h.get("role", ""), "ssh_port": port,
                        **({"ssh": h["ssh"]} if "ssh" in h else {})})
    for h in extra or []:
        ip, port = split_addr(h["ip"])
        out.append({"name": h["name"], "ip": ip, "role": h.get("role", "Custom"), "ssh_port": port})
    return out
