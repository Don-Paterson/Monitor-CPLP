"""
Start-up menu: choose the lab, then the machines to monitor.

Probes every known lab IP on tcp/22 first, so the menu can show what is
reachable and suggest the lab this A-GUI is sitting in.
"""
import os
import re
import sys

from cplpmon import labs as L

if os.name == "nt":
    os.system("")  # enable ANSI colours in the Windows console

C = {"h": "\033[96m", "ok": "\033[92m", "dim": "\033[90m", "warn": "\033[93m",
     "err": "\033[91m", "b": "\033[1m", "x": "\033[0m"}


def c(key, text):
    return f"{C[key]}{text}{C['x']}"


def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _hr(title):
    print()
    print(c("h", "=" * 64))
    print(c("h", f"  {title}"))
    print(c("h", "=" * 64))


def _parse_host_line(line):
    """'NAME IP [role words]' -> dict or None"""
    parts = line.split()
    if len(parts) < 2 or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", parts[1]):
        return None
    return {"name": parts[0], "ips": [parts[1]], "role": " ".join(parts[2:]) or "Custom",
            "default": True}


# ------------------------------------------------------------------ labs --
def choose_lab(labs, reach, detected, last):
    while True:
        _hr("Monitor-CPLP - choose the lab")
        for i, lab in enumerate(labs, 1):
            n = sum(1 for h in lab["hosts"] if L.reachable_ip(h, reach))
            tot = len(lab["hosts"])
            mark = c("ok", "  <- detected") if detected and lab["id"] == detected["id"] else ""
            count = c("ok" if n else "dim", f"{n}/{tot} reachable")
            local = c("dim", " (local)") if lab.get("source") == "labs.local.json" else ""
            print(f"   {i}) {c('b', lab['name'].ljust(22))}{local} {count}{mark}")
            print(c("dim", f"        {lab.get('description', '')}"))
        print(f"   C) Custom lab - enter machines by IP")
        print(f"   Q) Quit")
        default = None
        if last and any(l["id"] == last.get("lab") for l in labs):
            default = next(l for l in labs if l["id"] == last["lab"])
            hint = f"last used: {default['name']} ({', '.join(last.get('hosts', []))})"
        elif detected:
            default = detected
            hint = f"detected: {detected['name']}"
        else:
            hint = None
        if hint:
            print(c("dim", f"   Enter = {hint}"))
        a = ask("\n  Choice: ").lower()
        if a == "" and default:
            return default
        if a == "q":
            sys.exit(0)
        if a == "c":
            lab = custom_lab(reach)
            if lab:
                return lab
            continue
        if a.isdigit() and 1 <= int(a) <= len(labs):
            return labs[int(a) - 1]
        print(c("warn", "  Not a valid choice."))


def custom_lab(reach):
    _hr("Custom lab")
    name = ask("  Lab name (e.g. CCSA R82.10): ")
    if not name:
        return None
    print("  Enter one machine per line as:  NAME IP [role]    (blank line to finish)")
    print(c("dim", "  e.g.  A-SMS 10.1.1.101 Management"))
    hosts = []
    while True:
        line = ask("  > ")
        if not line:
            break
        h = _parse_host_line(line)
        if not h:
            print(c("warn", "  Format: NAME IP [role]"))
            continue
        hosts.append(h)
    if not hosts:
        return None
    reach.update(L.probe([ip for h in hosts for ip in h["ips"]]))
    lab_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "custom"
    return {"id": lab_id, "name": name, "description": ", ".join(h["name"] for h in hosts),
            "hosts": hosts, "source": "new", "_unsaved": True}


# -------------------------------------------------------------- machines --
def choose_hosts(lab, reach, last, base_dir):
    hosts = lab["hosts"]
    if last and last.get("lab") == lab["id"]:
        for x in last.get("extra_hosts", []):
            if not any(h["name"] == x["name"] for h in hosts):
                hosts.append({"name": x["name"], "ips": [x["ip"]], "role": x.get("role", "Custom"),
                              "_extra": True})
        reach.update(L.probe([ip for h in hosts for ip in h["ips"]]))
        chosen = {h["name"] for h in hosts if h["name"] in last.get("hosts", [])}
    else:
        defaults = {h["name"] for h in hosts if h.get("default", True)}
        up = {h["name"] for h in hosts if L.reachable_ip(h, reach)}
        chosen = (defaults & up) or defaults

    while True:
        _hr(f"{lab['name']} - choose machines to monitor")
        for i, h in enumerate(hosts, 1):
            ip = L.reachable_ip(h, reach)
            state = c("ok", "reachable") if ip else c("err", "no answer")
            box = c("ok", "[x]") if h["name"] in chosen else "[ ]"
            shown_ip = ip or h["ips"][0]
            print(f"   {box} {i:>2}  {h['name']:<12} {shown_ip:<15} {h.get('role', ''):<17} {state}")
        print()
        print(c("dim", "   Toggle with numbers (e.g. 2 4).  A=all  R=reachable only  N=none  D=defaults"))
        print(c("dim", "   +=add machine  P=re-probe  B=back to labs  Enter=start monitoring"))
        a = ask("\n  Choice: ")
        al = a.lower()
        if al == "":
            if not chosen:
                print(c("warn", "  Select at least one machine."))
                continue
            break
        if al == "b":
            return None
        if al == "a":
            chosen = {h["name"] for h in hosts}
        elif al == "n":
            chosen = set()
        elif al == "r":
            chosen = {h["name"] for h in hosts if L.reachable_ip(h, reach)}
        elif al == "d":
            chosen = {h["name"] for h in hosts if h.get("default", True)}
        elif al == "p":
            print("  Probing...")
            reach.update(L.probe([ip for h in hosts for ip in h["ips"]]))
        elif al.startswith("+"):
            line = a[1:].strip() or ask("  NAME IP [role]: ")
            h = _parse_host_line(line)
            if not h:
                print(c("warn", "  Format: NAME IP [role]"))
                continue
            h["_extra"] = True
            hosts.append(h)
            reach.update(L.probe(h["ips"]))
            chosen.add(h["name"])
        else:
            nums = re.findall(r"\d+", a)
            if not nums:
                print(c("warn", "  Not a valid choice."))
            for n in nums:
                n = int(n)
                if 1 <= n <= len(hosts):
                    chosen ^= {hosts[n - 1]["name"]}

    extras = [h for h in hosts if h.get("_extra")]
    if lab.get("_unsaved") or extras:
        what = "this lab" if lab.get("_unsaved") else "the added machine(s)"
        if ask(f"  Save {what} to labs.local.json for next time? [y/N]: ").lower() == "y":
            lab.pop("_unsaved", None)
            for h in hosts:
                h.pop("_extra", None)
            L.save_local_lab(base_dir, lab)
            extras = []
            print(c("ok", "  Saved."))
    names = [h["name"] for h in hosts if h["name"] in chosen]
    extra_sel = [{"name": h["name"], "ip": h["ips"][0], "role": h.get("role", "Custom")}
                 for h in extras if h["name"] in chosen]
    return names, extra_sel


# ----------------------------------------------------------------- entry --
def select(base_dir, lab_arg=None, hosts_arg=None, use_last=False, interactive=True):
    """Returns (lab, monitor_hosts)."""
    labs = L.load_labs(base_dir)
    last = L.load_selection(base_dir)
    print(c("dim", "  Checking which lab machines answer on SSH (tcp/22)..."))
    reach = L.probe(L.all_ips(labs))
    detected = L.detect_lab(labs, reach)

    # Non-interactive routes: --lab/--hosts, --last, or no console attached
    if lab_arg or use_last or not interactive:
        lab_id = lab_arg or (last or {}).get("lab") or (detected or {}).get("id")
        lab = next((l for l in labs if l["id"] == lab_id), None)
        if not lab:
            raise SystemExit(f"Unknown lab '{lab_id}'. Known: {', '.join(l['id'] for l in labs)}")
        if hosts_arg:
            names = [n.strip() for n in hosts_arg.split(",") if n.strip()]
            extra = []
        elif last and last.get("lab") == lab["id"]:
            names, extra = last.get("hosts", []), last.get("extra_hosts", [])
        else:
            names = [h["name"] for h in lab["hosts"] if h.get("default", True)]
            extra = []
        L.save_selection(base_dir, lab["id"], names, extra)
        return lab, L.to_monitor_hosts(lab, names, reach, extra)

    while True:
        lab = choose_lab(labs, reach, detected, last)
        res = choose_hosts(lab, reach, last, base_dir)
        if res is None:
            continue
        names, extra = res
        L.save_selection(base_dir, lab["id"], names, extra)
        # added machines are already in lab["hosts"], so no extra list here
        return lab, L.to_monitor_hosts(lab, names, reach)
