"""
Fake Gaia SSH host for testing Monitor-CPLP without a lab.

Simulates: Clish login prompt, 'expert' + password, expert bash prompt,
terminal echo, and Check Point commands backed by files in a state dir
(so a test can "apply an AutoUpdater update" by editing those files).

  python tests/fake_gaia.py --port 2222 --state /tmp/gw1 --name A-GW-01
"""
import os
import sys
import socket
import argparse
import threading
import subprocess

import paramiko

HOST_KEY = paramiko.RSAKey.generate(2048)
USER, PASSWORD, EXPERT_PW = "admin", "Chkp!234", "Chkp!234"
EXPERT_DELAY = 0.0
EXPERT_NEEDS_ENTER = False

FAKE_BIN = {
    "autoupdatercli": 'case "$2" in urgent_security_updates) cat "$STATE/au_cplp.txt" ;; *) cat "$STATE/au_take.txt" 2>/dev/null ;; esac',
    "cpinfo": 'cat "$STATE/cpinfo.txt"',
    "cplic": 'cat "$STATE/cplic.txt"',
    "cpvinfo": 'echo "This is Check Point VPN-1(TM) & FireWall-1(R) R82.10 - Build 88"',
    "dbget": 'grep "^$1 " "$STATE/consent_db.txt" | cut -d" " -f2',
    # CPLP: missing state file = CPLP not installed -> bash 'command not found' (rc 127)
    "cplp": '[ -f "$STATE/cplp_list.txt" ] || { echo "bash: cplp: command not found" >&2; exit 127; }; cat "$STATE/cplp_list.txt"',
    "clish": (
        'case "$2" in\n'
        '  *"status build"*) cat "$STATE/da.txt" ;;\n'
        '  *"packages installed"*) cat "$STATE/cpuse_installed.txt" ;;\n'
        '  *"available-for-download"*) cat "$STATE/cpuse_available.txt" ;;\n'
        '  *) echo "CLINFR0409 Invalid command" ;;\n'
        'esac'
    ),
}


def make_env(state):
    fake = os.path.join(state, "bin")
    os.makedirs(fake, exist_ok=True)
    for name, body in FAKE_BIN.items():
        p = os.path.join(fake, name)
        with open(p, "w") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, 0o755)
    env = dict(os.environ)
    env.update({
        "PATH": fake + ":" + env["PATH"],
        "STATE": state,
        "CPDIR": os.path.join(state, "CPshrd"),
        "FWDIR": os.path.join(state, "fw1"),
        "DADIR": os.path.join(state, "DA"),
        "AU_DIR": os.path.join(state, "AutoUpdater"),
    })
    return env


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PASSWORD) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def readline(chan, echo):
    buf = b""
    while True:
        c = chan.recv(1)
        if not c:
            raise EOFError
        if c in (b"\n", b"\r"):
            if echo:
                chan.send(b"\r\n")
            return buf.decode()
        buf += c
        if echo:
            chan.send(c)


def session(chan, name, env, login_shell):
    try:
        chan.send(f"This system is for authorized use only.\r\n".encode())
        mode, echo = login_shell, True
        while True:
            prompt = f"{name}:0> " if mode == "clish" else f"[Expert@{name}:0]# "
            chan.send(prompt.encode())
            line = readline(chan, echo)
            if mode == "clish":
                if line.strip() == "expert":
                    chan.send(b"Enter expert password:\r\n\r\n")
                    pw = readline(chan, False)
                    if pw == EXPERT_PW:
                        if EXPERT_DELAY:
                            import time as _t; _t.sleep(EXPERT_DELAY)
                        if EXPERT_NEEDS_ENTER:
                            readline(chan, False)   # CCTE lab gateways: silent until another Enter
                        chan.send(b"Warning! All configurations should be done through clish\r\n"
                                  b"You are in expert mode now.\r\n\r\n")
                        mode = "bash"
                    else:
                        chan.send(b"Wrong password.\r\n")
                elif line.strip() == "exit":
                    break
                elif line.strip():
                    chan.send(b"CLINFR0409 Invalid command\r\n")
                continue
            if line.strip() == "exit":
                break
            if "stty -echo" in line:
                echo = False
            out = subprocess.run(["bash", "-c", line], env=env, capture_output=True, text=True).stdout
            chan.send(out.replace("\n", "\r\n").encode())
    except (EOFError, OSError):
        pass
    finally:
        chan.close()


def serve(port, state, name, login_shell="clish"):
    env = make_env(state)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(20)
    while True:
        client, _ = sock.accept()

        def handle(client=client):
            t = paramiko.Transport(client)
            t.add_server_key(HOST_KEY)
            srv = Server()
            try:
                t.start_server(server=srv)
            except Exception:
                return
            chan = t.accept(20)
            if chan is None:
                return
            srv.event.wait(10)
            session(chan, name, env, login_shell)
            t.close()

        threading.Thread(target=handle, daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--shell", default="clish", choices=["clish", "bash"])
    ap.add_argument("--expert-delay", type=float, default=0.0,
                    help="seconds of silence after the expert password")
    ap.add_argument("--expert-needs-enter", action="store_true",
                    help="stay silent after the expert password until another Enter (CCTE lab gateways)")
    a = ap.parse_args()
    EXPERT_DELAY = a.expert_delay
    EXPERT_NEEDS_ENTER = a.expert_needs_enter
    serve(a.port, a.state, a.name, a.shell)
