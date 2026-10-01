"""
Interactive SSH shell to a Gaia host via Paramiko.

Handles both login shells found in the labs:
  - Clish (prompt ends in '>')  -> runs 'expert' and supplies the expert password
  - Bash  (prompt ends in '#')  -> used as-is

Each command is wrapped in begin/end markers so its output can be cut out
cleanly regardless of terminal echo, banners or prompts. The marker text in
the echoed command line is split with '' so only the real output matches.
"""
import re
import time
import uuid
import logging

import paramiko

logger = logging.getLogger("cplpmon.shell")

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[=>]")
CLISH_PROMPT_RE = re.compile(r">\s*$")
BASH_PROMPT_RE = re.compile(r"[#$]\s*$")
PASSWORD_PROMPT_RE = re.compile(r"(?i)password:\s*$")


class GaiaShellError(Exception):
    pass


def clean(text: str) -> str:
    text = ANSI_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


class GaiaShell:
    def __init__(self, host, user, password, expert_password=None, port=22,
                 connect_timeout=20, login_timeout=90):
        self.host = host
        self.user = user
        self.password = password
        self.expert_password = expert_password or password
        self.port = port
        self.connect_timeout = connect_timeout
        # Upper bound for each login step (prompt, expert, expert password).
        self.login_timeout = login_timeout
        self.client = None
        self.chan = None
        self.login_shell = None  # "clish" or "bash"

    # ---------- low level ----------
    def _recv_available(self) -> str:
        out = ""
        while self.chan.recv_ready():
            out += self.chan.recv(65535).decode("utf-8", errors="replace")
        return out

    def _read_until(self, patterns, timeout, buf=""):
        """Read until the last line of the buffer matches one of patterns.
        Returns (buffer, index_of_matching_pattern) or raises on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self._recv_available()
            if chunk:
                buf += chunk
                last = clean(buf).rstrip("\n").split("\n")[-1]
                for i, p in enumerate(patterns):
                    if p.search(last):
                        return buf, i
            elif self.chan.exit_status_ready():
                raise GaiaShellError("SSH channel closed by remote host")
            else:
                time.sleep(0.1)
        tail = clean(buf)[-300:]
        raise GaiaShellError(f"Timed out after {timeout}s waiting for prompt"
                             f"{' (' + self.stage + ')' if getattr(self, 'stage', '') else ''}. Last output: {tail!r}")

    def _wait_expert_prompt(self):
        """After the expert password, Gaia can sit silent until it gets another Enter
        (seen on every host of the CCTE lab, 28 Sep 2026: nothing for 30 s and more, then
        the banner and [Expert@host:0]# appear within a second of an extra Enter).
        So nudge with an Enter every few seconds until a prompt shows up."""
        pats = [BASH_PROMPT_RE, CLISH_PROMPT_RE, PASSWORD_PROMPT_RE]
        buf, deadline, nudge = "", time.time() + self.login_timeout, 3
        while True:
            left = deadline - time.time()
            if left <= 0:
                return self._read_until(pats, timeout=0.1, buf=buf)   # raises with context
            try:
                return self._read_until(pats, timeout=min(nudge, left), buf=buf)
            except GaiaShellError as e:
                if "closed" in str(e):
                    raise
            buf += self._recv_available()
            self._send("")          # the extra Enter
            nudge = 5

    def _send(self, line: str):
        self.chan.send(line + "\n")

    # ---------- session ----------
    def open(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.host, port=self.port,
                username=self.user, password=self.password,
                timeout=self.connect_timeout, banner_timeout=30, auth_timeout=30,
                look_for_keys=False, allow_agent=False,
            )
        except paramiko.AuthenticationException:
            raise GaiaShellError(f"SSH authentication failed for {self.user}@{self.host}")
        except Exception as e:
            raise GaiaShellError(f"SSH connect to {self.host} failed: {e}")

        # Wide terminal so long lines (cpinfo, CPUSE tables) are not wrapped
        self.chan = self.client.invoke_shell(term="vt100", width=400, height=100)
        self.stage = "login prompt"
        buf, idx = self._read_until([CLISH_PROMPT_RE, BASH_PROMPT_RE], timeout=self.login_timeout)

        if idx == 0:
            self.login_shell = "clish"
            self._send("expert")
            self.stage = "after 'expert'"
            buf, idx = self._read_until(
                [PASSWORD_PROMPT_RE, BASH_PROMPT_RE, CLISH_PROMPT_RE], timeout=self.login_timeout)
            if idx == 2:
                msg = clean(buf).strip().split("\n")[-2:]
                raise GaiaShellError(
                    f"'expert' refused on {self.host} (is an expert password set?): {' '.join(msg)}")
            if idx == 0:
                self._send(self.expert_password)
                self.stage = "after expert password"
                buf, idx = self._wait_expert_prompt()
                if idx != 0:
                    raise GaiaShellError(f"Expert password rejected on {self.host}")
        else:
            self.login_shell = "bash"

        self.stage = ""
        # Quieter, predictable shell. Don't leave our commands in bash history.
        self.run("unset HISTFILE; export TERM=dumb; stty -echo 2>/dev/null; true", timeout=15)
        return self

    def run(self, command: str, timeout: int = 120) -> dict:
        """Run a command in expert mode. Returns {output, rc, timed_out}."""
        tag = uuid.uuid4().hex[:10]
        begin = f"__CPLP_B_{tag}__"
        end_re = re.compile(rf"__CPLP_E_{tag}__ rc=(\d+)")
        wrapped = (f"echo __CPLP_B_''{tag}__; {{ {command} ; }} 2>&1; "
                   f"echo __CPLP_E_''{tag}__ rc=$?")
        self._send(wrapped)

        buf = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self._recv_available()
            if chunk:
                buf += chunk
                text = clean(buf)
                m = end_re.search(text)
                if m:
                    start = text.find(begin + "\n")
                    start = start + len(begin) + 1 if start >= 0 else 0
                    body = text[start:m.start()]
                    return {"output": body.rstrip("\n"), "rc": int(m.group(1)), "timed_out": False}
            elif self.chan.exit_status_ready():
                raise GaiaShellError("SSH channel closed during command")
            else:
                time.sleep(0.1)

        # Timed out: interrupt and resync with the shell
        self.chan.send("\x03")
        time.sleep(1)
        self._recv_available()
        text = clean(buf)
        start = text.find(begin + "\n")
        body = text[start + len(begin) + 1:] if start >= 0 else ""
        return {"output": body.rstrip("\n"), "rc": None, "timed_out": True}

    def close(self):
        try:
            if self.chan:
                self.chan.close()
        finally:
            if self.client:
                self.client.close()

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()
