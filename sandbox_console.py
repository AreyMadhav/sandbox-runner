#!/usr/bin/env python3
"""Python runtime sandbox for dynamic analysis.

Usage notes
-----------
- This tool is for observing and intercepting runtime behavior (process
    launches, network, DNS, HTTP) of target commands.
- Run it only inside a VM or similarly controlled/lab environment; do not use
    on production or personal systems.
- Intended for ethical research, incident response, and malware analysis where
    you have permission to execute the target code.

Invoke via CLI or interactive console to wrap a target command. Use --python to
force Python interception if auto-detection is insufficient.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
from typing import Iterable, List, Tuple

BANNER = r"""
╔════════════════════════════╗
║  PYTHON RUNTIME SANDBOX    ║
║  Intercept > Observe       ║
╚════════════════════════════╝
@-- By AreyMadhav --@
"""

INTERCEPT_PREFIX = "[INTERCEPT]"

# Embedded sitecustomize payload that hooks common exfil/IO primitives (Python-only).
SITECUSTOMIZE_CODE = "\n".join(
    [
        "import datetime",
        "import json",
        "import socket",
        "import sys",
        "",
        'PREFIX = "[INTERCEPT]"',
        "",
        "def emit(event, data):",
        "    record = {",
        '        "time": datetime.datetime.utcnow().isoformat(),',
        '        "event": event,',
        '        "data": data,',
        "    }",
        "    try:",
        '        sys.stdout.write(PREFIX + " " + json.dumps(record) + "\\n")',
        "        sys.stdout.flush()",
        "    except Exception:",
        "        pass",
        "",
        "def safe_hook(apply):",
        "    try:",
        "        apply()",
        "    except Exception:",
        "        pass",
        "",
        "def hook_socket():",
        '    if getattr(socket.socket.connect, "_sandbox_hook", False):',
        "        return",
        "    _orig_connect = socket.socket.connect",
        "    def wrapped_connect(self, address):",
        '        emit("socket", {"address": address})',
        "        return _orig_connect(self, address)",
        "    wrapped_connect._sandbox_hook = True",
        "    socket.socket.connect = wrapped_connect",
        "    _orig_create_connection = socket.create_connection",
        "    def wrapped_create(addr, *a, **kw):",
        '        emit("socket", {"address": addr})',
        "        return _orig_create_connection(addr, *a, **kw)",
        "    wrapped_create._sandbox_hook = True",
        "    socket.create_connection = wrapped_create",
        "    _orig_getaddrinfo = socket.getaddrinfo",
        "    def wrapped_dns(*a, **kw):",
        '        host = a[0] if a else kw.get("host")',
        '        emit("dns", {"host": host})',
        "        return _orig_getaddrinfo(*a, **kw)",
        "    wrapped_dns._sandbox_hook = True",
        "    socket.getaddrinfo = wrapped_dns",
        "",
        "def hook_requests():",
        "    try:",
        "        import requests",
        "    except Exception:",
        "        return",
        '    if getattr(requests.Session.request, "_sandbox_hook", False):',
        "        return",
        "    _orig_request = requests.Session.request",
        "    def wrapped(self, method, url, *a, **kw):",
        '        emit("http", {"method": method, "url": url})',
        "        return _orig_request(self, method, url, *a, **kw)",
        "    wrapped._sandbox_hook = True",
        "    requests.Session.request = wrapped",
        "",
        "def hook_urllib():",
        "    try:",
        "        import urllib.request",
        "    except Exception:",
        "        return",
        '    if getattr(urllib.request.urlopen, "_sandbox_hook", False):',
        "        return",
        "    _orig_urlopen = urllib.request.urlopen",
        "    def wrapped(url, *a, **kw):",
        '        method = kw.get("method") or "GET"',
        '        emit("http", {"method": method, "url": url})',
        "        return _orig_urlopen(url, *a, **kw)",
        "    wrapped._sandbox_hook = True",
        "    urllib.request.urlopen = wrapped",
        "",
        "def hook_http_client():",
        "    try:",
        "        import http.client",
        "    except Exception:",
        "        return",
        '    if getattr(http.client.HTTPConnection.request, "_sandbox_hook", False):',
        "        return",
        "    _orig_request = http.client.HTTPConnection.request",
        "    def wrapped(self, method, url, *a, **kw):",
        '        emit("http", {"method": method, "url": url})',
        "        return _orig_request(self, method, url, *a, **kw)",
        "    wrapped._sandbox_hook = True",
        "    http.client.HTTPConnection.request = wrapped",
        "",
        "def hook_subprocess():",
        "    try:",
        "        import subprocess",
        "    except Exception:",
        "        return",
        '    if getattr(subprocess.Popen, "_sandbox_hook", False):',
        "        return",
        "    _orig_popen = subprocess.Popen",
        "    def wrapped_popen(cmd, *a, **kw):",
        "        try:",
        "            if isinstance(cmd, (list, tuple)):",
        "                cmdline = list(cmd)",
        "            else:",
        "                cmdline = [str(cmd)]",
        "        except Exception:",
        '            cmdline = ["<unserializable>"]',
        '        emit("process", {"cmd": cmdline, "cwd": kw.get("cwd")})',
        "        return _orig_popen(cmd, *a, **kw)",
        "    wrapped_popen._sandbox_hook = True",
        "    subprocess.Popen = wrapped_popen",
        "",
        "safe_hook(hook_socket)",
        "safe_hook(hook_requests)",
        "safe_hook(hook_urllib)",
        "safe_hook(hook_http_client)",
        "safe_hook(hook_subprocess)",
        "",
    ]
)

def looks_like_python(cmd: List[str]) -> bool:
    if not cmd:
        return False
    head = cmd[0].lower()
    if head.endswith(".py"):
        return True
    if os.path.basename(head).startswith("python"):
        return True
    return False

class SandboxRunner:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None
        self.tempdir: tempfile.TemporaryDirectory[str] | None = None
        self.log_path: str | None = None

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, cmd: List[str], force_python: bool = False) -> None:
        if self.running():
            raise RuntimeError("A command is already running.")

        python_mode = force_python or looks_like_python(cmd)

        env = os.environ.copy()
        self.tempdir = None

        if python_mode:
            self.tempdir = tempfile.TemporaryDirectory()
            sc_path = os.path.join(self.tempdir.name, "sitecustomize.py")
            with open(sc_path, "w", encoding="utf-8") as f:
                f.write(SITECUSTOMIZE_CODE)
            env["PYTHONPATH"] = self.tempdir.name + os.pathsep + env.get("PYTHONPATH", "")
            env["PYTHONUNBUFFERED"] = "1"
            self.log_path = os.path.join(self.tempdir.name, "events.jsonl")
        else:
            self.log_path = None  # no intercept log in raw mode

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env if python_mode else None,
        )
        self.reader_thread = threading.Thread(target=self._reader, args=(python_mode,), daemon=True)
        self.reader_thread.start()

    def stop(self) -> None:
        if not self.proc:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        if self.tempdir:
            self.tempdir.cleanup()
            self.tempdir = None
            self.log_path = None

    def status(self) -> str:
        if not self.proc:
            return "idle"
        if self.proc.poll() is None:
            return "running"
        return f"exited ({self.proc.poll()})"

    def _reader(self, python_mode: bool) -> None:
        assert self.proc and self.proc.stdout
        log = None
        if python_mode and self.log_path:
            log = open(self.log_path, "a", encoding="utf-8")
        try:
            for raw in self.proc.stdout:
                if python_mode and raw.startswith(INTERCEPT_PREFIX):
                    self._handle_intercept(raw, log)
                    continue
                print(f"[OUT ] {raw}", end="")
        finally:
            if log:
                log.close()
        code = self.proc.wait()
        print(f"[*] Target exited with code {code}")

    def _handle_intercept(self, raw: str, log_file) -> None:
        try:
            payload = json.loads(raw.replace(INTERCEPT_PREFIX, "", 1).strip())
        except json.JSONDecodeError:
            print(f"[WARN] Could not decode intercept line: {raw.strip()}")
            return

        if log_file:
            log_file.write(json.dumps(payload) + "\n")
            log_file.flush()

        event = payload.get("event")
        data = payload.get("data", {})

        if event == "http":
            method = str(data.get("method", "?")).upper()
            url = data.get("url", "?")
            print(f"[HTTP] {method} {url}")
        elif event == "dns":
            print(f"[DNS ] {data.get('host')}")
        elif event == "socket":
            addr = data.get("address")
            if isinstance(addr, (list, tuple)) and len(addr) >= 2:
                host, port = addr[0], addr[1]
            else:
                host, port = addr, "?"
            print(f"[SOCK] {host}:{port}")
        elif event == "process":
            cmd = data.get("cmd")
            cmd_display = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            print(f"[PROC] {cmd_display}")
        else:
            print(f"[EVNT] {event}: {data}")

RUN_USAGE = "run [--python|--py] <command> [args...]"


def parse_run_command(raw: str) -> Tuple[List[str], bool, bool]:
    tokens = shlex.split(raw)
    if not tokens:
        raise ValueError("No command provided.")

    force_python = False
    help_requested = False

    while tokens and tokens[0].lower() in ("--python", "--py"):
        force_python = True
        tokens = tokens[1:]

    if tokens and tokens[0] in ("-h", "--help"):
        help_requested = True
        tokens = tokens[1:]

    if help_requested and not tokens:
        return [], force_python, True

    if not tokens:
        raise ValueError("No command provided after flags.")

    return tokens, force_python, help_requested


def print_help() -> None:
    print("Commands:")
    print(f"  {RUN_USAGE}")
    print("  stop")
    print("  status")
    print("  help | -h | --help")
    print("  exit")
    print("")
    print("Examples:")
    print("  run --python sample.py --opt 1           # Python with hooks")
    print("  run python sample.py --opt 1             # Auto-detected Python hooks")
    print("  run --python \"Anime API Hunter.py\"      # Python file with spaces in name")
    print("  run ./malware_elf --config cfg.yaml      # ELF raw run")
    print("  run C:\\path\\tool.exe /S                 # EXE raw run")
    print("  run /usr/local/bin/payload -v --mode test # Generic binary raw run")
    print("  run --python ./renamed_py_bin --arg foo   # Force hooks for renamed Python")

def interactive_console() -> None:
    print(BANNER)
    runner = SandboxRunner()

    while True:
        try:
            cmd = input("sandbox > ").strip()
        except (KeyboardInterrupt, EOFError):
            cmd = "exit"

        if cmd.startswith("run "):
            if runner.running():
                print("[!] A command is already running.")
                continue
            try:
                command, force_python, help_requested = parse_run_command(cmd[4:])
            except ValueError as exc:
                print(f"[!] {exc}")
                continue

            if help_requested:
                print(f"Usage: {RUN_USAGE}")
                continue

            try:
                runner.start(command, force_python=force_python)
                print("[*] Target started.")
            except Exception as exc:
                print(f"[!] Failed to start: {exc}")

        elif cmd == "stop":
            runner.stop()
            print("[*] Target stopped.")

        elif cmd == "status":
            print(f"[*] Status: {runner.status()}")

        elif cmd == "exit":
            runner.stop()
            print("[*] Sandbox stopped.")
            break

        elif cmd in ("help", "-h", "--help"):
            print_help()

        elif cmd == "":
            continue

        else:
            print("Unknown command. Type help.")

def main() -> None:
    parser = argparse.ArgumentParser(description="Runtime sandbox interceptor.")
    parser.add_argument("--python", "--py", action="store_true", dest="force_python", help="Force Python hooks even if command is not obviously Python.")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run (prefix args with -- to separate).")
    args = parser.parse_args()

    if args.command:
        # argparse with REMAINDER keeps leading --; strip if present
        cmd = args.command
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("[!] No command provided.")
            sys.exit(1)
        runner = SandboxRunner()
        try:
            runner.start(cmd, force_python=args.force_python)
            print("[*] Target started.")
            if runner.reader_thread:
                runner.reader_thread.join()
        finally:
            runner.stop()
    else:
        interactive_console()

if __name__ == "__main__":
    main()
