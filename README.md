# Sandbox Runner (Python Runtime Sandbox)

Python runtime sandbox for dynamic analysis. Intercepts common I/O channels (process creation, DNS lookups, socket connects, HTTP requests) while streaming target stdout. Built for ethical research, incident response, and malware analysis in controlled environments.

## Safety and ethics
- Run only inside a VM or similarly controlled lab environment; never on production or personal systems.
- Use only with code and binaries you are authorized to execute.
- Expect untrusted code to behave maliciously; isolate networking and filesystem accordingly.

## Features
- Python mode auto-injects hooks via `sitecustomize` to log network/process events.
- Raw mode runs non-Python binaries without injection (still streams stdout/stderr).
- Emits human-readable intercept lines (`[HTTP]`, `[DNS ]`, `[SOCK]`, `[PROC]`).
- Writes JSONL intercept log (`events.jsonl`) in a temp directory for Python targets.

## Requirements
- Python 3.9+ (tested on recent CPython).
- Windows/macOS/Linux with standard Python stdlib; no external deps.

## Quick start
```bash
# interactive console
python sandbox_console.py

# start a Python sample with hooks
a: run --python sample.py --opt 1
# stop / status / exit commands are available
```

Non-interactive one-liner:
```bash
python sandbox_console.py --python -- sample.py --opt 1
```

Run a binary without hooks:
```bash
python sandbox_console.py -- ./tool.exe /S
```

## Intercept output cheatsheet
- `[HTTP] METHOD URL`
- `[DNS ] host`
- `[SOCK] host:port`
- `[PROC] command line`
- `[OUT ] line` (passthrough stdout)

For Python-mode runs, a temp dir holds `sitecustomize.py` and `events.jsonl`; it is cleaned up when the run ends.

## Limitations
- Hooks cover common Python networking/process APIs (socket, requests, urllib, http.client, subprocess).
- Raw binaries are not instrumented beyond stdout passthrough.
- This is not a sandboxing boundary; it is an observer. Use OS/container/VM isolation for safety.

## License
MIT. See LICENSE for full text.

## Author
AreyMadhav
