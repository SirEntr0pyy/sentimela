#!/usr/bin/env python3
"""Exercise real central, agent and SSH viewer binaries on Linux without root."""
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import urllib.error
import urllib.request

BINARY = os.environ.get("SENTINELA_TEST_BINARY", str(Path(__file__).resolve().parents[1] / "target/release/sentinela"))
TOKEN = secrets.token_hex(32)
ENV = dict(os.environ, SENTINELA_HUB_TOKEN=TOKEN, TERM="xterm-256color",
           SSH_CONNECTION="192.0.2.1 54321 192.0.2.2 22")


def request(url, path, value=None, authenticated=True):
    headers = {"Authorization": "Bearer " + TOKEN} if authenticated else {}
    data = None
    if value is not None:
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, None


def start_hub(directory):
    process = subprocess.Popen(
        [BINARY, "hub", "--bind", "127.0.0.1:0", "--journal", "events.jsonl"],
        cwd=directory, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if not select.select([process.stderr], [], [], 10)[0]:
        process.kill()
        raise AssertionError("central startup timed out")
    line = process.stderr.readline().decode()
    match = re.search(r"127\.0\.0\.1:(\d+)", line)
    assert match, line
    return process, "http://127.0.0.1:" + match[1]


def stop(process):
    process.send_signal(signal.SIGINT)
    try:
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stderr:
            process.stderr.close()


def terminal_run(arguments, directory, width, height, actions):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([BINARY] + arguments, cwd=directory, env=ENV,
                               stdin=slave, stdout=slave, stderr=slave)
    output = bytearray()

    def drain(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                output.extend(os.read(master, 65536))
    try:
        drain(1.2)
        assert process.poll() is None, bytes(output).decode(errors="replace")
        for keys in actions:
            os.write(master, keys)
            drain(0.3)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 20, 36, 0, 0))
        drain(0.3)
        os.write(master, b"q")
        deadline = time.monotonic() + 10
        while process.poll() is None and time.monotonic() < deadline:
            drain(0.1)
        assert process.wait(timeout=1) == 0, bytes(output).decode(errors="replace")
        assert b"panicked" not in output
        assert termios.tcgetattr(slave) == original, "terminal settings were not restored"
        assert b"\x1b[?1049l" in output, "alternate screen was not restored"
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


with tempfile.TemporaryDirectory(prefix="sentimela-e2e-") as directory:
    process, url = start_hub(directory)
    try:
        assert request(url, "/api/v1/snapshot", authenticated=False)[0] == 401
        assert request(url, "/api/v1/incident", b"x" * 20000)[0] == 413
        base = dict(timestamp="2026-11-13 12:00:00", ip="192.0.2.42",
                    port=2222, service="SSH Honeypot", severity="CRÍTICO",
                    country="Test", city="Lab", isp="Test", rdns=None,
                    payload="SSH-2.0-test", threat_score=85, hit_count=1)
        for node in ["node-a", "node-b"]:
            assert request(url, "/api/v1/heartbeat", dict(
                id=node, name=node, ip="127.0.0.1", version="test"))[0] == 204
            value = dict(base, node_id=node, event_id="event-1")
            assert request(url, "/api/v1/incident", value)[0] == 200
            assert request(url, "/api/v1/incident", value)[1]["duplicate"]
        _, snapshot = request(url, "/api/v1/snapshot")
        assert snapshot["accepted"] == 2
        assert snapshot["correlations"][0]["nodes"] == ["node-a", "node-b"]
        print("PASS central: authentication, body limit, durable events, dedup, correlation", flush=True)

        for width, height in [(20, 10), (32, 16), (40, 24), (80, 24)]:
            terminal_run(["watch", "--hub", url], directory, width, height,
                         [b"/ssh\r", b"\r", b"\x1b"])
            print(f"PASS central viewer {width}x{height}: search, detail, resize, terminal restored", flush=True)

        terminal_run(["--simulate", "0", "--hub", url, "--node-id", "agent-e2e"],
                     directory, 40, 24, [])
        _, snapshot = request(url, "/api/v1/snapshot")
        assert snapshot["accepted"] == 5, snapshot
        assert sum(r["event"]["node_id"] == "agent-e2e" for r in snapshot["incidents"]) == 3
        print("PASS real agent forwards three simulated incidents", flush=True)
    finally:
        stop(process)

    path = Path(directory) / "events.jsonl"
    assert path.stat().st_mode & 0o077 == 0, "journal permissions too broad"
    with path.open("ab") as journal:
        journal.write(b'{"torn":')
    process, url = start_hub(directory)
    try:
        _, snapshot = request(url, "/api/v1/snapshot")
        assert snapshot["accepted"] == 5
        assert path.read_bytes().endswith(b"\n")
        print("PASS restart: durable history and torn-tail recovery", flush=True)
    finally:
        stop(process)

    # Network errors must remain visible and must not trap the viewer in raw mode.
    output = terminal_run(["watch", "--hub", url], directory, 32, 16, [])
    plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", output)
    assert b"SEMLIGA" in plain and b"error" in plain, repr(plain)
    print("PASS offline viewer remains usable and restores terminal", flush=True)
