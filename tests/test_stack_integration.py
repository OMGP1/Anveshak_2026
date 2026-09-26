"""Opt-in real TLS/Go/Rust/browser test; only self-owned ephemeral loopback endpoints.

SIH_STACK_TEST=1 python3 -m pytest -q tests/test_stack_integration.py -s
SIH_BROWSER_TEST=1 additionally drives a fresh isolated Chrome profile (macOS default).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest
from websockets.sync.client import connect

from tools.prepare_deployment import provision

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("SIH_STACK_TEST") != "1", reason="Opt-in real localhost stack test")


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def until(function, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, urllib.error.URLError) as exc:
            last = exc
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for local stack: {last}")


def browser_check(base: str, credentials_path: Path, directory: Path) -> dict:
    token = json.loads(credentials_path.read_text())["admin"]
    chrome_path = os.environ.get("SIH_CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if not Path(chrome_path).is_file():
        raise AssertionError("Requested browser check needs SIH_CHROME")
    profile = directory / "chrome-profile"
    process = subprocess.Popen([chrome_path, "--headless=new", "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
        "--ignore-certificate-errors", "--remote-debugging-port=0", "--user-data-dir=" + str(profile), "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until(lambda: (profile / "DevToolsActivePort").is_file())
        debug_port = (profile / "DevToolsActivePort").read_text().splitlines()[0]
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/list", timeout=3))
        tab = next(row for row in tabs if row["type"] == "page" and row["url"] == "about:blank")
        with connect(tab["webSocketDebuggerUrl"], proxy=None, open_timeout=5) as ws:
            sequence = 0
            errors = []
            navigation_events = []
            def call(method, params=None):
                nonlocal sequence
                sequence += 1
                ws.send(json.dumps({"id": sequence, "method": method, "params": params or {}}))
                while True:
                    message = json.loads(ws.recv(timeout=10))
                    if message.get("method") == "Runtime.exceptionThrown":
                        errors.append(message["params"])
                    if message.get("method") == "Network.loadingFailed":
                        navigation_events.append(message["params"])
                    if message.get("method") == "Network.responseReceived":
                        response = message["params"]["response"]
                        navigation_events.append({"url": response["url"].split("?")[0], "status": response["status"]})
                    if message.get("method") == "Log.entryAdded":
                        navigation_events.append({"log": message["params"]["entry"]["text"]})
                    if message.get("method") == "Network.requestWillBeSentExtraInfo":
                        headers = message["params"]["headers"]
                        navigation_events.append({"origin": headers.get("origin", headers.get("Origin", "absent"))})
                    if message.get("id") == sequence:
                        assert "error" not in message, message
                        return message.get("result", {})
            def js(expression):
                response = call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
                assert "exceptionDetails" not in response, response
                return response.get("result", {}).get("value")
            call("Runtime.enable")
            call("Page.enable")
            call("Network.enable")
            call("Log.enable")
            navigation = call("Page.navigate", {"url": base + "/?mock=0"})
            try:
                until(lambda: js("document.body.innerText.includes('Detection enclave login')"), timeout=10)
            except AssertionError as exc:
                raise AssertionError({"navigation": navigation, "events": navigation_events[-10:],
                    "page": js("({url:location.href,title:document.title,text:document.body.innerText})")}) from exc
            js("document.querySelector('input[name=token]').value=" + json.dumps(token) + "; document.querySelector('form').requestSubmit()")
            try:
                until(lambda: js("Boolean([...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Operations'))"), timeout=10)
            except AssertionError as exc:
                raise AssertionError({"events": navigation_events[-10:],
                    "page": js("({url:location.href,title:document.title,text:document.body.innerText})")}) from exc
            js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Operations').click()")
            until(lambda: js("document.body.innerText.includes('Problem statement 26145') && document.body.innerText.includes('31,264')"))
            assert js("document.body.innerText.includes('iperf3') && document.body.innerText.includes('DGArchive')")
            until(lambda: js("document.body.innerText.includes('Exact tool methods validated: 0/47')"))
            assert js("document.body.innerText.includes('Extended packet-rate alarms: enabled')")
            assert js("document.body.innerText.includes('SYN-attempt alarms: enabled')")
            until(lambda: js("document.body.innerText.includes('Beacon windows skipped: 0')"))
            js("[...document.querySelectorAll('summary')].find(s=>s.textContent.includes('Inspect 47 registered methods')).click()")
            assert js("[...document.querySelectorAll('summary')].find(s=>s.textContent.includes('Inspect 47 registered methods')).parentElement.querySelectorAll('tbody tr').length") == 47
            until(lambda: js("Boolean([...document.querySelectorAll('button')].find(b=>b.textContent.includes('Train quality candidate') && !b.disabled))"))
            js("[...document.querySelectorAll('button')].find(b=>b.textContent.includes('Train quality candidate')).click()")
            until(lambda: js("document.body.innerText.includes('running')"))
            screenshot = call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
            (directory / "dashboard.png").write_bytes(base64.b64decode(screenshot["data"]))
            assert not errors, errors
            return {"login": True, "inventory_rendered": True, "coverage_rows": 47,
                    "exact_methods_validated": 0, "training_clicked": True, "uncaught_exceptions": len(errors)}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def test_hardened_stack(tmp_path):
    provision(tmp_path / "runtime")
    runtime = tmp_path / "runtime"
    secrets = runtime / "secrets"
    credentials = json.loads((secrets / "operator-credentials.json").read_text())
    api_port, gateway_port = port(), port()
    base = f"https://localhost:{gateway_port}"
    environment = dict(os.environ, SIH_PRODUCTION="1", SIH_GATEWAY_SECRET_FILE=str(secrets / "backend-token"),
        SIH_MODEL_PUBLIC_KEY=str(secrets / "model-trust.pub"), SIH_MODEL_DIR=str(runtime / "models"),
        SIH_STATE_DIR=str(runtime / "state"), SIH_API_PORT=str(api_port), SIH_API_HOST="127.0.0.1",
        SIH_ENGINE_CONFIG=str(ROOT / "config/engine-production.json"), SIH_AUTO_TRAIN="0",
        OMP_NUM_THREADS="2", OPENBLAS_NUM_THREADS="2", MKL_NUM_THREADS="2")
    context = ssl.create_default_context(cafile=str(secrets / "tls.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    def request(path, role="admin", body=None):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + credentials[role], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, None
    processes = []
    with (tmp_path / "api.log").open("w") as api_log, (tmp_path / "gateway.log").open("w") as gate_log:
        try:
            processes.append(subprocess.Popen([sys.executable, "-m", "api.main"], cwd=ROOT, env=environment, stdout=api_log, stderr=api_log))
            processes.append(subprocess.Popen([str(ROOT / "gateway/sih-gateway"), "-listen", f"127.0.0.1:{gateway_port}",
                "-upstream", f"http://127.0.0.1:{api_port}", "-public-host", f"localhost:{gateway_port}",
                "-users", str(secrets / "gateway-users.json"), "-backend-secret", str(secrets / "backend-token"),
                "-audit", str(runtime / "state/gateway-audit.jsonl"), "-cert", str(secrets / "tls.crt"), "-key", str(secrets / "tls.key")],
                cwd=ROOT, stdout=gate_log, stderr=gate_log))
            until(lambda: request("/api/health")[0] == 200)
            assert request("/api/replay/stop", "viewer", {})[0] == 403
            assert request("/api/training/start", "operator", {})[0] == 403
            with pytest.raises(urllib.error.HTTPError) as direct:
                urllib.request.urlopen(f"http://127.0.0.1:{api_port}/api/status", timeout=3)
            assert direct.value.code == 401
            with connect(f"wss://localhost:{gateway_port}/ws", ssl=context, proxy=None, origin=base,
                         additional_headers={"Authorization": "Bearer " + credentials["viewer"]}) as ws:
                assert json.loads(ws.recv(timeout=5))["type"] == "status"
                assert request("/api/replay/start", "operator", {"scenario": "syn_flood", "mode": "virtual", "source": "rust-pcap"})[0] == 200
                until(lambda: not request("/api/status")[1]["running"])
            alerts = request("/api/alerts")[1]
            assert alerts and request("/api/ledger/verify")[1]["ok"]
            assert request("/api/health")[1]["replay_error"] is None
            browser = None
            if os.environ.get("SIH_BROWSER_TEST") == "1":
                browser = browser_check(base, secrets / "operator-credentials.json", tmp_path)
                until(lambda: request("/api/training")[1]["state"] != "running", timeout=120)
                job = request("/api/training")[1]
                assert job["state"] == "candidate_rejected", job
                assert not job["serving_model_changed"]
            report = {"tls13": True, "role_checks": True, "direct_api_denied": True, "websocket": True,
                "rust_replay_alerts": len(alerts), "browser": browser,
                "training_state": request("/api/training")[1]["state"], "evidence_directory": str(tmp_path)}
            (tmp_path / "stack-report.json").write_text(json.dumps(report, indent=2))
            print(json.dumps(report))
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
