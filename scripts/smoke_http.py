"""Check local HTTP delivery without opening or controlling a browser."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(ROOT / "demo")))
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
base = f"http://127.0.0.1:{server.server_port}"
try:
    with urlopen(base + "/", timeout=5) as response:
        assert response.status == 200
        assert b"Crypto Remediation Workbench" in response.read()
    with urlopen(base + "/report.json", timeout=5) as response:
        report = json.load(response)
        assert report["summary"]["applications"] == 25
    with urlopen(base + "/handoff.jsonl", timeout=5) as response:
        rows = [json.loads(line) for line in response.read().decode().splitlines()]
        assert len(rows) == report["summary"]["findings"]
        assert all(not row["eligible_for_training"] for row in rows)
    print(f"HTTP smoke passed: 25 apps, {len(rows)} review-gated handoff records")
finally:
    server.shutdown()
    server.server_close()
