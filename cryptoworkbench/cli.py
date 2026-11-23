"""CLI for analysis, offline dashboard, and JSONL handoff."""
import argparse
from collections import Counter
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys

from .engine import POLICY_VERSION, analyze, inventory, load


def build(inputs, out):
    assets = []
    warnings = []
    for path in inputs:
        loaded = load(path)
        if not loaded:
            warnings.append(f"{path.name}: no supported cryptographic observations; see adapter contract")
        assets.extend(loaded)
    findings = analyze(assets)
    report = {"policy_version": POLICY_VERSION,
              "summary": {"applications": len({a.app for a in assets}), "assets": len(assets),
                          "findings": len(findings), "by_severity": dict(Counter(f["severity"] for f in findings))},
              "warnings": warnings, "inventory": inventory(assets), "findings": findings}
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = [{"schema": "workbench.handoff.v1", "task": "cryptographic_remediation",
             "input": {k: f[k] for k in ("app", "asset", "observed", "evidence", "constraints")},
             "proposed_label": {k: f[k] for k in ("rule", "classification", "severity", "rationale", "plan")},
             "review_status": "unreviewed", "eligible_for_training": False} for f in findings]
    (out / "handoff.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    # JSON is data inside a non-executable script. Escape HTML delimiters to prevent script breakout.
    embedded = json.dumps(report).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    (out / "index.html").write_text(template.replace("__REPORT_JSON__", embedded), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("analyze")
    scan.add_argument("inputs", nargs="+", type=Path)
    scan.add_argument("--out", type=Path, default=Path("build"))
    serve = sub.add_parser("serve")
    serve.add_argument("--directory", type=Path, default=Path("build"))
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            report = build(args.inputs, args.out)
            print(json.dumps(report["summary"], indent=2))
            for warning in report["warnings"]:
                print("Warning: " + warning, file=sys.stderr)
            print(f"Dashboard: {args.out.resolve() / 'index.html'}")
        else:
            if not (args.directory / "index.html").is_file():
                parser.error("Run analyze first; dashboard is missing")
            handler = partial(SimpleHTTPRequestHandler, directory=str(args.directory.resolve()))
            server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
            print(f"Dashboard: http://127.0.0.1:{args.port} (Ctrl+C to stop)", flush=True)
            server.serve_forever()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"Input or output error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
