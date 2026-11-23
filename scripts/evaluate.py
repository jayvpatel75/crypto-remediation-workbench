"""Evaluate a checked-in synthetic benchmark; not an independent expert assessment."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptoworkbench.engine import Asset, analyze, validate  # noqa: E402


def main():
    cases = json.loads((ROOT / "evaluation/cases.json").read_text())
    tp = fp = fn = exact = 0
    errors = []
    for c in cases:
        a = validate(Asset("benchmark", c["id"], c["kind"], c["observed"], c.get("context", {}), "cases.json", c["id"], "synthetic"))
        predicted = {f["rule"] for f in analyze([a])}
        expected = set(c["expected"])
        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        exact += predicted == expected
        if predicted != expected:
            errors.append({"case": c["id"], "predicted": sorted(predicted), "expected": sorted(expected)})
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    result = {"dataset": "Authored synthetic regression benchmark; no external or expert validation",
              "cases": len(cases), "exact_matches": exact, "true_positive_labels": tp,
              "false_positive_labels": fp, "false_negative_labels": fn,
              "precision": precision, "recall": recall,
              "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0,
              "errors": errors}
    out = ROOT / "build"
    out.mkdir(exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
