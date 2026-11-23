# Evaluation methodology

`python scripts/evaluate.py` compares predicted rule sets against 21 authored synthetic cases in evaluation/cases.json. Label-level true positives, false positives and false negatives yield precision, recall and F1; exact-match cases measure full rule-set agreement.

Cases cover eight rules and negative controls: modern TLS, AES-128-GCM without a stricter policy, RSA SSH keys using SHA-2, public certificates that are not secret material, modern VPN proposals and ML-KEM dependencies.

This is a regression benchmark written for this implementation. Expected labels have not been independently reviewed, and matching them does not establish real-world accuracy, compliance, remediation safety or expert equivalence. There is no held-out production dataset. Rule evaluation does not grade the semantic correctness of every generated plan.

The unit suite separately tests ingestion errors, nested BOM traversal, provenance, redaction, deduplication, output escaping, decision distinctions and infrastructure constraints. GitHub Actions runs the suite and generates a downloadable demo artifact on Python 3.11, 3.12 and 3.13.

For a stronger future evaluation, obtain independent SME annotations, split by application/vendor to avoid leakage, evaluate unsupported/missing evidence, assess inter-reviewer agreement, and score remediation feasibility separately from classification correctness. Keep such evidence offline unless authorized for publication.
