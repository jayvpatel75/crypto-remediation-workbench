# Architecture and decisions

The system separates observations, risk classification, and proposed actions so a reviewer can trace each recommendation to input evidence.

## Ingestion and provenance

Input files are capped at 10 MB. Each asset retains the input filename, JSON pointer and SHA-256 of the complete original file. SHA-256 enables local evidence verification; it does not prove authenticity. Raw secret values and scanner snippets are excluded by an observation allowlist. Context is restricted to documented fields. The original files are not copied to output.

The CycloneDX adapter is intentionally narrow. Namespaced properties represent contextual scanner facts that are not otherwise available in the BOM. Native TLS protocol components can also be ingested. A software library's presence alone cannot demonstrate negotiated TLS versions or correct key management. An empty extraction produces a coverage warning rather than a clean security verdict.

## Decision model

Eight versioned rules return distinct classifications: weakness, migration and policy. Stable finding IDs derive from application, asset reference, rule and normalized observations. Duplicate identical findings collapse; the first input supplies provenance. Different observations remain separate. Asset totals count input observations and may include duplicates.

Priority = severity base (critical 85, high 65, medium 40, low 20) + 10 for internet exposure + 5 for high business criticality, capped at 100. This is an ordering heuristic. Missing owner or business criticality lowers context confidence; it is not calibrated statistical confidence.

## Remediation planning

Plans include owner confirmation, relevant load balancer/device constraints, a rule-specific proposal, canary validation and a rollback requirement. Hardware support is supplied context, not discovered fact. Long-lived confidentiality increases priority for quantum-vulnerable key establishment. ML-KEM is not proposed as a signature replacement.

Credential findings map to secret-manager retrieval. Cryptographic keys map to a KMS/HSM suitability assessment; some applications require redesign to use non-exportable keys. A KMS reference alone does not remediate a previously exposed key: rotation is required.

## Output and trust boundaries

The CLI emits an allowlisted JSON inventory and report. The dashboard embeds escaped JSON and renders imported text with `textContent`; input is never executed as HTML or instructions. The optional server binds only to localhost. All outputs remain readable files: operating-system permissions and storage protection are the operator's responsibility.

JSONL proposals explicitly carry `eligible_for_training: false` and `review_status: unreviewed`. A separate human workflow must adjudicate evidence, correct proposals and document approval before dataset use. No LLM API, prompt execution or autonomous remediation is included.

## Next engineering steps

Add full upstream scanner adapters and schema validation, authenticated multi-user review, signed evidence manifests, a relational dependency graph, policy configuration and independent SME evaluation. These are future work, not implemented features.
