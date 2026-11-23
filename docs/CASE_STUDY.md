# Enterprise cryptographic remediation case study

## Problem and result

Security analysts need to translate inconsistent cryptographic evidence into migration requirements that engineers can implement and reviewers can verify. A blanket algorithm replacement ignores where encryption terminates, which peers must interoperate and whether hardware can support the target configuration.

This portfolio implements a reproducible pipeline from JSON observations and a CycloneDX subset to ranked findings, infrastructure-aware plans and review-gated AI engineering records. The supplied data models 25 fictional applications; no proprietary evidence is used.

## Scenario 1 Legacy load balancer

The payments service has TLS 1.0/1.2 at an appliance that does not support TLS 1.3. The engine produces both a deprecated-protocol finding and a migration candidate. The plan explicitly requires a firmware or replacement assessment and separate checks of frontend/backend TLS hops. Verification must include legacy client discovery, negotiation tests and rollback planning.

## Scenario 2 Exposed key material

A scanner reports a synthetic private-key location in source. The engine preserves location metadata while excluding the secret value. It recommends rotation followed by assessing KMS/HSM operations, envelope encryption and workload identity. API tokens receive a different plan using a secret manager. The system does not assume that storing a compromised key in KMS removes its exposure.

## Scenario 3 Long-lived confidential data

An application uses RSA for key establishment and retains data for 15 years. It receives higher migration priority than a short-lived signature dependency. The plan identifies algorithm purpose, vendor dependencies and benchmarking before a supported PQC transition. Constrained IoT systems also require CPU, memory and handshake-size checks.

## Evidence for a hiring reviewer

- The code separates facts, policy judgments and remediation proposals.
- Negative controls prevent common errors about AES-128 and RSA SSH keys.
- Each finding includes a source pointer, source hash, rule version and confidence rationale.
- The small evaluation suite is explicitly synthetic and unreviewed by an independent SME.
- No production outcomes, enterprise deployment or invented efficiency savings are claimed.

## Five minute walkthrough

1. Open the offline demo and search `payments-01`.
2. Select the TLS finding and inspect the appliance blocker and evidence pointer.
3. Filter by policy to see the scoped AES-256-GCM requirement.
4. Search `KEY-001` and inspect the key rotation/KMS plan.
5. Open demo/handoff.jsonl to see the unreviewed AI handoff contract.
