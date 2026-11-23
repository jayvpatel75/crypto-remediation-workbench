"""Strict adapters, explainable rules, and constrained remediation planning."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

POLICY_VERSION = "2026.11-demo-1"
SOURCES = {
    "tls": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    "ssh": "https://www.openssh.com/txt/release-8.8",
    "pqc": "https://csrc.nist.gov/pubs/fips/203/final",
    "keys": "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
    "ipsec": "https://www.rfc-editor.org/rfc/rfc8247",
}
KINDS = {"tls", "cipher", "ssh", "secret", "ipsec", "public-key"}


@dataclass(frozen=True)
class Asset:
    app: str
    ref: str
    kind: str
    observed: dict
    context: dict
    source: str
    pointer: str
    source_sha256: str


def validate(asset: Asset) -> Asset:
    if asset.kind not in KINDS:
        raise ValueError(f"Unsupported asset kind: {asset.kind}")
    if not isinstance(asset.app, str) or not isinstance(asset.ref, str) or not asset.app or not asset.ref:
        raise ValueError("app and ref must be nonempty")
    if not isinstance(asset.observed, dict) or not isinstance(asset.context, dict):
        raise ValueError("observed and context must be objects")
    fields = {
        "tls": {"versions": list}, "cipher": {"algorithm": str, "mode": str, "bits": int},
        "ssh": {"host_key_algorithm": str, "signature_algorithm": str},
        "secret": {"type": str, "location": str},
        "ipsec": {"version": str, "encryption": str, "dh_group": int},
        "public-key": {"algorithm": str, "purpose": str},
    }
    for name, expected in fields[asset.kind].items():
        value = asset.observed.get(name)
        if type(value) is not expected:
            raise ValueError(f"{asset.ref}: observed.{name} must be {expected.__name__}")
    if asset.kind == "tls" and (not asset.observed["versions"] or any(
        v not in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
        for v in asset.observed["versions"]
    )):
        raise ValueError(f"{asset.ref}: invalid or empty TLS versions")
    for key in ("internet_exposed", "supports_tls13", "iot", "requires_aes256"):
        if key in asset.context and type(asset.context[key]) is not bool:
            raise ValueError(f"{asset.ref}: context.{key} must be boolean")
    if "retention_years" in asset.context and (
        type(asset.context["retention_years"]) is not int or asset.context["retention_years"] < 0
    ):
        raise ValueError("retention_years must be a nonnegative integer")
    for key in ("owner", "load_balancer", "vendor", "criticality"):
        if key in asset.context and type(asset.context[key]) is not str:
            raise ValueError(f"context.{key} must be a string")
    return asset


def safe_observation(kind: str, observed: dict) -> dict:
    """Allowlist typed facts; secret bytes and arbitrary scanner fields never leave ingestion."""
    allowed = {
        "tls": ("versions",), "cipher": ("algorithm", "mode", "bits"),
        "ssh": ("host_key_algorithm", "signature_algorithm"),
        "secret": ("type", "location"), "ipsec": ("version", "encryption", "dh_group"),
        "public-key": ("algorithm", "purpose"),
    }
    if kind not in allowed:
        raise ValueError(f"Unsupported asset kind: {kind}")
    return {k: observed[k] for k in allowed[kind] if k in observed}


def load(path: Path) -> list[Asset]:
    if path.stat().st_size > 10_000_000:
        raise ValueError("Input exceeds 10 MB limit")
    with path.open("rb") as handle:
        raw = handle.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError("Input exceeds 10 MB limit")
    data = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assets = []
    if not isinstance(data, dict):
        raise ValueError("Input root must be an object")
    if data.get("format") == "workbench.scan.v1":
        records = data.get("assets")
        if not isinstance(records, list):
            raise ValueError("assets must be an array")
        for i, row in enumerate(records):
            if not isinstance(row, dict):
                raise ValueError("Each asset must be an object")
            kind = row.get("kind")
            obs = row.get("observed", {})
            if not isinstance(obs, dict):
                raise ValueError("observed must be an object")
            assets.append(validate(Asset(row.get("app", ""), row.get("ref", ""), kind,
                safe_observation(kind, obs), row.get("context", {}), path.name,
                f"/assets/{i}", digest)))
    elif data.get("bomFormat") == "CycloneDX" and data.get("specVersion") in {"1.6", "1.7"}:
        # Explicit narrow adapter. Software-only components are inventory, not scan findings.
        app = data.get("metadata", {}).get("component", {}).get("name", path.stem)
        def walk(components, pointer):
            for i, component in enumerate(components):
                p = f"{pointer}/{i}"
                if component.get("type") == "cryptographic-asset":
                    props = {x["name"]: x["value"] for x in component.get("properties", [])}
                    kind = props.get("workbench:kind")
                    native = component.get("cryptoProperties", {}).get("protocolProperties", {})
                    if not kind and native.get("type") == "tls":
                        version = native.get("version", "")
                        obs = {"versions": ["TLSv" + version]}
                        assets.append(validate(Asset(app, component.get("bom-ref", ""), "tls",
                            obs, {}, path.name, p, digest)))
                    if kind:
                        obs = json.loads(props.get("workbench:observed", "{}"))
                        context = json.loads(props.get("workbench:context", "{}"))
                        assets.append(validate(Asset(app, component.get("bom-ref", ""), kind,
                            safe_observation(kind, obs), context, path.name, p, digest)))
                walk(component.get("components", []), p + "/components")
        walk(data.get("components", []), "/components")
    else:
        raise ValueError("Expected workbench.scan.v1 or CycloneDX 1.6/1.7 JSON")
    # Keep context allowlisted; arbitrary imported fields are not AI instructions.
    allowed = {"owner", "internet_exposed", "supports_tls13", "iot", "load_balancer",
               "requires_aes256", "retention_years", "vendor", "criticality"}
    return [Asset(a.app, a.ref, a.kind, a.observed,
                  {k: v for k, v in a.context.items() if k in allowed},
                  a.source, a.pointer, a.source_sha256) for a in assets]


def analyze(assets: list[Asset]) -> list[dict]:
    findings = []
    seen = set()
    for a in assets:
        o, c = a.observed, a.context
        def add(rule, severity, title, rationale, action, reference, classification="weakness"):
            key = (a.app, a.ref, rule, json.dumps(o, sort_keys=True))
            if key in seen:
                return
            seen.add(key)
            constraints = []
            if c.get("supports_tls13") is False and a.kind == "tls":
                constraints.append("Termination device cannot support TLS 1.3: assess firmware or replacement before migration.")
            if c.get("load_balancer") and a.kind == "tls":
                constraints.append("Validate client-to-load-balancer and load-balancer-to-backend hops separately.")
            if c.get("iot"):
                constraints.append("Benchmark memory, handshake size, CPU and legacy peer compatibility on device hardware.")
            missing = [x for x in ("owner", "criticality") if x not in c]
            score = {"critical": 85, "high": 65, "medium": 40, "low": 20}[severity]
            score += 10 if c.get("internet_exposed") else 0
            score += 5 if c.get("criticality") == "high" else 0
            plan = ["Confirm finding with the application owner and current runtime configuration.",
                    *constraints, action,
                    "Canary the change; verify intended negotiation and application integration tests.",
                    "Retain a tested configuration rollback; require time-limited approval for any insecure exception."]
            identity = json.dumps([a.app, a.ref, rule, o], sort_keys=True)
            findings.append({"id": hashlib.sha256(identity.encode()).hexdigest()[:16],
                "app": a.app, "asset": a.ref, "kind": a.kind, "rule": rule,
                "severity": severity, "priority_score": min(score, 100),
                "classification": classification, "title": title, "rationale": rationale,
                "observed": o, "owner": c.get("owner", "Unassigned"),
                "constraints": constraints, "missing_context": missing,
                "confidence": "medium" if missing else "high", "plan": plan,
                "reference": SOURCES[reference], "policy_version": POLICY_VERSION,
                "evidence": {"source": a.source, "pointer": a.pointer, "sha256": a.source_sha256},
                "review_status": "unreviewed", "review_required": True})
        if a.kind == "tls":
            old = set(o["versions"]) & {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
            if old:
                add("TLS-001", "high", "Deprecated protocol enabled",
                    "Observed legacy protocol support increases negotiation risk.",
                    "Disable SSL/TLS 1.0/1.1 after peer discovery; enable TLS 1.3 where supported.", "tls")
            if "TLSv1.2" in o["versions"] and "TLSv1.3" not in o["versions"]:
                add("TLS-002", "medium", "TLS 1.3 migration candidate",
                    "TLS 1.2 alone is not proof of a vulnerability; cipher and policy review are required.",
                    "Inventory clients and termination devices; pilot TLS 1.3 and document TLS 1.2 exceptions.", "tls", "migration")
        elif a.kind == "cipher":
            if o["algorithm"].upper() in {"DES", "3DES", "RC4"} or o["mode"].upper() == "ECB":
                add("ENC-001", "high", "Legacy or unsafe encryption configuration",
                    "Observed algorithm or mode does not meet the demonstration encryption baseline.",
                    "Use vetted AEAD such as AES-GCM; manage unique nonces and authenticated metadata through a supported library.", "keys")
            elif c.get("requires_aes256") and (o["algorithm"].upper(), o["bits"], o["mode"].upper()) != ("AES", 256, "GCM"):
                add("ENC-002", "medium", "Organization AES-256-GCM policy deviation",
                    "This is a local policy requirement; AES-128 is not inherently broken.",
                    "Validate the policy scope and platform support; migrate to AES-256-GCM with nonce-safe APIs.", "keys", "policy")
        elif a.kind == "ssh":
            if o["host_key_algorithm"] == "ssh-dss" or o["signature_algorithm"] == "ssh-rsa":
                add("SSH-001", "high", "Deprecated SSH signature algorithm",
                    "ssh-rsa denotes RSA/SHA-1 signatures; an RSA key can instead support RSA/SHA-2 signatures.",
                    "Disable DSA and RSA/SHA-1 signatures; pilot RSA/SHA-2 or approved alternative host keys and update known_hosts safely.", "ssh")
        elif a.kind == "secret":
            if o["type"] in {"private_key", "api_token", "password", "symmetric_key"}:
                key_material = o["type"] in {"private_key", "symmetric_key"}
                action = ("Rotate exposed key material; assess non-exportable KMS/HSM operations, envelope encryption and least-privilege identity access."
                          if key_material else "Revoke and rotate the credential; move retrieval to a secret manager using workload identity and least privilege.")
                add("KEY-001", "critical", "Potential plaintext secret in source",
                    "Scanner metadata suggests exposed material; validate privately without logging its value.", action, "keys")
        elif a.kind == "ipsec":
            if o["version"] != "IKEv2" or o["encryption"] in {"DES", "3DES"} or o["dh_group"] in {1, 2, 5}:
                add("VPN-001", "high", "IPsec proposal requires hardening",
                    "Observed IKE version, encryption or DH group violates the demonstration baseline.",
                    "Coordinate both VPN peers; pilot IKEv2 with approved AEAD proposals and suitable DH groups; verify rekey, PFS, MTU and failover.", "ipsec")
        elif a.kind == "public-key" and o["algorithm"].upper() in {"RSA", "ECDH", "ECDSA", "DSA"}:
            long_lived = c.get("retention_years", 0) >= 10
            add("PQC-001", "high" if long_lived and o["purpose"] == "key-establishment" else "medium",
                "Quantum-vulnerable public-key dependency",
                "Migration planning depends on cryptographic purpose, data lifetime, protocol integration and vendor support; this is not an immediate classical break.",
                "Map dependencies and vendor support; assess ML-KEM for key establishment or standardized PQC signatures for signing. Benchmark supported protocol integrations before rollout.",
                "pqc", "migration")
    return sorted(findings, key=lambda f: (-f["priority_score"], f["id"]))


def inventory(assets: list[Asset]) -> list[dict]:
    return [asdict(a) for a in assets]
