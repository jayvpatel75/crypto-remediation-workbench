"""Generate deterministic fictional data; never scan a real network or repository."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    records = []
    names = ["payments", "claims", "patient-portal", "warehouse-iot", "vpn-edge", "identity"]
    for i in range(24):
        app = f"{names[i % len(names)]}-{i + 1:02d}"
        context = {"owner": ["Platform", "Payments", "Operations"][i % 3],
                   "criticality": "high" if i % 3 == 0 else "medium",
                   "internet_exposed": i % 2 == 0, "iot": i % 6 == 3,
                   "supports_tls13": i % 4 != 0, "load_balancer": "Legacy-LB" if i % 4 == 0 else "Software proxy",
                   "retention_years": 15 if i % 3 == 0 else 2}
        observations = [
            ("tls", {"versions": ["TLSv1.0", "TLSv1.2"] if i % 4 == 0 else ["TLSv1.2"] if i % 4 == 1 else ["TLSv1.2", "TLSv1.3"]}),
            ("cipher", {"algorithm": "AES", "bits": 128 if i % 2 == 0 else 256, "mode": "ECB" if i % 5 == 0 else "GCM"}),
            ("ssh", {"host_key_algorithm": "ssh-rsa", "signature_algorithm": "ssh-rsa" if i % 4 == 0 else "rsa-sha2-512"}),
            ("public-key", {"algorithm": "RSA" if i % 2 == 0 else "ECDSA", "purpose": "key-establishment" if i % 2 == 0 else "signature"}),
        ]
        if i % 6 == 0:
            observations.append(("secret", {"type": "private_key", "location": "src/config.py:12", "value": "SYNTHETIC-NOT-A-REAL-KEY"}))
        if i % 6 == 4:
            observations.append(("ipsec", {"version": "IKEv1", "encryption": "3DES", "dh_group": 2}))
        for j, (kind, observed) in enumerate(observations):
            records.append({"app": app, "ref": f"{app}/{kind}/{j}", "kind": kind, "observed": observed,
                            "context": {**context, "requires_aes256": i % 3 == 0}})
    out = ROOT / "examples"
    out.mkdir(exist_ok=True)
    (out / "enterprise.scan.json").write_text(json.dumps({"format": "workbench.scan.v1", "synthetic": True, "assets": records}, indent=2) + "\n", encoding="utf-8")
    cbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "partner-gateway"}},
            "components": [{"type": "cryptographic-asset", "name": "TLS endpoint", "bom-ref": "partner-tls",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.2"}},
                "properties": [{"name": "workbench:kind", "value": "tls"},
                               {"name": "workbench:observed", "value": json.dumps({"versions": ["TLSv1.2"]})},
                               {"name": "workbench:context", "value": json.dumps({"owner": "Partners", "criticality": "high", "supports_tls13": False, "load_balancer": "Appliance"})}]}]}
    (out / "partner.cdx.json").write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(records)} observations across 24 fictional applications + 1 CBOM application")


if __name__ == "__main__":
    main()
