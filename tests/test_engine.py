import json
from pathlib import Path
import tempfile
import unittest

from cryptoworkbench.cli import build, main
from cryptoworkbench.engine import Asset, analyze, load


def asset(kind, observed, **context):
    return Asset("test-app", "endpoint-1", kind, observed, context, "fixture.json", "/assets/0", "0" * 64)


class Rules(unittest.TestCase):
    def rules(self, a):
        return {f["rule"] for f in analyze([a])}

    def test_modern_tls_is_clean(self):
        self.assertEqual(self.rules(asset("tls", {"versions": ["TLSv1.3"]})), set())

    def test_legacy_tls_and_migration_are_distinct(self):
        self.assertEqual(self.rules(asset("tls", {"versions": ["TLSv1.0", "TLSv1.2"]})), {"TLS-001", "TLS-002"})

    def test_tls12_migration_is_not_vulnerability(self):
        f = analyze([asset("tls", {"versions": ["TLSv1.2"]})])[0]
        self.assertEqual(f["classification"], "migration")

    def test_aes128_not_automatically_weak(self):
        self.assertFalse(analyze([asset("cipher", {"algorithm": "AES", "bits": 128, "mode": "GCM"})]))

    def test_aes256_policy(self):
        self.assertEqual(self.rules(asset("cipher", {"algorithm": "AES", "bits": 128, "mode": "GCM"}, requires_aes256=True)), {"ENC-002"})

    def test_ecb(self):
        self.assertEqual(self.rules(asset("cipher", {"algorithm": "AES", "bits": 256, "mode": "ECB"})), {"ENC-001"})

    def test_rsa_key_with_sha2_is_accepted(self):
        self.assertFalse(analyze([asset("ssh", {"host_key_algorithm": "ssh-rsa", "signature_algorithm": "rsa-sha2-512"})]))

    def test_sha1_signature_is_flagged(self):
        self.assertEqual(self.rules(asset("ssh", {"host_key_algorithm": "ssh-rsa", "signature_algorithm": "ssh-rsa"})), {"SSH-001"})

    def test_secret_manager_and_kms_plans_differ(self):
        key = analyze([asset("secret", {"type": "private_key", "location": "test.py:1"})])[0]
        token = analyze([asset("secret", {"type": "api_token", "location": "test.py:1"})])[0]
        self.assertIn("KMS/HSM", " ".join(key["plan"]))
        self.assertIn("secret manager", " ".join(token["plan"]))

    def test_infrastructure_blocker_is_preserved(self):
        f = analyze([asset("tls", {"versions": ["TLSv1.2"]}, supports_tls13=False, load_balancer="appliance", iot=True)])[0]
        self.assertEqual(len(f["constraints"]), 3)

    def test_pqc_long_lived_key_establishment_prioritized(self):
        f = analyze([asset("public-key", {"algorithm": "RSA", "purpose": "key-establishment"}, retention_years=15)])[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["classification"], "migration")

    def test_ipsec_proposal(self):
        self.assertEqual(self.rules(asset("ipsec", {"version": "IKEv1", "encryption": "3DES", "dh_group": 2})), {"VPN-001"})

    def test_duplicate_findings_collapsed_and_ids_stable(self):
        a = asset("tls", {"versions": ["TLSv1.0"]})
        self.assertEqual(analyze([a, a]), analyze([a]))


class Ingestion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, obj):
        p = self.root / "input.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def scan(self, kind="tls", observed=None, **kw):
        return {"format": "workbench.scan.v1", "assets": [{"app": "app", "ref": "ref", "kind": kind,
            "observed": observed if observed is not None else {"versions": ["TLSv1.0"]}, **kw}]}

    def test_secret_values_excluded_from_all_outputs(self):
        p = self.write(self.scan("secret", {"type": "api_token", "location": "test.py:1", "value": "DO-NOT-EXPORT", "snippet": "DO-NOT-EXPORT"}))
        out = self.root / "out"
        build([p], out)
        for file in out.iterdir():
            self.assertNotIn("DO-NOT-EXPORT", file.read_text(encoding="utf-8"))

    def test_invalid_tls_does_not_silently_pass(self):
        for obs in ({"versions": []}, {"versions": ["TLSv9"]}, {"versions": "TLSv1.0"}):
            with self.subTest(obs=obs), self.assertRaises(ValueError):
                load(self.write(self.scan(observed=obs)))

    def test_boolean_strings_rejected(self):
        with self.assertRaises(ValueError):
            load(self.write(self.scan(context={"supports_tls13": "false"})))

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            load(self.write({"scan": []}))

    def test_nested_cbom_and_json_pointer(self):
        p = self.write({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "application", "components": [
            {"type": "cryptographic-asset", "bom-ref": "tls", "properties": [
                {"name": "workbench:kind", "value": "tls"},
                {"name": "workbench:observed", "value": '{"versions":["TLSv1.0"]}'}]}]}]})
        self.assertEqual(load(p)[0].pointer, "/components/0/components/0")

    def test_plain_sbom_warns_instead_of_claiming_clean(self):
        p = self.write({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "openssl"}]})
        self.assertTrue(build([p], self.root / "out")["warnings"])

    def test_native_cbom_tls_without_extensions(self):
        p = self.write({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [
            {"type": "cryptographic-asset", "bom-ref": "edge", "cryptoProperties": {
                "assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.2"}}}]})
        self.assertEqual(load(p)[0].observed, {"versions": ["TLSv1.2"]})

    def test_html_script_breakout_escaped(self):
        data = self.scan()
        data["assets"][0]["app"] = "</script><script>alert(1)</script>"
        build([self.write(data)], self.root / "out")
        html = (self.root / "out/index.html").read_text(encoding="utf-8")
        self.assertNotIn("</script><script>alert(1)", html)
        self.assertIn("\\u003c/script", html)

    def test_export_labels_not_training_approved(self):
        build([self.write(self.scan())], self.root / "out")
        row = json.loads((self.root / "out/handoff.jsonl").read_text())
        self.assertFalse(row["eligible_for_training"])
        self.assertEqual(row["review_status"], "unreviewed")

    def test_cli_reports_input_error(self):
        self.assertEqual(main(["analyze", str(self.root / "missing.json")]), 2)


if __name__ == "__main__":
    unittest.main()
