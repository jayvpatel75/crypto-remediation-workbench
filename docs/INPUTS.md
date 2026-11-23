# Input contract

## Normalized observations

```json
{
  "format": "workbench.scan.v1",
  "assets": [{
    "app": "payments-api",
    "ref": "edge-termination",
    "kind": "tls",
    "observed": {"versions": ["TLSv1.2"]},
    "context": {
      "owner": "Platform",
      "criticality": "high",
      "internet_exposed": true,
      "supports_tls13": false,
      "load_balancer": "Legacy appliance"
    }
  }]
}
```

Required observed fields:

| Kind | Fields |
|---|---|
| tls | `versions`: nonempty list of SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2 or TLSv1.3 |
| cipher | `algorithm`, `mode`: strings; `bits`: integer |
| ssh | `host_key_algorithm`, `signature_algorithm`: strings |
| secret | `type`, `location`: strings; do not include secret values |
| ipsec | `version`, `encryption`: strings; `dh_group`: integer |
| public-key | `algorithm`, `purpose`: strings; use `key-establishment` or `signature` for purpose |

Context accepts strings for owner, criticality, load_balancer and vendor; booleans for internet_exposed, supports_tls13, iot and requires_aes256; and a nonnegative integer for retention_years. Unknown context and observation fields are dropped. These adapters validate types and selected enums, not every cryptographic parameter or semantic combination.

## CycloneDX subset

Root must identify CycloneDX version 1.6 or 1.7. Application name is taken from metadata.component.name. Components are traversed recursively. A cryptographic-asset with cryptoProperties.protocolProperties.type `tls` and version `1.2` becomes one observed TLS version. This does not assert complete protocol enumeration.

For richer observations, supply namespaced string properties:

- `workbench:kind`: one normalized observation kind.
- `workbench:observed`: a JSON string matching the fields above.
- `workbench:context`: optional JSON context string.

These extension properties take precedence over native TLS extraction. Components require a nonempty bom-ref when ingested. Standard cryptographic assets outside this subset are ignored; when no observations can be extracted the CLI emits a warning. No claim of general SBOM/CBOM interoperability or complete schema validation is made.

Use metadata-only scanner exports. Even a location or owner field can contain sensitive information: sanitize all metadata before distribution. Dropping a secret-value field does not sanitize secrets accidentally placed in another supported string field.
