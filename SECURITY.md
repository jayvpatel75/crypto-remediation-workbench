# Security and data handling

This is local demonstration software, not a hardened enterprise service. Use the provided fictional inputs for public demonstrations.

- The application performs no outbound calls, network scans or remediation actions.
- Input parsing excludes raw secret fields and snippets. Supported metadata strings are not guaranteed secret-free. Sanitize metadata before use.
- Never commit production inputs, keys, private scan data or identifying infrastructure details. `private-inputs/` is ignored but ignore rules are not a data loss prevention system.
- Reports and AI handoffs contain metadata and evidence filenames/hashes. Store them with appropriate filesystem access controls; they are not encrypted by the application.
- The optional static server binds to 127.0.0.1. Do not expose it as a multi-user production service.
- Finding source hashes establish reproducibility, not authenticity or authorization.
- All remediation plans and AI labels require human review. No automatic training approval is implemented.
- File size is checked before reading and reads are bounded to 10 MB plus one sentinel byte. There are no deep nesting/record-count limits; use trusted, bounded inputs only.

For a security issue in this demonstration, avoid posting real credentials or private evidence in public issues. Provide a minimal synthetic reproduction.
