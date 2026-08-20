# TDS GA7 — CI/CD Container Release Gate

Deterministic policy endpoint: `POST /release-gate`

Returns `{ "decision": "promote" | "block", "violations": [...] }`.
