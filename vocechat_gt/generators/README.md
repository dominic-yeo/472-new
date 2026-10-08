# VoceChat GT generators

Deterministic pipeline that produces `vocechat_gt/l1_gt.yaml` and `l2_gt.yaml` from fixed inputs
(server source, frontend services, the live `/api/spec`, and the two HAR captures). Re-running against the
same inputs yields byte-identical YAML.

## Inputs (all under the repo / deliverable)
- `vocechat_src/vocechat-server-rust-0.5.36/` — server handlers (Cargo 0.3.3; see annotation_issues issue-001)
- `vocechat_src/vocechat-web/` — frontend 0.9.122 service definitions
- `vocechat_gt/openapi_spec_0.5.36.json` — live `GET /api/spec` snapshot (authoritative enumeration)
- `vocechat_gt/auth.har`, `vocechat_gt/localhost.har` — runtime verification

## Run order
```
python har_dump.py har_entries.json   # parse both HARs -> har_entries.json (intermediate)
python build_l1.py                    # -> l1_build.json  (prints node/candidate/edge counts; unmatched HAR must be [])
python build_l2.py                    # -> l2_build.json  (coverage check + gated by lint_l2)
python emit.py                        # writes l1_gt.yaml + l2_gt.yaml into ../ (vocechat_gt/)
# then, from the repo root:
python validate_gt.py --l1 vocechat_gt/l1_gt.yaml --l2 vocechat_gt/l2_gt.yaml
python export_to_pengent.py --l1 vocechat_gt/l1_gt.yaml --l2 vocechat_gt/l2_gt.yaml --out vocechat_gt/pengent_export.json
```
Run with `PYTHONIOENCODING=utf-8`. Paths in `common.py` are absolute to this checkout; adjust `ROOT` if moved.

## Modules
| file | role |
|---|---|
| `common.py` | source line-resolver + `SEM` raw_field→resource vocabulary (the single source of fact *type* consistency) |
| `ops_server.py` / `ops_frontend.py` / `ops_binary.py` | operation tables from server source / frontend / live spec |
| `reach_policy.py` | intended-configuration reachability overrides (issue-005) |
| `build_l1.py` | assembles L1; matches every HAR request to a node; attaches evidence/samples/identity_statuses |
| `l2lib.py` + `l2_spec*.py` | one hand-authored L2 core per business action (Subject/Operation/Object/Req/Eff/io-map) |
| `build_l2.py` | expands cores → L2 nodes; coverage check; **gated by `lint_l2`** |
| `lint_l2.py` | cross-action fact reconciliation (see below) |
| `emit.py` | serialises to YAML |

## lint_l2 — fact reconciliation (the cross-action guarantee)
L2 actions are authored independently, so a consumer's `Req` fact must either match some action's produced
`Eff.gen` fact, or be a declared ROOT. `lint_l2` matches on a CANONICAL key that drops per-action bookkeeping
(entity local-id and `{role}`, and a reference target's downstream role) while keeping load-bearing parts
(predicate, subject/principal `[relative_role]`, reference type, object type). It FAILS the build on any
consumed fact that is neither produced nor an approved root. Approved roots: `Can(...)` authorization axioms,
bot `Authenticated(APIToken)`, device existence/subscription (created by any login), and external inputs the
caller brings (OAuth code / id-token / wallet signature / magic token / third-party key / license blob /
custom-page name / Agora channel name / external URL). Current status: 28 matched, 17 roots, 0 drift.
