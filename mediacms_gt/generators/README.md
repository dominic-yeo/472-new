# MediaCMS GT generators

Deterministic pipeline that produces `mediacms_gt/l1_gt.yaml` and `l2_gt.yaml` from fixed inputs
(the MediaCMS 9.2.1 source tree, the live Django URL-resolver dump, and identity-scoped runtime probes).
Re-running against the same inputs yields byte-identical YAML. `environment.yaml` and
`annotation_issues.yaml` are authored by hand (not generated).

## Inputs (all under the repo / deliverable)
- `mediacms/` — MediaCMS 9.2.1 source (commit 874e687); handlers in `files/`, `users/`,
  `migrationservice/`, `uploader/`, `lti/`.
- `mediacms_gt/url_dump.txt` — authoritative mounted-route list from the running container
  (produced by `dump_urls.py`; see below). Used because the deployment's own `/swagger.json`
  crashes (annotation_issues issue-001).
- `mediacms_gt/runtime_probe.txt` — identity-scoped (anonymous/user/admin) status probes against
  the live deployment at http://localhost.

## Run order
```
# (one-time, inside the running web container) regenerate the route list:
docker cp dump_urls.py mediacms-web-1:/tmp/dumpurls.py
docker exec mediacms-web-1 bash -c 'cd /home/mediacms.io/mediacms && \
    python manage.py shell -c "exec(open(\"/tmp/dumpurls.py\").read())"' > ../url_dump.txt

# build the GT (run with PYTHONIOENCODING=utf-8; needs: pip install pyyaml):
python build_l1.py     # -> ../l1_gt.yaml  (prints node/candidate/edge counts; fails on dup keys)
python build_l2.py     # -> ../l2_gt.yaml  (coverage check: every api+io_variants L1 node is bound)
python lint_l2.py      # fact-variable declaration + dependency-graph reconciliation (must be 0/0)

# then from the repo root:
python validate_gt.py --l1 mediacms_gt/l1_gt.yaml --l2 mediacms_gt/l2_gt.yaml
python export_to_pengent.py --l1 mediacms_gt/l1_gt.yaml --l2 mediacms_gt/l2_gt.yaml \
    --out mediacms_gt/pengent_export.json
```

## Modules
| file | role |
|---|---|
| `common.py` | ORIGIN/key helpers; the `SEM` raw_field→resource vocabulary (single source of fact-type consistency); L1 node/variant/request/response builders (derive inputs/outputs/semantic_inputs/outputs); L2 typed-term + fact builders; `fact_key()` (byte-for-byte copy of validate_gt.py so io_accounting always matches Req/Eff). |
| `l1_data.py` | The L1 endpoint inventory as data: `API_NODES` (52 L2 candidates), `PAGE_NODES` (pages/auth/docs), `EDGES`. |
| `build_l1.py` | Assembles L1, checks duplicate keys, writes `l1_gt.yaml` with `excluded_items`. |
| `l2lib.py` | L2 action assembler: compact cores → full Pengent nodes; `_auto_declare` adds every fact variable to Object.participants (guide 3.7); derives consumes/produces/l1_keys. |
| `l2_data.py` | 104 action cores (one business action each), split by permission context and by request discriminators via `l1_bindings[].selector`. |
| `build_l2.py` | Expands cores → L2 nodes; coverage check (every candidate bound); writes `l2_gt.yaml`. |
| `lint_l2.py` | (A) every fact variable declared; (B) every consumed fact is produced by some Eff or is an approved ROOT (`Can(...)`, base `Authenticated`, the login password the caller brings). Current status: 0 undeclared, 0 drift. |
| `dump_urls.py` | Run inside the container to emit the authoritative mounted-route list (`url_dump.txt`). |

## Current status
L1 = 110 nodes (52 api candidates + 58 page). L2 = 104 actions; all 52 candidates covered.
validate_gt.py, export_to_pengent.py and lint_l2.py all pass.
