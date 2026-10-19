# Prompt: build Pengent Web GT (L1 + L2) for the next application

Open a Claude Code session at the repo root, fill in the `{...}` placeholders, and paste everything below the line.

---

Build the Pengent-compatible ground truth for **{APP_NAME}**, following `Traditional_Web_GT_Annotation_Guide.md`, `00_STUDENT_INSTRUCTIONS.md`, `REVIEW_CHECKLIST.md`, and the four templates. This is authorized ground-truth annotation for a research benchmark. Do not add, remove, or rename schema fields; anything the schema cannot represent goes in `annotation_issues.yaml` with evidence.

**Inputs**
- Server source: `{SERVER_SOURCE_DIR}`
- Frontend source (if separate): `{FRONTEND_SOURCE_DIR}`
- Deployed target: `{BASE_URL}` (image `{IMAGE}`), authorized for testing including state-changing requests
- Accounts: `{ACCOUNTS}` (store references only, never plaintext secrets)
- Captures: `{HAR_FILES}`
- Output: `{OUTPUT_DIR}/` (environment.yaml, l1_gt.yaml, l2_gt.yaml, annotation_issues.yaml, pengent_export.json)

**Working method**
- Source first, then runtime: enumerate from source, then verify against the deployed target and captures and fill gaps.
- Generate the YAML from Python generator scripts (operation tables + L2 specs as data), not by hand. Copy the generators into `{OUTPUT_DIR}/generators/` with a README giving run order. The scratchpad is temporary; the generators must persist.
- Pin exact versions/digests. Run Python with `PYTHONIOENCODING=utf-8`; `pip install pyyaml`.
- Report only what was checked and how. Mark inferred items with lower confidence and list them in `annotation_issues.yaml`. Do not claim completeness you did not verify.

## L1 — endpoint inventory

One node per normalized route (`origin + path template`, query values do not create nodes); each HTTP method is a separate `io_variant`.

1. Enumerate API routes from the server's route/handler definitions: method, path, request/response field shapes, declared auth, status codes.
2. Add routes the source lacks from the frontend's API-call definitions, then reconcile against the deployed app's own API description if it serves one (e.g. an OpenAPI/spec endpoint) — that is the authoritative route list for the running build. Save that description into `{OUTPUT_DIR}/` as evidence.
3. Add non-API routes (SPA entry, health/metrics, docs, static assets) from the server's mount code and the frontend's public tree.
4. For each business field, record a semantic decision: which resource it denotes and whether it is a stable reference to an object. `reference_capable` only for stable identifiers/locators.
5. Attach runtime evidence from the captures: match every captured request to a node (none should be unmatched); fill identity-scoped statuses and redacted samples; set `route_confirmed` only for nodes actually exercised.
6. Visibility is the minimum access to identify the item, independent of the evidence source. If the deployment serves its own API docs/spec unauthenticated and the black-box profile grants API docs, discovering a route that way is black-box, not white-box.

L1 is complete for the routes the API wrapper registers (it matches the wrapper's own output); non-wrapper routes are only as complete as source + frontend + captures reveal; behavior/authorization is reconstructed, not guaranteed.

## L2 — business actions `<Subject, Operation, Object, Req, Eff>`

1. For every L1 endpoint+method with an IO contract, read the handler and decide the business operation(s). Split one endpoint into multiple actions by three rules — apply them to every handler, ideally found by scanning for `is_admin`/owner/sender checks and branches on request fields:
   - one action per permission context the handler accepts (owner, admin, sender, member, anonymous);
   - one action per request field/branch that changes which facts are required or produced (discriminators like `type`, `action`, visibility flags, `status`);
   - one action per mode with different effects (set vs. clear, enable vs. disable).
2. Write each action independently: Subject (semantic role, not a concrete account); Operation (business verb + Create/Read/Update/Delete); Object (entity/state/relation); Req (facts that must hold first); Eff (`gen`/`kill` facts). Use only the six predicates `Exists, Know, State, Relation, Can, Authenticated`. New content/credentials are object attributes, not `Know` requirements. Delete/Update represent the resulting state (watch append-only models where a mutation is really a new record). Ensure any `Req` fact is produced by some action's `Eff` so the dependency graph can form.
3. Expand each spec to a full node with a script: declare every entity/principal named in the facts; account for every request/response field (link to a Req/Eff fact, or mark payload/observed-only with a reason); bind to the L1 key with a selector when the endpoint was split; copy visibility/reachability/evidence from L1.
4. Reachability: annotate against the application's intended configuration. A feature toggled off by config that an in-scope admin endpoint can enable is reachable, with the enabling step as a stated precondition; mark actions that also need un-mintable external infrastructure (real IdP, SMTP, external service) with an explicit `EXTERNAL DEPENDENCY:` precondition. Keep visibility and reachability separate.
5. Do not write L2 edges — Pengent derives them by matching produced fact keys to required ones (and `kill` as invalidation).

## Validate and finish

- Script-check: every L1 candidate (api + non-empty io_variants) is bound to ≥1 action; no duplicate action keys; every captured request matched a node.
- Run `validate_gt.py` and `export_to_pengent.py`; fix until both pass.
- For each `annotation_issues` entry, sweep the source for other occurrences of the same pattern (no-auth handlers, append-only mutations, path-vs-query binding, version drift) and record whether the set is exhaustive.
- State the residual gaps honestly: fraction of nodes runtime-confirmed, operations whose behavior is inferred (no matching source), and any endpoints you judged may be under-split.

## Known limits to carry forward

- Coverage (≥1 action per endpoint) is machine-checked; completeness of the operation list is your judgment and the checks cannot detect under-splitting.
- If the deployed binary is a newer version than the supplied source, source describes the interface but not the behavior of the added routes; confirm against the live spec and flag them.
