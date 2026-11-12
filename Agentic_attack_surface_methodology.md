# Agentic attack-surface methodology

Companion to `Agentic_attack_surface_schema.yaml`. This defines the repeatable
procedure for producing an agentic attack-surface Ground Truth (GT) for one app,
with the same discipline as the L1/L2 pipeline (static extraction from
version-pinned source → runtime grounding on a pinned image → validation →
export). The schema is the output contract; this is how you fill it.

The agentic layer sits **above** L1/L2 and reuses their IDs. It does not replace
them: a tool call is realized through an L1 interaction and participates in an L2
operation. Build L1 and L2 first.

---

## 0. Applicability gate (run this before anything else)

The agentic layer applies only to apps that have an **agent runtime**: a
model-invocation loop where the model's output selects a subsequent action
(a tool/function call, a delegation, or a decision to continue). Apply this test
to the pinned source:

- **Qualifies** if source contains (a) a loop that calls an LLM, (b) a tool/
  function registry presented to that model, and (c) a dispatch step that
  executes the model-chosen tool and feeds the result back into context.
  Examples in this workspace: `anything-llm` (`server/utils/agents/aibitat/`),
  `LibreChat` (`packages/api/src/agents/`), `open-webui`
  (`backend/open_webui/utils/{tool_calling,subagents,code_interpreter}.py`),
  `lobe-chat`, `openclaw`.
- **Does not qualify** — no agentic GT — if the app only calls an LLM for a
  single-shot completion with no tools and no action loop, or has no LLM at all
  (`directus`, `ghost`, `outline`, `keycloak`, `writefreely`). A chat UI that
  streams a model reply but never lets the model act is **not** agentic.

Record the verdict and the evidence (file + symbol) in `environment.yaml`. If the
app does not qualify, stop — do not emit an empty agentic GT.

Degenerate case: an app with a loop but zero tools (model can only talk) gets one
`agents` record and no `tool_bindings`; still worth capturing for its
context/memory/output lineage.

---

## 1. Inputs and prerequisites

Before starting, you must have:

1. **Version-pinned source** checked out at the same ref used for L1/L2 (the
   `*_gt/environment.yaml` version). Agentic wiring drifts fast between versions.
2. **L1 GT** (`l1_gt.yaml`) and **L2 GT** (`l2_gt.yaml`) built, so tool bindings
   and agents can reference real `l1_id`/`l2_id` values.
3. **The subject taxonomy** used by that app's L2 (e.g. Anonymous / User / Admin /
   Tenant-scoped). `writers[].principal` and `authority_context` must use the
   same subject names, not ad-hoc ones.
4. **A pinned runtime image** matching source (per the project's runtime tip:
   stamp only version-stable behavior; document divergence as an annotation
   issue). Needed for Phase E.

---

## 2. Pipeline overview

```
A. Locate      → find the agent runtime and its seven surfaces in source
B. Extract     → one pass per record set, source-confirmed, with stable IDs
C. Annotate    → trust_class + authority/identity + controls (the security pass)
D. Close       → verify data-lineage: every content item traces entry→carry→exit
E. Ground      → drive the agent on the pinned image; upgrade records to observed
F. Link        → wire related_l1_ids / related_l2_ids / l1_ids to existing GT
G. Validate    → validate_agentic.py (referential + lineage + enum checks)
H. Export      → map into the pengent export alongside L1/L2
```

Phases A–D are static (source-confirmed). E is runtime (observed). F–H are
mechanical. Produce the whole thing as `generators/` code that emits
`agentic_gt.yaml`, the same way `build_l1.py`/`build_l2.py` emit their YAML —
never hand-write the output file.

---

## 3. Phase A — Locate the agent runtime

Find these seven loci in source; each maps to one record set. Grep terms and the
real anchors seen in this workspace:

| Locus | What to find | Grep / anchors |
|---|---|---|
| **Orchestration loop** | the model-call + dispatch cycle | `aibitat/index.js` (anything-llm); `packages/api/src/agents/*` (LibreChat); `utils/middleware.py`, `tool_calling.py` (open-webui) |
| **Model-call site** | provider/model, how messages[] are built | provider wrappers; `handleStream` / completion calls |
| **Tool registry** | the tools/functions handed to the model | `aibitat/plugins/index.js` + `plugins/*` (anything-llm); `utils/tools.py`, `tool_search.py` (open-webui); MCP server configs |
| **Prompt assembly** | everything concatenated into context | system-prompt template, `plugins/chat-history.js`, RAG/similaritySearch, `utils/context_compaction.py` |
| **Memory/state** | cross-turn/cross-run stores | `plugins/memory.js` (anything-llm); `utils/memory.py` (open-webui); vector store + chat tables |
| **Output/egress** | where results leave | stream responder; `plugins/create-files/*`, `gmail/*`, `http-socket.js`; file writers |
| **Guardrails** | approvals, filters, permissions | `request-user-input.js`, `model-router-cooldown.js` (anything-llm); `tool_approval.py`, `tool_permissions.py`, `filter.py`, `sanitize.py`, `rate_limit.py` (open-webui) |

Write the file:symbol for each into a scratch map before extracting — it becomes
each record's `source_ref`.

---

## 4. Phase B — Extraction rules, per record set

One pass per record set, in this order (later sets reference earlier IDs). All
records are `evidence_status: source_confirmed` at this stage. Keep secrets out;
record config **location**, never values.

### 4.1 `agents` — one record per distinct agent role or deployable config
- Enumerate every registered agent/role and every sub-agent spawned as its own
  model context (e.g. anything-llm `sql-agent`, `section-agent`; LibreChat
  subagents). A loop that re-enters the *same* context is one agent; a spawned
  child context is a new agent record.
- Fill `invocation_surfaces` from the L1 entry points that start/resume it
  (chat endpoint, websocket, scheduled job, webhook) — reference real `l1_id`s.
- `instruction_sources` = the assembled system/developer prompt templates, with
  `writers` (use `[]` when hard-coded in source; name the principal + `l1_id`
  when an admin/user can edit it, e.g. a workspace system-prompt field).
- ID: `agent.<component>.<role>` (e.g. `agent.anythingllm.workspace`,
  `agent.anythingllm.sql_agent`).

### 4.2 `tool_bindings` — one record per tool exposed to an agent in a config
- One record per (agent, tool). The same tool offered to two agents = two
  bindings (authority/identity may differ).
- `tool_source`: `native` (in-process function), `mcp`, `api`, `plugin`,
  `code`. `server_or_provider` for MCP/API.
- `effect_class`: classify honestly — `code_execution` for interpreters/shell/
  SQL-query tools, `external_send` for mail/http, `financial`/`destructive`
  where apt. Set `execution_environment` (sandbox, network_egress,
  filesystem_scope, enforced_by) for every code-exec, fetch/URL, and shell tool
  — this is the SSRF / escape surface.
- `execution_identity`: the identity the tool acts as when it hits its backing
  service — the caller's session vs a shared service account vs an API key held
  by the server. This is the confused-deputy axis; get it right.
- `output_ids`: the context/memory/sink IDs that receive the tool result (set in
  4.3–4.5; back-fill).
- `l1_ids`: the L1 interaction(s) the tool wraps (e.g. `sql-agent/query` → the
  DB; `gmail-send-email` → the external API). `control_ids`: per-tool approvals/
  policies (4.7).
- ID: `tool.<agent>.<tool_name>`.

### 4.3 `context_sources` — one record per origin of content entering the prompt
- Enumerate every string concatenated into `messages[]`: system prompt,
  developer prompt, user input, chat history, tool results, retrieved docs
  (RAG / vector similaritySearch), uploaded documents, delegated summaries,
  `mcp_resource` / `mcp_prompt` content.
- `trust_class` is the crux: `trusted_instruction` only for content the runtime
  genuinely treats as instruction and that only trusted principals can write;
  `untrusted_data` for tool results, retrieved docs, user input, external
  content; `mixed` where a blob carries both.
- `writers`: who can populate it (this is how prompt-injection reach is modeled —
  an untrusted writer into a high-trust channel is the finding-shaped fact, even
  though we record only the surface).
- ID: `ctx.<what>` (e.g. `ctx.workspace_system_prompt`, `ctx.rag_chunks`,
  `ctx.tool_results`).

### 4.4 `memory_stores` — one record per cross-step store
- Vector store, conversation/chat tables, agent scratch memory, task summaries,
  caches, event logs.
- `scope` + `isolation_enforcement`: how the boundary is actually applied
  (namespace filter in repo code, per-session key, or by convention only — the
  last is the cross-tenant surface). `write_provenance`: can untrusted users/
  tools write it (memory-poisoning reach)?
- ID: `mem.<store>`.

### 4.5 `output_sinks` — one record per destination output leaves
- Chat response stream, created files, outbound email, external API writes,
  notifications, delegated results, logs.
- `render_side_effects`: set for the chat-UI sink and any HTML/markdown renderer
  — whether auto-loaded images/links or active content can fetch an
  attacker-chosen URL (the model-authored-markdown exfil channel).
- `becomes_context_source_ids`: close feedback loops (a written file later read
  back; memory later retrieved).
- ID: `sink.<what>`.

### 4.6 `execution_edges` — one record per transition
- Enumerate loop transitions: user→agent; agent→tool (model-selected);
  tool→agent (result back into context); agent→sub-agent (delegation);
  agent→sink (final output); and any external→model edge (MCP **sampling**:
  leave `source.agent_id` null, set `source.external_trigger`, use
  `decision_maker: external_event`).
- `decision_maker`: `llm` for model-chosen tool/branch selection,
  `deterministic_code` for loop control/routing, `user`/`human_reviewer` for
  approvals.
- `argument_sources`: whether tool args are model-composed (injection-relevant)
  or code-passed. `loop_bound`: cap on repeated/recursive edges (ties to
  `agents.resource_limits`; unbounded = runaway-agency surface).
- `related_l2_steps`: `{l2_id, order}` so an operation's edges read in sequence.
- ID: `edge.<from>__<to>`.

### 4.7 `controls` — one record per guardrail/approval/filter/monitor
- Human-approval gates (`request-user-input`, `tool_approval.py`), tool
  permission/policy (`tool_permissions.py`), input/output filters
  (`filter.py`, `sanitize.py`), rate limits/cooldowns, monitoring/audit.
- The decisive fields: `enforcement_mode` (blocking vs advisory vs observe_only)
  and `implementation` (`code` vs `model_prompt` — a guardrail that is only a
  prompt instruction is not enforcement) and `failure_mode` (fail_closed vs
  fail_open vs bypass). Link via `applies_to_agent_ids` **and**
  `applies_to_tool_binding_ids`.
- ID: `ctl.<what>`.

---

## 5. Phase C — Trust & authority annotation

A dedicated pass after extraction, because it needs the full graph:

1. **Trust classes**: finalize `context_sources.trust_class` for every source
   that reaches each agent. Flag any `untrusted_data` that lands in the
   `system`/`developer` `destination_channel` — record it faithfully (surface,
   not verdict).
2. **Authority/identity**: fill every `agents.authority_context` and
   `tool_bindings.execution_identity`. State where authorization is **enforced**
   (`authz_enforcement`: code / external policy / none) — never treat a prompt
   instruction as enforcement.
3. **Writers everywhere**: every `instruction_sources`, `context_sources`,
   `memory_stores`, `description_source` must have `writers` resolved to subject-
   taxonomy principals + the `l1_id` used to write, or `[]` for source-fixed.

---

## 6. Phase D — Data-lineage closure (the core invariant)

The schema's purpose is traceability. Before runtime, assert statically:

- **Entry**: every `context_sources` and `memory_stores` has at least one
  `writers` entry (or is explicitly source-fixed).
- **Carry**: every `tool_bindings.output_ids` and `execution_edges.output_ids`
  references a real `context_sources` / `memory_stores` / `output_sinks` ID.
- **Exit**: every `output_sinks.producer_ids` references a real agent or tool
  binding; feedback loops closed via `becomes_context_source_ids`.
- **No dangling IDs** in any `*_ids` field (agents↔tools↔context↔memory↔sinks↔
  edges↔controls all resolve).

A content item that enters but reaches no agent, or an agent output with no sink,
is an extraction gap — fix it here, not at validation.

---

## 7. Phase E — Runtime grounding

Reuse the L1/L2 runtime discipline (pinned image matching source; stamp only
version-stable behavior; divergence → annotation issue). Grounding an agentic
record means **observing one real run**, not just reading source:

1. Bring up the app on the pinned image with a model provider wired (a cheap/
   local model is fine; or a stub provider if the app allows — the point is the
   *control/data path*, not model quality).
2. Drive the agent with a prompt that forces exactly one tool call. Capture:
   - the tool invocation + the **arguments** actually sent (model-composed?);
   - the **identity** the tool used to reach its backend (confused-deputy check);
   - what **landed back in context** (confirms the `output_ids` edge);
   - whether a **control fired** (approval prompt, filter, denial) and its
     `enforcement_mode` in practice vs source.
3. Mark the records exercised `evidence_status: observed` and note the run in
   `source_ref`. Everything else stays `source_confirmed`.
4. Set `reachability.status` from what you could actually trigger
   (`black_box_reachable`, `conditionally_mounted` for tools gated behind config/
   MCP enablement, `blocked_by_control`, `unreachable_in_source`).

Aim to ground at least: the orchestration loop, one representative tool per
`effect_class` present, one memory read/write, and each distinct control — the
agentic analogue of the "N nodes runtime-confirmed" count in the L1/L2 builds.

---

## 8. Phase F — Link to L1/L2

- `tool_bindings.l1_ids` → the L1 interaction each tool wraps.
- `agents.invocation_surfaces[].l1_id` → the L1 entry points.
- `*.related_l2_ids` / `execution_edges.related_l2_steps` → the L2 operations the
  agent participates in, with `order`.
- `writers[].l1_id` → the interface used to write each content item.

Every agentic record that touches HTTP must resolve to an existing L1 ID; if the
tool reaches a surface L1 didn't catalog (e.g. an outbound third-party API), note
it and add the L1 node rather than leaving the link null.

---

## 9. Phase G — Validate

Build `validate_agentic.py` (none exists yet). Minimum assertions:

1. **Referential integrity**: every ID referenced in any `*_ids` field exists in
   its record set; no dangling references.
2. **Lineage closure**: the Phase-D invariants, as hard checks.
3. **Enum conformance**: every enum field holds a schema-listed value.
4. **Writers well-formed**: `{principal, l1_id}` with principal in the subject
   taxonomy; `[]` only for source-fixed content.
5. **No secrets**: no API-key/token-shaped values in any field (config
   *locations* only).
6. **Evidence/reachability separation**: `reachability.status` never holds an
   `evidence_status` value, and vice versa.
7. **Cross-layer**: every referenced `l1_id`/`l2_id` exists in the app's
   `l1_gt.yaml`/`l2_gt.yaml`.

Gate the build on a clean validate, exactly as the L1/L2 flow does.

---

## 10. Phase H — Export

Extend `export_to_pengent.py` (or add an agentic exporter) to emit the agentic
record sets alongside L1/L2 in `pengent_export.json`, preserving the cross-layer
IDs so a consumer can walk L2 operation → execution edges → tool bindings → L1
interactions.

---

## 11. File layout & conventions

Per app, under `<app>_gt/`:

```
generators/
  agentic_data.py     # the seven record sets as data (like l1_data.py/l2_data.py)
  agentic_lib.py      # builders: agent(), tool(), ctx(), mem(), sink(), edge(), ctl()
  build_agentic.py    # emits agentic_gt.yaml
agentic_gt.yaml       # the output
environment.yaml      # + applicability verdict and agent-runtime version
annotation_issues.yaml# + agentic divergences (source vs image)
```

ID conventions (stable, lowercase, dotted):
`agent.<component>.<role>` · `tool.<agent>.<tool_name>` · `ctx.<what>` ·
`mem.<store>` · `sink.<what>` · `edge.<from>__<to>` · `ctl.<what>`.

Reuse the L1/L2 generator skeleton pattern: data modules + a small builder lib +
a `build_*.py` that validates IDs as it emits. Copy `agentic_lib.py` from the
newest app's version and adapt the per-app registries, the same way the L1/L2
skeleton is copied and adapted.

---

## 12. Evidence & reachability discipline

- `evidence_status` is about **how you know** (observed > source_confirmed >
  inferred > unknown). Phases A–D produce `source_confirmed`; Phase E upgrades to
  `observed`; never claim `observed` for a path you only read.
- `reachability` is about **whether it can be triggered** in this deployment.
  Keep the two orthogonal — a tool can be `source_confirmed` but
  `conditionally_mounted` (defined, needs an MCP server or env flag to reach).
- `visibility` is the access needed to *understand* the record — e.g. that
  editing a tool-description field changes another agent's behavior several
  requests later is `grey_box_required`/`white_box_required` even when the field
  itself is black-box observable.

---

## 13. Common pitfalls

- **Modeling the model, not the paths.** The GT is the control/data graph, not
  the LLM's quality. Ground paths, not completions.
- **Prompt guidance recorded as enforcement.** A "do not do X" system-prompt line
  is `implementation: model_prompt`, `enforcement_mode: advisory` — never
  `authorization`.
- **One tool, many agents collapsed.** Different agents may invoke the same tool
  with different `execution_identity`; keep separate bindings.
- **Image/source drift.** The published image's agent wiring may diverge from the
  pinned source (tools enabled by default, model provider, MCP mounts). Stamp
  version-stable behavior only; log divergence as an annotation issue.
- **Missing feedback loops.** Files written then re-read, and memory written then
  retrieved, are lineage edges — set `becomes_context_source_ids` /
  `write_provenance`, or the injection/poisoning path is invisible.
- **Secrets leaking into the GT.** Record where a credential lives, never its
  value.
```
