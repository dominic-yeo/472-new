# Agentic Layer Runtime Grounding (#8)

_2026-11-21. Honest characterization of how much of the agentic GT is
runtime-observed, and precisely why the rest is not._

The agentic layer (agents, tool_bindings, context_sources, memory_stores,
output_sinks, execution_edges, controls) has **307 records across 5 LLM apps**.
All runtime observation uses a **local model** (qwen2.5 / llama3.1 in Ollama) —
**no cloud credentials** — so some surface is unreachable by construction.

## Observed: 129 / 307 (42%)  _(up from 102 at #8 start; +5 stand-in servers, +7 scheduler/CRUD driving 2026-11-22)_

| app | observed | total | driven via |
|---|--:|--:|---|
| anything-llm | 47 | 58 | REST `@agent` runs + local stand-ins (image, MCP) + **cron scheduler fired** |
| open-webui | 36 | 82 | socket.io harness + direct feature APIs + local image stand-in + **automations CRUD/run** |
| openclaw | 22 | 82 | gateway agent runs (SSRF control seen firing) |
| LibreChat | 24 | 54 | SSE harness + direct APIs (memory recall, attachments) + **memory/action CRUD** |
| lobe-chat | 0 | 31 | — (blocked, below) |

**Driving campaign (ongoing).** Records are promoted to `observed` only when a
real feature call returns 2xx (or a verified effect). The reliably-drivable
records are the ones exercised by **direct feature APIs** (memory/knowledge/notes/
skills/tools/files create + read) — model-independent, so honest and repeatable.
Model-dependent records (tool calls inside a chat, subagent spawns, RAG retrieval)
and client-side ones (open-webui code-exec is browser pyodide) need agent runs
through the unreliable local model and remain the slow part of the backlog.

## The 178 unobserved, by blocker (every record now tagged `runtime_blocker`)

| category | count | meaning |
|---|--:|---|
| **local_not_driven** | 125 | exercisable locally, not yet driven — a labeled backlog |
| **crypto_blocked** | 31 | lobe-chat: chat auth payload (`X-lobe-chat-auth` + keyvault) could not be reproduced |
| **external_integration** | 15 | needs a real 3rd-party credential (OAuth) a local stand-in cannot supply |
| **scheduling_required** | 7 | openclaw cron — gateway dormant + write-side needs model tool-call (see below) |

### Scheduler + direct-CRUD driving (2026-11-22): +7
Two classes of previously-blocked records that need **no agent tool-call** were driven to
effect-observed:
- **anything-llm scheduler (scheduling_required 10 → 7):** created a job via
  `POST /api/scheduled-jobs/new` (`* * * * *`); the in-process cron timer fired
  `ScheduledJobRun` 1/2/3 at consecutive minutes and run 3 completed with
  `EphemeralAgentHandler` output `SCHEDULED` (qwen2.5:7b). This genuinely observes the
  scheduling surface — `mem.scheduled_jobs` (durable job store), `sink.scheduled_job`
  (persisted run delivered), `edge.scheduled__ephemeral` (scheduler re-invokes an agent) —
  independent of tool-calling. **Scheduling is therefore no longer a hard ceiling.**
- **direct-CRUD store writes (local_not_driven 129 → 125):** a store is genuinely exercised
  when the app's own API writes and reads it back, with no model in the loop. Driven:
  LibreChat `mem.agent_memory` + `sink.memory_write` (`POST /api/memories` 201 → persisted
  entry → `GET` 200), LibreChat `mem.actions` (`POST /api/agents/actions/{id}` → encrypted
  action set persisted with outbound domain), open-webui `mem.automations`
  (`POST .../automations/create` → durable rrule trigger → `POST /{id}/run` →
  `AutomationRun status=success`). The matching **agent tool** records (`tool.memory`,
  `edge.memory_extract`, automation *authoring* by the model) stay `local_not_driven` —
  those need the model to emit the call.

**The 7 remaining scheduling records (openclaw)** are blocked for two honest reasons: the
openclaw container currently runs `sleep infinity` with no gateway/scheduler process, and
even activated, the write-side cron records (`tool.primary.cron`, `edge.primary__cron`,
the creator-cap control) need the local model to emit the cron tool-call — the same
model-dependent wall. They are reachability/model-limited, not a principled ceiling.

### Local stand-in servers (external_integration 22 → 15)
Rather than real SaaS, stand up **secret-free local endpoints** so an integration
edge fires against a local target and is genuinely observable (logged inbound hit
+ effect). Two stand-ins (`scratchpad/stub_server.py` on :8099, `mcp_stub.py` on
:8100): an **OpenAI-compatible image API** (`/images/generations` → real 1×1 PNG)
and a **streamable-HTTP MCP server** (one `gt_mcp_probe` tool). Converted **5**:
open-webui `tool.primary.image`+`sink.image_gen` (image API → file produced),
anything-llm `tool.ws.generate_image`+`sink.image` (localAi provider → stand-in)
and `tool.ws.mcp` (qwen2.5 @agent → JSON-RPC `tools/call` proxied to the MCP
stand-in). The remaining 15 split three ways:
- **OAuth-gated, truly not stub-addressable (7):** anything-llm Gmail/Outlook/
  GCal + `sink.email`/`sink.calendar`, LibreChat `tool.mcp`/`ctl.mcp_oauth`. These
  need a real Google/Microsoft OAuth identity; a local SMTP/API stand-in does not
  substitute an OAuth grant. Hard block by design.
- **Stub-addressable but model-dependent (6):** open-webui `tool.primary.mcp`/
  `sink.external_tool_call`/`edge.primary__external`, openclaw `web_search`/
  `github`/`sink.github`. The integration *connects* to a local stand-in (proven
  for openclaw MCP: `openclaw mcp probe` → "1 tools"), but firing it needs the
  local model to emit a native structured tool call — the same reliability wall as
  the model-dependent `local_not_driven` records (openclaw's 2 MCP records were
  reclassified there for this reason).
- **Stub-addressable, deferred (2):** LibreChat `tool.image_gen`/`sink.image` —
  same image pattern, but needs a disruptive container recreate (image base URL is
  env-only), deferred.

### local_not_driven (129) — the real remaining opportunity
These are **not a hard block**: memory stores, RAG/context sources, code-exec and
subagent flows, tool edges, and guardrail controls that the local model *can*
exercise. They aren't observed yet because each requires driving a **specific
agent feature** (invoke that tool, run code, spawn a subagent, trip that control)
through an unreliable local model with an app-specific harness (socket.io / SSE /
gateway). High effort, modest per-record yield — a genuine backlog, not a
ceiling. A plain chat does **not** exercise them (it only touches the basic
user→assistant→response loop), so they cannot be honestly marked from a chat.

### crypto_blocked (31) — lobe-chat
Re-confirmed this session. The Ollama provider bypasses the *apiKey* decryption
(no key needed) and the `X-lobe-chat-auth` header is now accepted (401→500), but
the server rejects the auth payload with `SyntaxError: Unexpected non-whitespace
character after JSON` — its encoding/keyvault format could not be reproduced.
Architecturally blocked.

### external_integration (15) — OAuth-hard + model-dependent
Image generation and MCP are NO LONGER a hard block — a local stand-in supplies
them without secrets (5 converted, above). What remains is genuinely external:
**7 OAuth-gated** (Gmail/Outlook/GCal/email/calendar sinks + per-user MCP OAuth)
that need a real Google/Microsoft grant a stand-in cannot mint; **6 model-
dependent** (MCP/web-search/GitHub that connect to a local stand-in but need the
local model to emit a native tool call); and **2 deferred** (LibreChat image,
env-only base URL → needs a container recreate). Only the 7 OAuth ones are a
principled hard block; the other 8 are reachability-limited, not design-excluded.

## Honest bottom line
The hard, principled ceiling is now **38 records** (7 OAuth external + 31 crypto) that
cannot be runtime-observed in a local, secret-free environment. Scheduling dropped out of
the ceiling this phase — proven drivable on anything-llm — so the remaining **140** are all
reachability-limited (125 `local_not_driven` + 7 openclaw scheduling + 8 stub-addressable-
but-model-dependent/deferred): drivable in principle, bounded by the dormant openclaw
gateway and by how reliably the local model emits native tool calls. Cumulative driving
this cycle: **+5** via local stand-in servers (image + MCP) and **+7** via the scheduler and
direct-CRUD store writes — all effect-traced (a real 2xx, a persisted run, or a read-back),
with every unobserved record stating precisely *why*.
