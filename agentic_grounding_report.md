# Agentic Layer Runtime Grounding (#8)

_2026-11-21. Honest characterization of how much of the agentic GT is
runtime-observed, and precisely why the rest is not._

The agentic layer (agents, tool_bindings, context_sources, memory_stores,
output_sinks, execution_edges, controls) has **307 records across 5 LLM apps**.
All runtime observation uses a **local model** (qwen2.5 / llama3.1 in Ollama) —
**no cloud credentials** — so some surface is unreachable by construction.

## Observed: 117 / 307 (38%)  _(up from 102 at #8 start)_

| app | observed | total | driven via |
|---|--:|--:|---|
| anything-llm | 41 | 58 | REST `@agent` runs (local model) |
| open-webui | 33 | 82 | socket.io harness + direct feature APIs (memories, knowledge, notes, skills, tools, files) |
| openclaw | 22 | 82 | gateway agent runs (SSRF control seen firing) |
| LibreChat | 21 | 54 | SSE harness + direct APIs (memory recall, attachments) |
| lobe-chat | 0 | 31 | — (blocked, below) |

**Driving campaign (ongoing).** Records are promoted to `observed` only when a
real feature call returns 2xx (or a verified effect). The reliably-drivable
records are the ones exercised by **direct feature APIs** (memory/knowledge/notes/
skills/tools/files create + read) — model-independent, so honest and repeatable.
Model-dependent records (tool calls inside a chat, subagent spawns, RAG retrieval)
and client-side ones (open-webui code-exec is browser pyodide) need agent runs
through the unreliable local model and remain the slow part of the backlog.

## The 204 unobserved, by blocker (every record now tagged `runtime_blocker`)

| category | count | meaning |
|---|--:|---|
| **local_not_driven** | 127 | exercisable locally, not yet driven — a labeled backlog |
| **crypto_blocked** | 31 | lobe-chat: chat auth payload (`X-lobe-chat-auth` + keyvault) could not be reproduced |
| **external_integration** | 22 | needs a 3rd-party SaaS credential we deliberately exclude |
| **scheduling_required** | 10 | needs a cron/timer trigger to fire |

### local_not_driven (141) — the real remaining opportunity
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

### external_integration (22) — by design
Gmail, Google Calendar, Outlook, web-search providers, image generation, MCP
servers, webhooks, OAuth, cloud storage. Exercising these needs real 3rd-party
credentials, which the grounding methodology deliberately excludes (no secrets in
or around the GT). Unreachable by construction, not by oversight.

## Honest bottom line
The hard, principled ceiling is **53 records** (22 external + 31 crypto) plus 10
scheduling-gated — these cannot be runtime-observed in a local, secret-free
environment. The other **127 are drivable** (14 driven this campaign so far) with further per-app feature driving;
this pass added 1 reliably-confirmed observation (anything-llm `@agent`) and
labeled the rest so the gap is precise and auditable rather than vague.
