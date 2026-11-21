# Agentic Layer Runtime Grounding (#8)

_2026-11-21. Honest characterization of how much of the agentic GT is
runtime-observed, and precisely why the rest is not._

The agentic layer (agents, tool_bindings, context_sources, memory_stores,
output_sinks, execution_edges, controls) has **307 records across 5 LLM apps**.
All runtime observation uses a **local model** (qwen2.5 / llama3.1 in Ollama) —
**no cloud credentials** — so some surface is unreachable by construction.

## Observed: 122 / 307 (40%)  _(up from 102 at #8 start; +5 via local stand-in servers)_

| app | observed | total | driven via |
|---|--:|--:|---|
| anything-llm | 44 | 58 | REST `@agent` runs (local model) + local stand-ins (image, MCP) |
| open-webui | 35 | 82 | socket.io harness + direct feature APIs + local image stand-in |
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

## The 185 unobserved, by blocker (every record now tagged `runtime_blocker`)

| category | count | meaning |
|---|--:|---|
| **local_not_driven** | 129 | exercisable locally, not yet driven — a labeled backlog |
| **crypto_blocked** | 31 | lobe-chat: chat auth payload (`X-lobe-chat-auth` + keyvault) could not be reproduced |
| **external_integration** | 15 | needs a real 3rd-party credential (OAuth) a local stand-in cannot supply |
| **scheduling_required** | 10 | needs a cron/timer trigger to fire |

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
The hard, principled ceiling is now **48 records** (7 OAuth external + 31 crypto +
10 scheduling) that cannot be runtime-observed in a local, secret-free environment.
The remaining **137** are reachability-limited (129 `local_not_driven` + 8
stub-addressable-but-model-dependent/deferred) — drivable in principle, bounded by
how reliably the local model emits native tool calls. This phase drove **+5** via
local stand-in servers (image + MCP, all effect-traced) and sharpened the gap so
every unobserved record states precisely *why*.
