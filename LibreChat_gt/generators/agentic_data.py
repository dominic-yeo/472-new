# -*- coding: utf-8 -*-
"""LibreChat agentic attack-surface data (schema: agentic-attack-surface-v1).

App: LibreChat (web source under 472-new/LibreChat). Agent runtime = the Agents
endpoint: a @librechat/agents LangGraph run (api/server/services/Runs/*,
createRunBody.js) over tools loaded by ToolService.js (loadAgentTools), gated by
AgentCapabilities. Native tools: execute_code (Code Interpreter API, sandboxed),
file_search (RAG API), web_search, image gen, memory; plus MCP tools (per-user
OAuth/OBO identity) and OpenAPI Actions (loadActionSets, per-agent auth). Agents
can delegate to SUB-AGENTS (packages/api/src/agents/*: subagentIdentity,
delegation, routing). A background memory agent extracts memories.

Distinctive: MCP uses PER-USER OBO identity (AuthIdentityContext from the real
request user) -- stronger than instance-cred apps. Static pass; grounding pending.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

P = "agent.librechat.primary"

AGENTS = [
    agent(
        P, "Agent (Agents endpoint)", "LibreChat", "interactive",
        "User-configured agent run over a LangGraph loop; tools gated by AgentCapabilities; "
        "can call MCP servers, OpenAPI Actions, and sub-agents.",
        invocation_surfaces=[
            {"l1_id": "l1.api.agents.chat", "trigger": "POST agents chat (EModelEndpoint.agents) run",
             "auth_context": "session JWT -> req.user; agent access + tool role grants"},
        ],
        model_config={"provider": "any configured endpoint (OpenAI/Anthropic/Bedrock/Google/custom)",
                     "model": "agent model_parameters", "config_source": "agent definition + librechat.yaml",
                     "writers": [writer("agent_author", "l1.api.agents.update"), writer("admin", "l1.config.librechat_yaml")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("agent_author", "l1.api.agents.update")]}],
        tool_binding_ids=["tool.execute_code", "tool.file_search", "tool.web_search", "tool.image_gen",
                         "tool.memory", "tool.mcp", "tool.actions", "tool.plugins", "tool.subagent"],
        context_source_ids=["ctx.system_prompt", "ctx.user_message", "ctx.chat_history", "ctx.file_search_rag",
                          "ctx.tool_results", "ctx.web_content", "ctx.memory_recall", "ctx.ocr_context",
                          "ctx.tool_descriptions", "ctx.attachments"],
        memory_ids=["mem.conversations", "mem.vectordb", "mem.agent_memory", "mem.agents_config", "mem.actions"],
        output_sink_ids=["sink.chat_response", "sink.artifacts", "sink.code_exec", "sink.image",
                         "sink.action_call", "sink.mcp_call", "sink.web_fetch"],
        control_ids=["ctl.agent_capabilities", "ctl.tool_role_grants", "ctl.code_sandbox", "ctl.mcp_oauth",
                     "ctl.action_auth", "ctl.abort"],
        resource_limits={"max_iterations": "LangGraph recursion/step limit (agent run)",
                        "recursion": "sub-agents bounded by routing config", "token_or_cost_budget": "token limits per agent",
                        "loop_detection": "graph recursionLimit", "enforced_by": "code"},
        authority_context={"principal_source": "session JWT -> req.user",
                         "tenant_scope": "per-user; shared agents by permission",
                         "resource_scope": "user's files/memories; agent's actions/MCP",
                         "delegated_identity": "MCP/Actions use PER-USER OAuth/OBO identity (AuthIdentityContext); "
                         "Actions may also use stored apiKey auth",
                         "authz_enforcement": "code (AgentCapabilities + resolveToolRoleGrants + per-tool auth)"},
        related_l2_ids=["l2.agents.chat"],
        source_ref="api/server/services/ToolService.js loadAgentTools; createRunBody.js; Runs/StreamRunManager.js",
        notes="Tool set = native capability tools + agent.tools (plugins) + agent actions + MCP servers, "
              "each gated by AgentCapabilities and tool role grants.",
    ),
    agent(
        "agent.librechat.subagent", "Sub-agent (delegated)", "LibreChat", "specialist",
        "Delegated agent/graph run spawned by a parent agent; identity captured as subagentIdentity.",
        invocation_surfaces=[{"l1_id": "l1.internal.subagent", "trigger": "parent agent delegation (chain capability)",
                            "auth_context": "parent run's user identity"}],
        model_config={"provider": "sub-agent's own definition", "model": "sub-agent model", "config_source": "agent definition",
                     "writers": [writer("agent_author", "l1.api.agents.update")], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("agent_author", "l1.api.agents.update")]},
                           {"surface_id": "ctx.delegated_task", "instruction_role": "developer", "precedence": "base",
                            "config_version": "runtime", "writers": [writer(P, None)]}],
        tool_binding_ids=["tool.execute_code", "tool.file_search", "tool.web_search", "tool.mcp", "tool.actions"],
        context_source_ids=["ctx.system_prompt", "ctx.delegated_task", "ctx.tool_results", "ctx.file_search_rag",
                          "ctx.web_content"],
        memory_ids=["mem.conversations", "mem.vectordb"],
        output_sink_ids=["sink.delegated_result", "sink.action_call", "sink.mcp_call"],
        control_ids=["ctl.agent_capabilities", "ctl.subagent_routing", "ctl.tool_role_grants"],
        resource_limits={"max_iterations": "graph recursionLimit", "recursion": "routing bounds nesting",
                        "token_or_cost_budget": "per sub-agent", "loop_detection": "graph limit", "enforced_by": "code"},
        authority_context={"principal_source": "inherits parent user",
                         "tenant_scope": "same user", "resource_scope": "sub-agent's tools/actions",
                         "delegated_identity": "subagentIdentity (subagentKind agent|graph + subagentAgentId); per-user OBO",
                         "authz_enforcement": "code (capabilities + routing)"},
        related_l2_ids=["l2.agents.chat"],
        source_ref="packages/api/src/agents/{subagentIdentity,subagentTaskRouting,subagentDelivery}.ts",
        notes="Child content + identity buffered and delivered back to the parent (subagentContent/Delivery)."),
    agent(
        "agent.librechat.memory", "Memory agent", "LibreChat", "reviewer",
        "Background agent that extracts/updates long-term memory from conversation turns.",
        invocation_surfaces=[{"l1_id": "l1.internal.memory", "trigger": "post-turn memory processing (memory capability)",
                            "auth_context": "turn user"}],
        model_config={"provider": "configured memory model", "model": "memory agent model", "config_source": "librechat.yaml memory",
                     "writers": [writer("admin", "l1.config.librechat_yaml")], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.memory_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("admin", "l1.config.librechat_yaml")]}],
        tool_binding_ids=["tool.memory"],
        context_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.memory_prompt"],
        memory_ids=["mem.agent_memory"],
        output_sink_ids=["sink.memory_write"],
        control_ids=["ctl.agent_capabilities"], resource_limits=None,
        authority_context={"principal_source": "turn user", "tenant_scope": "same user",
                         "resource_scope": "user's memories", "delegated_identity": "runs as the user",
                         "authz_enforcement": "code (memory capability + token limits)"},
        related_l2_ids=["l2.agents.chat"],
        source_ref="packages/api memory processing; Tools memory",
        notes="Turn-derived memory extraction -> poisoning persistence into ctx.memory_recall."),
]

_user_obo = {"identity": "the request user (AuthIdentityContext / OBO)", "credential_source": "user session + stored OAuth tokens"}
_argh = {"validation": "tool arg schema (LangGraph structured tools)", "authorization": "AgentCapabilities + tool role grants",
         "normalization": "provider tool-call parsing", "enforced_by": "code"}


def _env(sandbox, egress, fs, by="code"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


TOOLS = [
    tool("tool.execute_code", P, "execute_code (Code Interpreter)", "api", "code_execution",
         l1_ids=["l1.api.code.execute"], server_or_provider="LibreChat Code Interpreter API",
         capabilities=["run code in a sandboxed interpreter; file I/O in the session sandbox"],
         execution_identity={"identity": "Code API session (per-user)", "credential_source": "LIBRECHAT_CODE_API_KEY + user session"},
         execution_environment=_env("LibreChat Code API sandbox (remote container)", "controlled by Code API",
                                  "session sandbox FS", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "sink.code_exec"],
         control_ids=["ctl.agent_capabilities", "ctl.code_sandbox", "ctl.tool_role_grants"],
         source_ref="ToolService; app/clients/tools code/agent.ts",
         reachability=reach("conditionally_mounted", "AgentCapabilities.execute_code enabled + code resource"),
         notes="Sandboxed interpreter (stronger isolation than in-process evaluators)."),

    tool("tool.file_search", P, "file_search (RAG)", "api", "read",
         l1_ids=["l1.api.rag.search"], server_or_provider="RAG API (vector)",
         capabilities=["semantic search over the user's attached files"], execution_identity=_user_obo,
         output_ids=["ctx.file_search_rag", "ctx.tool_results"],
         control_ids=["ctl.agent_capabilities", "ctl.tool_role_grants"],
         source_ref="ToolService file_search; RAG API",
         reachability=reach("conditionally_mounted", "AgentCapabilities.file_search + file_search resource"),
         notes="Retrieved file chunks are untrusted -> indirect injection."),

    tool("tool.web_search", P, "web_search", "native", "external_send",
         capabilities=["search provider + scrape results + rerank"],
         execution_identity={"identity": "server", "credential_source": "search/scraper/reranker keys (librechat.yaml)"},
         execution_environment=_env("in-process + scraper", "unrestricted scrape (SSRF surface)", "none"),
         output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_fetch"],
         control_ids=["ctl.agent_capabilities"], source_ref="app/clients/tools web/agent.ts",
         reachability=reach("conditionally_mounted", "AgentCapabilities.web_search enabled"),
         notes="Scrapes model-reachable URLs -> SSRF + indirect injection via page content."),

    tool("tool.image_gen", P, "image generation", "native", "external_send",
         capabilities=["image_gen_oai / gemini_image_gen / dalle"], execution_identity={"identity": "provider key",
                                                                                        "credential_source": "image provider config"},
         output_ids=["sink.image", "ctx.tool_results"], control_ids=["ctl.agent_capabilities"],
         source_ref="ToolService imageGenTools", reachability=reach("conditionally_mounted", "image gen tool enabled")),

    tool("tool.memory", P, "memory", "native", "write",
         capabilities=["read/write agent long-term memory"], execution_identity=_user_obo,
         output_ids=["mem.agent_memory", "ctx.memory_recall"], control_ids=["ctl.agent_capabilities"],
         source_ref="ToolService memory; packages/api memory",
         reachability=reach("conditionally_mounted", "AgentCapabilities.memory enabled"),
         notes="Agent/turn-written memory re-injected (poisoning loop)."),

    tool("tool.mcp", P, "MCP server tools", "mcp", "mixed",
         server_or_provider="configured MCP servers (user or global)",
         capabilities=["call MCP tools; MCP SDK (tools, possibly resources)"],
         description_source={"source_ref": "MCP tool listing (remote)",
                           "writers": [writer("external_service", None), writer("admin", "l1.config.mcp_servers"),
                                       writer("user", "l1.api.mcp.connect")]},
         execution_identity=_user_obo,
         execution_environment=_env("remote MCP server", "per server", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "ctx.tool_descriptions", "sink.mcp_call"],
         control_ids=["ctl.agent_capabilities", "ctl.mcp_oauth"],
         source_ref="api/server/services/Tools/mcp.js; packages/api/src/mcp; getMCPManager",
         reachability=reach("conditionally_mounted", "MCP server configured + (per-user) OAuth connected"),
         notes="PER-USER OAuth/OBO identity (AuthIdentityContext) -> not a shared-cred confused deputy; "
               "remote tool descriptions still a rug-pull/injection channel."),

    tool("tool.actions", P, "OpenAPI Actions", "api", "mixed",
         l1_ids=["l1.api.actions.execute"], server_or_provider="per-agent OpenAPI action domains",
         capabilities=["call operations from an agent's OpenAPI action sets"],
         description_source={"source_ref": "OpenAPI spec (per agent, authored/imported)",
                           "writers": [writer("agent_author", "l1.api.actions.create"), writer("external_service", None)]},
         execution_identity={"identity": "action auth (none | apiKey | OAuth)", "credential_source": "action set auth (stored, encrypted)"},
         execution_environment=_env("remote action domain", "action domain", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "sink.action_call"],
         control_ids=["ctl.agent_capabilities", "ctl.action_auth"],
         source_ref="ToolService loadActionSets/processActions",
         reachability=reach("conditionally_mounted", "AgentCapabilities.actions + agent has action sets"),
         notes="Model-composed args to agent-defined OpenAPI domains -> SSRF/abuse scoped by action auth; "
               "OpenAPI description is model-facing."),

    tool("tool.plugins", P, "structured tool plugins", "plugin", "mixed",
         capabilities=["manifest tools / toolkits (manifestToolMap)"], execution_identity={"identity": "plugin",
                                                                                           "credential_source": "plugin auth (user-provided keys)"},
         output_ids=["ctx.tool_results", "sink.action_call"], control_ids=["ctl.tool_role_grants"],
         source_ref="app/clients/tools/manifest; loadTools",
         reachability=reach("conditionally_mounted", "agent.tools includes plugin ids")),

    tool("tool.subagent", P, "delegate to sub-agent", "native", "none",
         capabilities=["spawn a sub-agent/graph (chain capability)"], execution_identity=_user_obo,
         output_ids=["ctx.delegated_task", "sink.delegated_result"], control_ids=["ctl.subagent_routing"],
         source_ref="packages/api/src/agents/* (subagent delegation)",
         reachability=reach("conditionally_mounted", "chain/agents capability + referenced sub-agents"),
         notes="Delegation edge; sub-agent carries the real effects."),
]

_dest = [P, "agent.librechat.subagent"]
CONTEXT = [
    ctx("ctx.system_prompt", "system_prompt", "trusted_instruction", source_ref="agent.instructions",
        writers=[writer("agent_author", "l1.api.agents.update")], destination_agent_ids=_dest,
        destination_channel="system", provenance="agent definition", persistence_scope="tenant",
        notes="Agent instructions authored by the agent owner; shared agents expose this to other users."),

    ctx("ctx.memory_prompt", "system_prompt", "trusted_instruction", source_ref="librechat.yaml memory prompt",
        writers=[writer("admin", "l1.config.librechat_yaml")], destination_agent_ids=["agent.librechat.memory"],
        destination_channel="system", provenance="admin config", persistence_scope="global"),

    ctx("ctx.user_message", "user_input", "untrusted_data", source_ref="chat message",
        writers=[writer("user", "l1.api.agents.chat")], destination_agent_ids=[P, "agent.librechat.memory"],
        destination_channel="user", provenance="end user", persistence_scope="session"),

    ctx("ctx.chat_history", "chat_history", "mixed", source_ref="conversations/messages",
        writers=[writer("user", "l1.api.agents.chat"), writer(P, None)], destination_agent_ids=[P, "agent.librechat.memory"],
        destination_channel="user", provenance="prior turns", persistence_scope="session"),

    ctx("ctx.file_search_rag", "retrieval", "untrusted_data", source_ref="RAG API file_search results",
        writers=[writer("user", "l1.api.files.upload")], destination_agent_ids=_dest, destination_channel="tool",
        provenance="user files", persistence_scope="user",
        notes="Retrieved file chunks -> indirect injection."),

    ctx("ctx.tool_results", "tool_result", "untrusted_data", source_ref="tool outputs re-fed to the graph",
        writers=[writer(P, None), writer("external_service", None)], destination_agent_ids=_dest,
        destination_channel="tool", provenance="tool/MCP/action output", persistence_scope="session"),

    ctx("ctx.web_content", "external", "untrusted_data", source_ref="web_search scrape results",
        writers=[writer("external_service", None)], destination_agent_ids=_dest, destination_channel="tool",
        provenance="scraped web", persistence_scope="session",
        notes="Scraped page content -> indirect injection + SSRF reflection."),

    ctx("ctx.memory_recall", "retrieval", "untrusted_data", source_ref="memory injected into context",
        writers=[writer("agent.librechat.memory", None), writer(P, None)], destination_agent_ids=[P],
        destination_channel="system", provenance="prior memory writes", persistence_scope="user",
        notes="Turn-derived memory re-injected -> poisoning persistence."),

    ctx("ctx.ocr_context", "document", "untrusted_data", source_ref="ocr/context capability file content injection",
        writers=[writer("user", "l1.api.files.upload")], destination_agent_ids=[P], destination_channel="user",
        provenance="uploaded files (OCR/context)", persistence_scope="session",
        reachability=reach("conditionally_mounted", "AgentCapabilities.ocr / context")),

    ctx("ctx.tool_descriptions", "external", "untrusted_data",
        source_ref="MCP tool listings + OpenAPI action descriptions shown to the model",
        writers=[writer("external_service", None), writer("agent_author", "l1.api.actions.create")],
        destination_agent_ids=_dest, destination_channel="tool", provenance="remote MCP / OpenAPI specs",
        persistence_scope="tenant",
        notes="Remote MCP/action descriptions are model-facing -> rug-pull / description injection."),

    ctx("ctx.delegated_task", "delegated_summary", "mixed", source_ref="parent -> sub-agent task",
        writers=[writer(P, None)], destination_agent_ids=["agent.librechat.subagent"], destination_channel="developer",
        provenance="parent agent (model-composed)", persistence_scope="workflow",
        notes="Parent-composed sub-agent task -> parent->child injection path."),

    ctx("ctx.attachments", "document", "untrusted_data", source_ref="message file/image attachments",
        writers=[writer("user", "l1.api.files.upload")], destination_agent_ids=[P], destination_channel="user",
        provenance="user uploads", persistence_scope="session"),
]

MEMORY = [
    mem("mem.conversations", "conversation_history", "LibreChat", "user",
        readers=[P, "agent.librechat.subagent", "agent.librechat.memory"],
        writers=[writer("user", "l1.api.agents.chat"), writer(P, None)],
        isolation_enforcement="per-user conversations (userId scoping)", write_provenance="user + agent turns",
        read_path="messages replayed into run", retention_and_deletion="user-managed",
        source_ref="packages/data-schemas conversations/messages"),

    mem("mem.vectordb", "vector_store", "LibreChat", "user",
        readers=[P, "agent.librechat.subagent"], writers=[writer("user", "l1.api.files.upload")],
        isolation_enforcement="per-user file ownership; shared agent files by permission",
        write_provenance="uploaded files (RAG API)", read_path="file_search semantic query",
        retention_and_deletion="file lifecycle", source_ref="RAG API; Files service",
        notes="Shared-agent file resources can cross users."),

    mem("mem.agent_memory", "agent_notes", "LibreChat", "user",
        readers=[P, "agent.librechat.memory"], writers=[writer("agent.librechat.memory", None), writer(P, None)],
        isolation_enforcement="per-user memory", write_provenance="memory agent (turn-derived) + memory tool",
        read_path="memory injected into context", retention_and_deletion="user-managed",
        source_ref="packages/api memory", reachability=reach("conditionally_mounted", "memory capability"),
        notes="Poisoning sink -> ctx.memory_recall."),

    mem("mem.agents_config", "database", "LibreChat", "tenant",
        readers=[P], writers=[writer("agent_author", "l1.api.agents.update"), writer("admin", "l1.config.librechat_yaml")],
        isolation_enforcement="agent ownership + share permissions", write_provenance="agent authors",
        read_path="agent definition supplies instructions + tools + actions",
        retention_and_deletion="owner-managed", source_ref="agents schema",
        notes="Editing a shared agent = provisioning instructions + tools for its users."),

    mem("mem.actions", "database", "LibreChat", "tenant",
        readers=[P], writers=[writer("agent_author", "l1.api.actions.create")],
        isolation_enforcement="per-agent action sets", write_provenance="agent authors",
        read_path="loadActionSets -> tools", retention_and_deletion="owner-managed",
        source_ref="ToolService loadActionSets; actions schema (auth encrypted)",
        notes="Action auth (apiKey/OAuth) stored encrypted; defines outbound domains."),
]

_md = {"auto_fetch": "chat UI renders markdown images/links", "active_content": "sanitized markdown",
       "enforced_by": "code"}
SINKS = [
    sink("sink.chat_response", "chat_response", producer_ids=[P], audience="user (chat UI)",
         delivery="streamed markdown", render_side_effects=_md, related_l2_ids=["l2.agents.chat"],
         source_ref="StreamRunManager", notes="Markdown image/link auto-load = exfil-on-render channel."),

    sink("sink.artifacts", "file", producer_ids=[P], audience="user (iframe)",
         delivery="model-authored HTML/React/Mermaid rendered in a sandboxed artifact iframe",
         render_side_effects={"auto_fetch": "iframe may load remote resources",
                            "active_content": "executes model-authored code in a sandboxed iframe",
                            "enforced_by": "code (artifacts capability + iframe sandbox)"},
         source_ref="artifacts capability", reachability=reach("conditionally_mounted", "AgentCapabilities.artifacts"),
         notes="Client-side code execution of model output; gated by artifacts capability."),

    sink("sink.code_exec", "external_api", producer_ids=["tool.execute_code"], audience="Code Interpreter API",
         delivery="HTTP to LibreChat Code API sandbox", source_ref="code/agent.ts",
         notes="Sandboxed remote execution; per-user session."),

    sink("sink.image", "external_api", producer_ids=["tool.image_gen"], audience="image provider",
         delivery="provider API", source_ref="image gen tools"),

    sink("sink.action_call", "external_api", producer_ids=["tool.actions", "tool.plugins"],
         audience="agent OpenAPI action domains / plugin APIs", delivery="HTTP with action/plugin auth + model args",
         related_l2_ids=["l2.agents.chat"], source_ref="processActions",
         notes="Model-composed args to agent-defined domains under stored action auth."),

    sink("sink.mcp_call", "external_api", producer_ids=["tool.mcp"], audience="MCP servers",
         delivery="MCP call under per-user OBO identity", source_ref="Tools/mcp.js",
         notes="Per-user OAuth identity (not shared creds)."),

    sink("sink.web_fetch", "external_api", producer_ids=["tool.web_search"], audience="arbitrary web",
         delivery="scraper fetch", becomes_context_source_ids=["ctx.web_content"], source_ref="web/agent.ts"),

    sink("sink.delegated_result", "delegated_result", producer_ids=["agent.librechat.subagent"],
         audience="parent agent", delivery="sub-agent content/identity buffered to parent",
         becomes_context_source_ids=["ctx.tool_results"], source_ref="subagentDelivery/subagentContent",
         notes="Child->parent path."),

    sink("sink.memory_write", "database_record", producer_ids=["agent.librechat.memory", "tool.memory"],
         audience="mem.agent_memory", delivery="memory upsert", becomes_context_source_ids=["ctx.memory_recall"],
         source_ref="packages/api memory", notes="Closes poisoning loop into ctx.memory_recall."),
]


def _S(step, ag=P):
    return {"agent_id": ag, "step": step, "external_trigger": None}


EDGES = [
    edge("edge.user__primary", "user",
         source={"agent_id": None, "step": "request", "external_trigger": "agents chat"},
         destination={"agent_id": P}, condition="user runs an agent chat",
         input_source_ids=["ctx.user_message", "ctx.system_prompt", "ctx.file_search_rag"],
         payload="user message + agent config", execution_mode="synchronous", failure_behavior="abort",
         related_l1_ids=["l1.api.agents.chat"], related_l2_steps=[{"l2_id": "l2.agents.chat", "order": 1}],
         source_ref="agents endpoint; createRunBody.js"),

    edge("edge.primary__tool", "llm", source=_S("tool-node"),
         destination={"tool_binding_id": "(model-selected binding)"},
         condition="LangGraph model node emits a tool call",
         argument_sources="model-composed args (structured tools)",
         input_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.file_search_rag", "ctx.tool_results",
                          "ctx.web_content", "ctx.memory_recall", "ctx.tool_descriptions"],
         payload="tool name + args", output_ids=["ctx.tool_results"],
         control_ids=["ctl.agent_capabilities", "ctl.tool_role_grants", "ctl.code_sandbox", "ctl.mcp_oauth",
                     "ctl.action_auth"],
         validation_or_approval="capability gate + role grants + per-tool auth (NO interactive per-call approval)",
         execution_mode="synchronous", loop_bound="graph recursionLimit",
         failure_behavior="retry", related_l2_steps=[{"l2_id": "l2.agents.chat", "order": 2}],
         source_ref="Runs/StreamRunManager.js; @librechat/agents graph",
         notes="Tool use gated by capability + auth, but no interactive human approval per call."),

    edge("edge.tool__primary", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": P}, condition="tool returns", payload="tool result",
         output_ids=["ctx.tool_results"], execution_mode="synchronous", failure_behavior="retry",
         related_l2_steps=[{"l2_id": "l2.agents.chat", "order": 3}], source_ref="RunManager"),

    edge("edge.primary__subagent", "llm", source=_S("delegate"),
         destination={"agent_id": "agent.librechat.subagent"}, condition="agent delegates (chain capability)",
         argument_sources="model-composed task", input_source_ids=["ctx.user_message", "ctx.chat_history"],
         payload="delegated task", output_ids=["ctx.delegated_task"], control_ids=["ctl.subagent_routing"],
         execution_mode="background", loop_bound="routing nesting bound", failure_behavior="partial_effect",
         related_l1_ids=["l1.internal.subagent"], source_ref="subagentTaskRouting.ts",
         notes="subagentIdentity captured; parent->child task injection path."),

    edge("edge.subagent__primary", "deterministic_code",
         source={"agent_id": "agent.librechat.subagent", "step": "result", "external_trigger": None},
         destination={"agent_id": P, "output_sink_id": "sink.delegated_result"}, condition="sub-agent completes",
         payload="sub-agent content", output_ids=["sink.delegated_result", "ctx.tool_results"],
         execution_mode="callback", failure_behavior="partial_effect", source_ref="subagentDelivery.ts"),

    edge("edge.primary__external", "llm", source=_S("external-tool"),
         destination={"tool_binding_id": "tool.mcp", "external_surface": "MCP / OpenAPI action domains"},
         condition="agent calls MCP / Action", argument_sources="model-composed args",
         payload="operation + args", output_ids=["sink.mcp_call", "sink.action_call", "ctx.tool_results"],
         control_ids=["ctl.mcp_oauth", "ctl.action_auth"], execution_mode="synchronous", failure_behavior="fail_closed",
         source_ref="Tools/mcp.js; processActions",
         notes="MCP under per-user OBO; Actions under stored action auth. No MCP sampling edge observed."),

    edge("edge.primary__code", "llm", source=_S("code"),
         destination={"tool_binding_id": "tool.execute_code", "external_surface": "Code Interpreter API"},
         condition="agent calls execute_code", argument_sources="model-composed code",
         payload="code", output_ids=["sink.code_exec", "ctx.tool_results"], control_ids=["ctl.code_sandbox"],
         execution_mode="synchronous", failure_behavior="abort", source_ref="code/agent.ts"),

    edge("edge.memory_extract", "llm", source=_S("post-turn", "agent.librechat.memory"),
         destination={"agent_id": "agent.librechat.memory", "output_sink_id": "sink.memory_write"},
         condition="post-turn memory processing (memory capability)",
         input_source_ids=["ctx.user_message", "ctx.chat_history"], argument_sources="turn content -> memory ops",
         payload="memory updates", output_ids=["sink.memory_write", "mem.agent_memory"], execution_mode="background",
         failure_behavior="abort", source_ref="packages/api memory processing",
         notes="Turn-derived memory write; poisoning persistence edge."),

    edge("edge.primary__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.chat_response"}, condition="agent run completes",
         payload="final markdown (+ artifacts)", output_ids=["sink.chat_response"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="StreamRunManager finalize",
         related_l2_steps=[{"l2_id": "l2.agents.chat", "order": 4}]),
]

_all = [P, "agent.librechat.subagent", "agent.librechat.memory"]
CONTROLS = [
    ctl("ctl.agent_capabilities", "tool_policy", "before_tool", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="ToolService resolveAgentCapabilities; librechat.yaml endpoints.agents.capabilities",
        notes="Admin enables capability classes (execute_code/file_search/web_search/actions/tools/artifacts/"
              "ocr/context/memory/chain); a disabled capability's tools are never loaded."),

    ctl("ctl.tool_role_grants", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="ToolService resolveToolRoleGrants",
        notes="Per-role grants decide which tools a user/agent may load."),

    ctl("ctl.code_sandbox", "tool_policy", "before_tool", "blocking", "external_service",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.librechat.subagent"],
        applies_to_tool_binding_ids=["tool.execute_code"],
        source_ref="LibreChat Code Interpreter API (remote sandbox)",
        notes="Code runs in the remote Code API sandbox, not in the app process."),

    ctl("ctl.mcp_oauth", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.librechat.subagent"],
        applies_to_tool_binding_ids=["tool.mcp"],
        source_ref="Tools/mcp.js AuthIdentityContext / OBO; getUserConnection; loadUserMCPAuthMap",
        notes="MCP calls use the REAL request user's OAuth identity (per-user), not a shared credential."),

    ctl("ctl.action_auth", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.librechat.subagent"],
        applies_to_tool_binding_ids=["tool.actions"],
        source_ref="ToolService processActions; action set auth (encrypted apiKey/OAuth)",
        notes="Each action set carries its own stored auth and domain scope."),

    ctl("ctl.subagent_routing", "tool_policy", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P],
        applies_to_tool_binding_ids=["tool.subagent"],
        source_ref="packages/api/src/agents/subagentTaskRouting.ts",
        notes="Routes/bounds delegation to allowed sub-agents."),

    ctl("ctl.abort", "monitoring", "after_model", "blocking", "code",
        failure_mode="abort", applies_to_agent_ids=_all, source_ref="run abort/cancel",
        notes="User can cancel the run; no interactive per-tool approval gate."),
]
