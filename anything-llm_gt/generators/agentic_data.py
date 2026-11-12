# -*- coding: utf-8 -*-
"""AnythingLLM agentic attack-surface data (schema: agentic-attack-surface-v1).

App: anything-llm (Mintplex-Labs). Agent runtime = AIbitat
(server/utils/agents/aibitat/index.js): a graph of agents (USER human-monitor +
@agent workspace agent) running a provider tool-call loop over "skills"
(aibitat/plugins/*), community IMPORTED plugins (docker-run custom code),
Agent Flows, and MCP servers. Entry = AgentHandler (utils/agents/index.js),
invoked by the `@agent` prefix over the websocket chat and the developer API.

Key authority note: external skills (gmail/outlook/gcal/sql/mcp/imported) act
under INSTANCE-level stored credentials, not the invoking user's -> any user who
can reach @agent wields the instance's connected accounts (confused deputy).

Static pass (evidence_status: source_confirmed). Runtime grounding pending.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

A = "agent.anythingllm.workspace"

# ===========================================================================
# AGENTS
# ===========================================================================
AGENTS = [
    agent(
        A, "Workspace agent (@agent)", "anything-llm", "interactive",
        "Primary agent for a workspace; runs the AIbitat tool-call loop over enabled "
        "skills, imported plugins, agent flows, and MCP servers.",
        invocation_surfaces=[
            {"l1_id": "l1.ws.agent_invocation", "trigger": "`@agent` prefix in a workspace chat (websocket agent session)",
             "auth_context": "workspace membership; multi-user role (admin|manager|default)"},
            {"l1_id": "l1.api.workspace_agent", "trigger": "developer API agent invocation / ephemeral agent",
             "auth_context": "API key"},
        ],
        model_config={"provider": "workspace agent provider (OpenAI/Anthropic/Ollama/Gemini/... tooled or untooled)",
                     "model": "workspace agent model", "config_source": "workspace + system settings (admin)",
                     "writers": [writer("admin", "l1.api.system_settings"), writer("workspace_manager", "l1.api.workspace.update")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[
            {"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
             "config_version": "runtime", "writers": [writer("workspace_manager", "l1.api.workspace.update")]},
            {"surface_id": "ctx.clarifying_note", "instruction_role": "system", "precedence": "appended",
             "config_version": "runtime", "writers": [writer("admin", "l1.api.system_settings")]},
        ],
        tool_binding_ids=[
            "tool.ws.memory", "tool.ws.rag_docs", "tool.ws.web_browsing", "tool.ws.web_scraping",
            "tool.ws.sql_agent", "tool.ws.filesystem", "tool.ws.create_files", "tool.ws.gmail",
            "tool.ws.outlook", "tool.ws.gcal", "tool.ws.generate_image", "tool.ws.rechart",
            "tool.ws.request_user_input", "tool.ws.scheduled_job", "tool.ws.imported_plugin",
            "tool.ws.agent_flow", "tool.ws.mcp",
        ],
        context_source_ids=[
            "ctx.system_prompt", "ctx.clarifying_note", "ctx.user_message", "ctx.chat_history",
            "ctx.rag_context", "ctx.tool_results", "ctx.web_content", "ctx.memory_recall",
            "ctx.tool_descriptions", "ctx.clarifying_input", "ctx.flow_variables",
        ],
        memory_ids=["mem.workspace_chats", "mem.embeddings", "mem.agent_memory", "mem.scheduled_jobs",
                    "mem.filesystem"],
        output_sink_ids=["sink.chat_response", "sink.email", "sink.calendar", "sink.files",
                         "sink.image", "sink.sql_write", "sink.external_call", "sink.scheduled_job"],
        control_ids=["ctl.user_oversight", "ctl.imported_tool_approval", "ctl.max_tool_calls",
                     "ctl.skill_enablement", "ctl.multiuser_skill_gate", "ctl.model_router_cooldown",
                     "ctl.abort"],
        resource_limits={"max_iterations": "AGENT_MAX_TOOL_CALLS (default cap) + maxRounds per response",
                        "recursion": "flows/sub-stages are bounded; no open agent self-spawn",
                        "token_or_cost_budget": "none in core", "loop_detection": "maxRounds boundary + abort",
                        "enforced_by": "code"},
        authority_context={"principal_source": "workspace user (session) or API key",
                         "tenant_scope": "workspace-scoped RAG/chats",
                         "resource_scope": "workspace documents + INSTANCE-level connected accounts",
                         "delegated_identity": "external skills use INSTANCE stored credentials, NOT the user's",
                         "authz_enforcement": "code (role + workspace membership); connected-account scope NOT per-user"},
        related_l2_ids=["l2.workspace.agent_chat"],
        source_ref="utils/agents/index.js AgentHandler; utils/agents/defaults.js WORKSPACE_AGENT; aibitat/index.js",
        notes="Skill set = DEFAULT_SKILLS (memory, docSummarizer, webScraping, webBrowsing) + admin-enabled "
              "skills + imported plugins + flows + MCP. ToolReranker may trim the exposed set.",
    ),
    agent(
        "agent.anythingllm.ephemeral", "Ephemeral agent", "anything-llm", "specialist",
        "Headless agent session used by the developer API, agent flows, and scheduled jobs; "
        "same loop without a live websocket user.",
        invocation_surfaces=[{"l1_id": "l1.api.ephemeral_agent", "trigger": "API / flow / scheduled-job runner",
                             "auth_context": "API key or system (scheduled)"}],
        model_config={"provider": "inherits workspace", "model": "workspace model", "config_source": "workspace/system",
                     "writers": [], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("workspace_manager", "l1.api.workspace.update")]}],
        tool_binding_ids=["tool.ws.rag_docs", "tool.ws.web_browsing", "tool.ws.web_scraping", "tool.ws.sql_agent",
                         "tool.ws.imported_plugin", "tool.ws.mcp"],
        context_source_ids=["ctx.system_prompt", "ctx.rag_context", "ctx.tool_results", "ctx.web_content",
                          "ctx.flow_variables"],
        memory_ids=["mem.workspace_chats", "mem.embeddings"],
        output_sink_ids=["sink.external_call", "sink.files", "sink.email"],
        control_ids=["ctl.max_tool_calls", "ctl.skill_enablement"],
        resource_limits={"max_iterations": "AGENT_MAX_TOOL_CALLS", "recursion": "bounded",
                        "token_or_cost_budget": "none", "loop_detection": "maxRounds", "enforced_by": "code"},
        authority_context={"principal_source": "API key / scheduler",
                         "tenant_scope": "workspace", "resource_scope": "workspace + instance accounts",
                         "delegated_identity": "instance credentials; no live human oversight (USER interrupt absent)",
                         "authz_enforcement": "code"},
        related_l2_ids=["l2.workspace.agent_chat"],
        source_ref="utils/agents/ephemeral.js; utils/agentFlows; create-scheduled-job",
        notes="No USER human-monitor in the loop -> ctl.user_oversight does not apply; higher autonomy.",
    ),
]

# ===========================================================================
# TOOL BINDINGS
# ===========================================================================
_inst_cred = {"identity": "instance connected-account", "credential_source": "system settings / skill setup_args (stored)"}
_ws_ident = {"identity": "workspace context", "credential_source": "workspace config"}
_argh = {"validation": "JSON-schema params per skill (draft-07)", "authorization": "skill enablement + role",
         "normalization": "provider tool-call parsing (tooled/untooled helpers)", "enforced_by": "code"}


def _env(sandbox, egress, fs, by="code"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


TOOLS = [
    tool("tool.ws.memory", A, "memory (agent memory skill)", "native", "write",
         capabilities=["store/recall workspace agent memories"], execution_identity=_ws_ident,
         output_ids=["mem.agent_memory", "ctx.memory_recall"],
         source_ref="aibitat/plugins/memory.js",
         notes="Default-enabled; agent-written memory re-injected into context (poisoning loop)."),

    tool("tool.ws.rag_docs", A, "doc summarizer / workspace RAG", "native", "read",
         l1_ids=["l1.api.workspace.vector_search"], capabilities=["search/summarize workspace documents"],
         execution_identity=_ws_ident, output_ids=["ctx.rag_context", "ctx.tool_results"],
         source_ref="aibitat/plugins/summarize.js; workspace vector search"),

    tool("tool.ws.web_browsing", A, "web-browsing (search)", "native", "external_send",
         capabilities=["web search via configured provider"],
         execution_identity={"identity": "server", "credential_source": "search provider API key (system settings)"},
         execution_environment=_env("in-process", "search provider", "none"),
         output_ids=["ctx.web_content", "ctx.tool_results"], source_ref="aibitat/plugins/web-browsing.js",
         notes="Default-enabled."),

    tool("tool.ws.web_scraping", A, "web-scraping (fetch URL)", "native", "external_send",
         capabilities=["fetch/scrape an arbitrary URL"],
         execution_identity={"identity": "server HTTP client", "credential_source": "none"},
         execution_environment=_env("in-process (CollectorApi)", "unrestricted (arbitrary URL = SSRF)", "none"),
         output_ids=["ctx.web_content", "ctx.tool_results"], source_ref="aibitat/plugins/web-scraping.js",
         notes="Default-enabled; model-composed URL, no host allowlist -> SSRF surface."),

    tool("tool.ws.sql_agent", A, "sql-agent", "native", "mixed",
         l1_ids=["l1.api.sql_connection"], capabilities=["list DBs/tables, read schema, run SQL against configured connectors"],
         server_or_provider="configured SQL connectors (Postgres/MySQL/MSSQL)",
         execution_identity={"identity": "configured DB connection", "credential_source": "SQL connector config (stored)"},
         execution_environment=_env("remote DB", "DB host", "n/a", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "sink.sql_write"],
         control_ids=["ctl.user_oversight"],
         source_ref="aibitat/plugins/sql-agent/*",
         notes="Model-composed SQL against instance DB creds; DML possible -> write/exfil."),

    tool("tool.ws.filesystem", A, "filesystem-agent", "native", "mixed",
         capabilities=["read/write/edit/move/copy/search files in the agent storage dir"],
         execution_identity={"identity": "server process", "credential_source": "none"},
         execution_environment=_env("server FS (agent storage dir)", "none", "agent storage directory", by="code"),
         output_ids=["mem.filesystem", "ctx.tool_results"], control_ids=["ctl.user_oversight"],
         source_ref="aibitat/plugins/filesystem/*; isToolAvailable env gate",
         reachability=reach("conditionally_mounted", "filesystem skill enabled + isToolAvailable()")),

    tool("tool.ws.create_files", A, "create-files-agent", "native", "write",
         capabilities=["generate docx/pdf/pptx/xlsx/text files (pptx uses an LLM section-agent)"],
         execution_identity={"identity": "server process", "credential_source": "none"},
         output_ids=["sink.files", "ctx.tool_results"],
         source_ref="aibitat/plugins/create-files/*",
         reachability=reach("conditionally_mounted", "create-files skill enabled + isToolAvailable()"),
         notes="pptx section-agent is a nested LLM call (sub-generation)."),

    tool("tool.ws.gmail", A, "gmail-agent", "native", "external_send",
         capabilities=["search/read/draft/send email; manage threads/labels"],
         server_or_provider="Gmail API", execution_identity=_inst_cred,
         execution_environment=_env("remote", "Google APIs", "n/a", by="external_service"),
         output_ids=["sink.email", "ctx.tool_results"], control_ids=["ctl.user_oversight"],
         source_ref="aibitat/plugins/gmail/*; GmailBridge",
         reachability=reach("conditionally_mounted", "gmail skill enabled + OAuth connected"),
         notes="Send-email acts under INSTANCE OAuth identity -> confused deputy for any @agent user."),

    tool("tool.ws.outlook", A, "outlook-agent", "native", "external_send",
         capabilities=["search/read/draft/send Outlook email"], server_or_provider="Microsoft Graph",
         execution_identity=_inst_cred, output_ids=["sink.email", "ctx.tool_results"],
         control_ids=["ctl.user_oversight"], source_ref="aibitat/plugins/outlook/*",
         reachability=reach("conditionally_mounted", "outlook skill enabled + OAuth connected")),

    tool("tool.ws.gcal", A, "google-calendar-agent", "native", "write",
         capabilities=["list/create/update/delete calendar events"], server_or_provider="Google Calendar API",
         execution_identity=_inst_cred, output_ids=["sink.calendar", "ctx.tool_results"],
         control_ids=["ctl.user_oversight"], source_ref="aibitat/plugins/google-calendar/*",
         reachability=reach("conditionally_mounted", "gcal skill enabled + OAuth connected")),

    tool("tool.ws.generate_image", A, "generate-image", "native", "external_send",
         capabilities=["image generation via provider"], execution_identity=_inst_cred,
         output_ids=["sink.image", "ctx.tool_results"], source_ref="aibitat/plugins/generate-image.js",
         reachability=reach("conditionally_mounted", "skill enabled")),

    tool("tool.ws.rechart", A, "rechart", "native", "none",
         capabilities=["render chart config returned to UI"], execution_identity=_ws_ident,
         output_ids=["ctx.tool_results"], source_ref="aibitat/plugins/rechart.js"),

    tool("tool.ws.request_user_input", A, "request-user-input", "native", "none",
         capabilities=["ask the user clarifying questions (survey card)"], execution_identity=_ws_ident,
         output_ids=["ctx.clarifying_input"], approval_required=True,
         source_ref="aibitat/plugins/request-user-input.js",
         reachability=reach("conditionally_mounted", "agent_clarifying_questions_enabled"),
         notes="HITL input primitive."),

    tool("tool.ws.scheduled_job", A, "create-scheduled-job", "native", "write",
         capabilities=["create a cron-scheduled agent job"], execution_identity=_ws_ident,
         output_ids=["mem.scheduled_jobs"], control_ids=["ctl.multiuser_skill_gate", "ctl.user_oversight"],
         source_ref="aibitat/plugins/create-scheduled-job/*",
         reachability=reach("conditionally_mounted", "single-user mode only (SINGLE_USER_ONLY_SKILLS)"),
         notes="Persistent scheduled re-invocation; blocked in multi-user mode."),

    tool("tool.ws.imported_plugin", A, "imported community plugin", "plugin", "code_execution",
         l1_ids=["l1.api.agent_skill.import"], capabilities=["admin-imported community skill (custom handler.js)"],
         description_source={"source_ref": "plugin.json description (imported)",
                           "writers": [writer("admin", "l1.api.agent_skill.import"), writer("external_service", None)]},
         execution_identity={"identity": "plugin (docker runtime)", "credential_source": "skill setup_args (stored secrets)"},
         execution_environment=_env("docker runtime", "per plugin", "plugin workspace", by="platform_config"),
         output_ids=["ctx.tool_results", "sink.external_call"], control_ids=["ctl.imported_tool_approval"],
         source_ref="utils/agents/imported.js (runtime: 'docker'; handler.js)",
         reachability=reach("conditionally_mounted", "community skill imported + enabled"),
         notes="Runs imported custom code; description is model-facing + import-controlled -> rug-pull + RCE class. "
               "requestToolApproval available for HITL."),

    tool("tool.ws.agent_flow", A, "agent flow", "native", "mixed",
         capabilities=["run an admin-authored no-code Agent Flow (API calls, LLM blocks, variables)"],
         description_source={"source_ref": "flow definition name/description",
                           "writers": [writer("admin", "l1.api.agent_flows.save")]},
         execution_identity={"identity": "flow-defined", "credential_source": "flow config"},
         output_ids=["ctx.flow_variables", "ctx.tool_results", "sink.external_call"],
         source_ref="utils/agentFlows; AgentFlows.activeFlowPlugins",
         reachability=reach("conditionally_mounted", "flow created + active")),

    tool("tool.ws.mcp", A, "MCP server tools", "mcp", "mixed",
         capabilities=["call tools from configured MCP servers"], server_or_provider="configured MCP server(s)",
         description_source={"source_ref": "MCP listTools result (remote)",
                           "writers": [writer("external_service", None), writer("admin", "l1.api.mcp_servers.config")]},
         execution_identity={"identity": "MCP identity (withMCPIdentity)", "credential_source": "MCP server config"},
         execution_environment=_env("remote MCP server", "per server", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "sink.external_call"],
         source_ref="utils/MCP/index.js MCPCompatibilityLayer (listTools/callTool)",
         reachability=reach("conditionally_mounted", "MCP server configured + tool not suppressed"),
         notes="MCP compat layer exposes TOOLS only (callTool) -> no resources/prompts/sampling channel."),
]

# ===========================================================================
# CONTEXT SOURCES
# ===========================================================================
_dest = ["agent.anythingllm.workspace"]
_dest_both = ["agent.anythingllm.workspace", "agent.anythingllm.ephemeral"]

CONTEXT = [
    ctx("ctx.system_prompt", "system_prompt", "trusted_instruction",
        source_ref="Provider.systemPrompt(workspace) -> workspace.openAiPrompt",
        writers=[writer("workspace_manager", "l1.api.workspace.update"), writer("admin", "l1.api.system_settings")],
        destination_agent_ids=_dest_both, destination_channel="system", provenance="workspace config",
        persistence_scope="tenant",
        notes="Workspace system prompt is editable by workspace managers -> user-tier control of a trusted channel."),

    ctx("ctx.clarifying_note", "system_prompt", "trusted_instruction",
        source_ref="defaults.js appended clarifying-questions instruction",
        writers=[writer("source_code", None)], destination_agent_ids=_dest, destination_channel="system",
        provenance="app", persistence_scope="global"),

    ctx("ctx.user_message", "user_input", "untrusted_data", source_ref="workspace chat message",
        writers=[writer("workspace_user", "l1.ws.agent_invocation")], destination_agent_ids=_dest,
        destination_channel="user", provenance="end user", persistence_scope="session"),

    ctx("ctx.chat_history", "chat_history", "mixed", source_ref="aibitat/plugins/chat-history.js -> workspace_chats",
        writers=[writer("workspace_user", "l1.ws.agent_invocation"), writer(A, None)],
        destination_agent_ids=_dest, destination_channel="user", provenance="prior turns",
        persistence_scope="session"),

    ctx("ctx.rag_context", "retrieval", "untrusted_data",
        source_ref="workspace vector similaritySearch + pinned docs injected into systemPrompt context",
        writers=[writer("workspace_user", "l1.api.document.upload"), writer("workspace_manager", "l1.api.workspace.embed")],
        destination_agent_ids=_dest_both, destination_channel="system", provenance="workspace documents",
        persistence_scope="tenant", related_l2_ids=["l2.workspace.agent_chat"],
        notes="Uploaded document text injected -> indirect prompt injection; workspace-shared docs cross users."),

    ctx("ctx.tool_results", "tool_result", "untrusted_data", source_ref="aibitat function handler returns",
        writers=[writer(A, None), writer("external_service", None)], destination_agent_ids=_dest_both,
        destination_channel="tool", provenance="skill/plugin/MCP output", persistence_scope="session"),

    ctx("ctx.web_content", "external", "untrusted_data", source_ref="web-scraping/web-browsing results",
        writers=[writer("external_service", None)], destination_agent_ids=_dest_both, destination_channel="tool",
        provenance="arbitrary web", persistence_scope="session",
        notes="Attacker web content via scraping -> indirect injection + SSRF reflection."),

    ctx("ctx.memory_recall", "retrieval", "untrusted_data", source_ref="aibitat/plugins/memory.js rerank",
        writers=[writer(A, None), writer("workspace_user", "l1.ws.agent_invocation")],
        destination_agent_ids=_dest, destination_channel="system", provenance="prior agent memories",
        persistence_scope="tenant", notes="Agent-written memory re-injected -> poisoning persistence."),

    ctx("ctx.tool_descriptions", "external", "untrusted_data",
        source_ref="skill/imported/MCP tool descriptions presented to the LLM",
        writers=[writer("admin", "l1.api.agent_skill.import"), writer("external_service", None)],
        destination_agent_ids=_dest_both, destination_channel="tool", provenance="skill authors / remote specs",
        persistence_scope="global",
        notes="Imported-plugin + MCP descriptions are model-facing -> rug-pull / description injection."),

    ctx("ctx.clarifying_input", "user_input", "untrusted_data", source_ref="request-user-input survey result",
        writers=[writer("workspace_user", "l1.ws.clarify_response")], destination_agent_ids=_dest,
        destination_channel="user", provenance="user survey answers", persistence_scope="session"),

    ctx("ctx.flow_variables", "delegated_summary", "mixed", source_ref="agent flow variables/blocks",
        writers=[writer("admin", "l1.api.agent_flows.save"), writer("external_service", None)],
        destination_agent_ids=_dest_both, destination_channel="developer", provenance="flow definition + block outputs",
        persistence_scope="workflow",
        reachability=reach("conditionally_mounted", "a flow is active")),
]

# ===========================================================================
# MEMORY STORES
# ===========================================================================
MEMORY = [
    mem("mem.workspace_chats", "conversation_history", "anything-llm", "tenant",
        readers=[A, "agent.anythingllm.ephemeral"],
        writers=[writer("workspace_user", "l1.ws.agent_invocation"), writer(A, None)],
        isolation_enforcement="workspace_id + user scoping in repository queries",
        write_provenance="user turns + agent responses (chat-history plugin)",
        read_path="prior workspace_chats replayed into context",
        retention_and_deletion="workspace-managed", source_ref="models/workspaceChats; chat-history.js"),

    mem("mem.embeddings", "vector_store", "anything-llm", "tenant",
        readers=[A, "agent.anythingllm.ephemeral"],
        writers=[writer("workspace_user", "l1.api.document.upload"), writer("workspace_manager", "l1.api.workspace.embed")],
        isolation_enforcement="per-workspace vector namespace; shared docs by workspace",
        write_provenance="uploaded/embedded documents", read_path="similaritySearch -> context injection",
        retention_and_deletion="document lifecycle", source_ref="vectorDb providers; EmbedChunks",
        notes="Workspace-shared document store = cross-user injection/read surface within a workspace."),

    mem("mem.agent_memory", "agent_notes", "anything-llm", "tenant",
        readers=[A], writers=[writer(A, None), writer("workspace_user", "l1.ws.agent_invocation")],
        isolation_enforcement="workspace-scoped memory", write_provenance="the agent's memory skill (turn-derived) + user",
        read_path="reranked memories injected into context",
        retention_and_deletion="workspace-managed", source_ref="aibitat/plugins/memory.js",
        notes="Memory-poisoning sink; re-read each turn."),

    mem("mem.scheduled_jobs", "database", "anything-llm", "tenant",
        readers=["agent.anythingllm.ephemeral"], writers=[writer(A, None), writer("workspace_user", "l1.api.scheduled_job.create")],
        isolation_enforcement="single-user mode only", write_provenance="scheduled-job skill",
        read_path="scheduler triggers ephemeral agent runs", retention_and_deletion="user-managed",
        source_ref="create-scheduled-job; models/agentSchedule",
        reachability=reach("conditionally_mounted", "single-user mode"),
        notes="Durable re-invocation / foothold."),

    mem("mem.filesystem", "database", "anything-llm", "tenant",
        readers=[A], writers=[writer(A, None)], isolation_enforcement="agent storage directory",
        write_provenance="filesystem-agent", read_path="filesystem read tools",
        retention_and_deletion="storage lifecycle", source_ref="aibitat/plugins/filesystem/*",
        reachability=reach("conditionally_mounted", "filesystem skill available")),
]

# ===========================================================================
# OUTPUT SINKS
# ===========================================================================
_md = {"auto_fetch": "chat UI renders markdown incl. images/links", "active_content": "sanitized client-side",
       "enforced_by": "code"}
SINKS = [
    sink("sink.chat_response", "chat_response", producer_ids=[A, "agent.anythingllm.ephemeral"],
         audience="workspace user (chat UI)", delivery="streamed markdown over websocket",
         render_side_effects=_md, related_l2_ids=["l2.workspace.agent_chat"],
         source_ref="aibitat websocket plugin; chat-history finalize",
         notes="Model-authored markdown image/link = exfil-on-render channel."),

    sink("sink.email", "email", producer_ids=["tool.ws.gmail", "tool.ws.outlook"],
         audience="arbitrary recipients", delivery="Gmail / MS Graph send under instance OAuth",
         source_ref="gmail/outlook send plugins",
         notes="Model-composed email sent from the instance's connected mailbox."),

    sink("sink.calendar", "external_api", producer_ids=["tool.ws.gcal"], audience="Google Calendar",
         delivery="Calendar API write", source_ref="google-calendar plugin"),

    sink("sink.files", "file", producer_ids=["tool.ws.create_files", "tool.ws.filesystem"],
         audience="agent storage / download", delivery="file write to storage dir",
         becomes_context_source_ids=["ctx.tool_results"], source_ref="create-files; filesystem write",
         notes="Written files can be re-read by filesystem tools (feedback loop)."),

    sink("sink.image", "external_api", producer_ids=["tool.ws.generate_image"], audience="image provider",
         delivery="provider API", source_ref="generate-image plugin"),

    sink("sink.sql_write", "database_record", producer_ids=["tool.ws.sql_agent"], audience="configured DB",
         delivery="SQL executed against connector (DML if permitted)", source_ref="sql-agent query",
         notes="Model-composed SQL under instance DB creds."),

    sink("sink.external_call", "external_api",
         producer_ids=["tool.ws.imported_plugin", "tool.ws.mcp", "tool.ws.agent_flow"],
         audience="external services / MCP / flow endpoints", delivery="HTTP/MCP/docker-plugin calls with model args",
         source_ref="imported.js; MCP; agentFlows",
         notes="Model-composed args leave under stored credentials / docker plugin."),

    sink("sink.scheduled_job", "database_record", producer_ids=["tool.ws.scheduled_job"],
         audience="scheduler", delivery="persisted cron job", becomes_context_source_ids=["ctx.flow_variables"],
         source_ref="create-scheduled-job",
         reachability=reach("conditionally_mounted", "single-user mode")),
]

# ===========================================================================
# EXECUTION EDGES
# ===========================================================================
def _S(step, ag=A):
    return {"agent_id": ag, "step": step, "external_trigger": None}


EDGES = [
    edge("edge.user__workspace", "user",
         source={"agent_id": None, "step": "request", "external_trigger": "websocket @agent / API"},
         destination={"agent_id": A}, condition="user sends `@agent ...` in a workspace chat",
         input_source_ids=["ctx.user_message", "ctx.system_prompt", "ctx.rag_context"],
         payload="user message + workspace context", execution_mode="synchronous", failure_behavior="abort",
         related_l1_ids=["l1.ws.agent_invocation"],
         related_l2_steps=[{"l2_id": "l2.workspace.agent_chat", "order": 1}],
         source_ref="utils/agents/index.js isAgentInvocation"),

    edge("edge.workspace__tool", "llm", source=_S("tool-call"),
         destination={"tool_binding_id": "(model-selected binding)"}, condition="model emits a tool call",
         argument_sources="provider tool-call parsing (tooled) or regex extraction (untooled)",
         input_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.rag_context", "ctx.tool_results",
                          "ctx.web_content", "ctx.memory_recall", "ctx.tool_descriptions"],
         payload="function name + args", output_ids=["ctx.tool_results"],
         control_ids=["ctl.max_tool_calls", "ctl.user_oversight", "ctl.skill_enablement"],
         validation_or_approval="ToolReranker selects subset; USER interrupt / imported approval before side effects",
         execution_mode="synchronous", loop_bound="AGENT_MAX_TOOL_CALLS / maxRounds",
         failure_behavior="retry", related_l2_steps=[{"l2_id": "l2.workspace.agent_chat", "order": 2}],
         source_ref="aibitat/index.js handleExecution",
         notes="Tool selection + arg composition model-directed -> primary injection->action edge."),

    edge("edge.tool__workspace", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": A}, condition="tool returns", payload="tool result (+citations/attachments)",
         output_ids=["ctx.tool_results"], execution_mode="synchronous", failure_behavior="retry",
         related_l2_steps=[{"l2_id": "l2.workspace.agent_chat", "order": 3}],
         source_ref="aibitat/index.js result handling"),

    edge("edge.user_oversight", "human_reviewer", source=_S("oversight"),
         destination={"agent_id": A}, condition="USER agent interrupt=ALWAYS (human monitor in the graph)",
         control_ids=["ctl.user_oversight"], payload="approve/guide", execution_mode="callback",
         failure_behavior="fail_closed", source_ref="defaults.js USER_AGENT interrupt ALWAYS",
         notes="Present only for interactive @agent sessions, NOT ephemeral/API/scheduled runs."),

    edge("edge.workspace__imported", "llm", source=_S("imported"),
         destination={"tool_binding_id": "tool.ws.imported_plugin", "external_surface": "docker plugin runtime"},
         condition="model calls an imported community skill", argument_sources="model-composed args",
         payload="plugin args", output_ids=["sink.external_call", "ctx.tool_results"],
         control_ids=["ctl.imported_tool_approval"], execution_mode="synchronous", failure_behavior="fail_closed",
         source_ref="utils/agents/imported.js",
         notes="Executes imported custom handler.js in a docker runtime."),

    edge("edge.workspace__external", "llm", source=_S("external"),
         destination={"tool_binding_id": "tool.ws.mcp", "external_surface": "MCP / connected accounts"},
         condition="model calls MCP / gmail / sql / flow", argument_sources="model-composed args",
         payload="operation + args", output_ids=["sink.external_call", "ctx.tool_results"],
         control_ids=["ctl.user_oversight"], execution_mode="synchronous", failure_behavior="fail_closed",
         source_ref="MCP/index.js; gmail/sql plugins",
         notes="Acts under INSTANCE credentials; no MCP sampling edge (compat layer = tools only)."),

    edge("edge.scheduled__ephemeral", "scheduler",
         source={"agent_id": None, "step": "cron", "external_trigger": "agent schedule"},
         destination={"agent_id": "agent.anythingllm.ephemeral"}, condition="scheduled job fires",
         payload="job prompt/context", output_ids=["sink.external_call"], execution_mode="queued",
         failure_behavior="abort", source_ref="create-scheduled-job runner",
         reachability=reach("conditionally_mounted", "single-user mode; a job exists"),
         notes="Autonomous re-invocation without human oversight."),

    edge("edge.workspace__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.chat_response"}, condition="agent produces final answer",
         payload="final markdown response", output_ids=["sink.chat_response"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="aibitat websocket finalize",
         related_l2_steps=[{"l2_id": "l2.workspace.agent_chat", "order": 4}]),
]

# ===========================================================================
# CONTROLS
# ===========================================================================
_both = ["agent.anythingllm.workspace", "agent.anythingllm.ephemeral"]
CONTROLS = [
    ctl("ctl.user_oversight", "human_approval", "before_tool", "blocking", "human_process",
        failure_mode="fail_closed", applies_to_agent_ids=["agent.anythingllm.workspace"],
        source_ref="defaults.js USER_AGENT (interrupt: ALWAYS) in the aibitat graph",
        notes="Human monitor can interrupt/approve agent turns in interactive sessions. Does NOT apply to "
              "ephemeral/API/scheduled runs -> those are unsupervised."),

    ctl("ctl.imported_tool_approval", "human_approval", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_both,
        applies_to_tool_binding_ids=["tool.ws.imported_plugin"],
        source_ref="utils/agents/imported.js createToolApprovalFn / requestToolApproval",
        notes="Imported plugins can request explicit tool approval before running."),

    ctl("ctl.max_tool_calls", "rate_limit", "before_tool", "blocking", "code",
        failure_mode="abort", applies_to_agent_ids=_both,
        source_ref="aibitat/index.js defaultMaxToolCalls (AGENT_MAX_TOOL_CALLS) + maxRounds",
        notes="Caps tool-call chaining per response -> bounds runaway loops/cost."),

    ctl("ctl.skill_enablement", "tool_policy", "before_tool", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=_both,
        source_ref="defaults.js agentSkillsFromSystemSettings (default_agent_skills / disabled_agent_skills)",
        notes="Admin decides which skills are mounted; disabled skills never reach the LLM."),

    ctl("ctl.multiuser_skill_gate", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_both,
        applies_to_tool_binding_ids=["tool.ws.scheduled_job"],
        source_ref="defaults.js SINGLE_USER_ONLY_SKILLS (create-scheduled-job blocked in multi-user)",
        notes="Certain skills are suppressed in multi-user mode."),

    ctl("ctl.model_router_cooldown", "rate_limit", "before_model", "modifying", "code",
        failure_mode="fallback", applies_to_agent_ids=_both,
        source_ref="aibitat/plugins/model-router-cooldown.js",
        notes="Provider cooldown/fallback on rate limits."),

    ctl("ctl.abort", "monitoring", "after_model", "blocking", "code",
        failure_mode="abort", applies_to_agent_ids=_both,
        source_ref="aibitat/index.js AbortController / _aborted (stop, socket close, bail)",
        notes="Checked at loop boundaries; stops further LLM/tool turns."),
]
