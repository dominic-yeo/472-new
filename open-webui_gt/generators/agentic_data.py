# -*- coding: utf-8 -*-
"""Open WebUI agentic attack-surface data (schema: agentic-attack-surface-v1).

App: open-webui v0.13.3 (git b0e6098, 2026-11-09). Agent runtime = native
function-calling loop in backend/open_webui/utils/middleware.py over a tool
registry assembled by utils/tools.py (builtin:, workspace Python tools, OpenAPI
tool servers `server:`, MCP, terminal/ACP). Sub-agents via utils/subagents.py.
Controls: utils/tool_approval.py, utils/tool_permissions.py, utils/filter.py.

Granularity: the ~60 builtin functions are grouped into capability bindings by
effect_class; security-critical tools (execute_code, fetch_url, create_tool,
create_skill, delegate_task, external tool servers, MCP, terminal) are kept
distinct. See annotation_issues.yaml.

Static pass only (evidence_status: source_confirmed). Runtime grounding (Phase E)
not yet done; reachability of feature-gated tools = conditionally_mounted.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

SRC = "open-webui@0.13.3"

# ===========================================================================
# AGENTS
# ===========================================================================
AGENTS = [
    agent(
        "agent.openwebui.primary", "Primary chat agent", "open-webui",
        "interactive",
        "User-facing assistant that runs a native tool-calling loop over the "
        "selected model and the enabled builtin/workspace/MCP/terminal tools.",
        invocation_surfaces=[
            {"l1_id": "l1.api.chat.completions", "trigger": "POST /api/chat/completions (and /api/.../completions)",
             "auth_context": "session JWT or API key -> UserModel"},
            {"l1_id": "l1.api.chat.completed", "trigger": "resume after tool-call approval (/api/chat/completed, tool resolve)",
             "auth_context": "same user; write access to chat"},
        ],
        model_config={"provider": "configurable (OpenAI-compatible / Ollama / Azure / Anthropic via pipelines)",
                      "model": "per-chat model_id", "deployment": "self-hosted",
                      "config_source": "Models workspace + connection config (admin)",
                      "writers": [writer("admin", "l1.api.models.config"),
                                  writer("user", "l1.api.chats.params")],
                      "evidence_status": "source_confirmed"},
        instruction_sources=[
            {"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
             "config_version": "runtime", "writers": [writer("user", "l1.api.users.settings"),
                                                       writer("admin", "l1.api.configs.default_settings")]},
            {"surface_id": "ctx.tool_approval_policy", "instruction_role": "system", "precedence": "appended",
             "config_version": "runtime", "writers": [writer("admin", "l1.api.configs.tool_permissions")]},
            {"surface_id": "ctx.skill_instructions", "instruction_role": "developer", "precedence": "injected",
             "config_version": "runtime", "writers": [writer("user", "l1.api.skills.update"),
                                                       writer("admin", "l1.api.skills.update")]},
        ],
        tool_binding_ids=[
            "tool.primary.code_interpreter", "tool.primary.web", "tool.primary.image",
            "tool.primary.memory", "tool.primary.knowledge_rag", "tool.primary.files",
            "tool.primary.notes", "tool.primary.chats", "tool.primary.channels",
            "tool.primary.calendar", "tool.primary.automations", "tool.primary.notify",
            "tool.primary.tasks", "tool.primary.skills", "tool.primary.create_skill",
            "tool.primary.create_tool", "tool.primary.subagents", "tool.primary.ask_user",
            "tool.primary.workspace_python", "tool.primary.tool_server", "tool.primary.mcp",
            "tool.primary.terminal",
        ],
        context_source_ids=[
            "ctx.system_prompt", "ctx.user_message", "ctx.chat_history", "ctx.rag_knowledge",
            "ctx.tool_results", "ctx.web_content", "ctx.memory_recall", "ctx.files_attached",
            "ctx.skill_instructions", "ctx.tool_descriptions", "ctx.terminal_system_prompt",
            "ctx.tool_approval_policy", "ctx.mcp_resource",
        ],
        memory_ids=["mem.memories", "mem.chat_history", "mem.knowledge_vector", "mem.notes",
                    "mem.skills", "mem.tasks", "mem.automations"],
        output_sink_ids=["sink.chat_stream", "sink.notify", "sink.image_gen",
                         "sink.external_tool_call", "sink.code_exec", "sink.terminal"],
        control_ids=["ctl.tool_approval", "ctl.tool_permissions_auto", "ctl.tool_permission_rbac",
                     "ctl.pipeline_inlet_filter", "ctl.pipeline_outlet_filter", "ctl.function_filters",
                     "ctl.arg_validation", "ctl.tool_repetition_guard", "ctl.untrusted_data_prompt"],
        resource_limits={"max_iterations": "model-driven loop; per-request, no hard global cap found "
                         "(tool_repetition_guard stops 2x-failed repeats only)",
                         "recursion": "sub-agents cannot spawn sub-agents (internal request strips delegate_task)",
                         "token_or_cost_budget": "none in core (provider-side only)",
                         "loop_detection": "tool_repetition_error (name+args, 2 consecutive failures)",
                         "enforced_by": "code"},
        authority_context={"principal_source": "session JWT / API key -> UserModel",
                          "tenant_scope": "single-tenant; per-user isolation",
                          "resource_scope": "user's own chats/files/memories unless shared KB/model",
                          "delegated_identity": "builtin tools act AS the user via extra_params.__user__",
                          "authz_enforcement": "code (has_permission over user.permissions + RBAC groups)"},
        related_l2_ids=["l2.chat.completion"],
        source_ref="utils/middleware.py:process_chat_payload/process_chat_response; utils/tools.py:get_tools/get_builtin_tools",
        notes="Builtin tool set is gated by (global config) AND (model capability meta) AND (per-user "
              "permission) AND (feature flag) -- most tools are conditionally_mounted.",
    ),
    agent(
        "agent.openwebui.subagent", "Delegated sub-agent", "open-webui", "specialist",
        "Isolated task worker spawned by delegate_task; runs its own tool loop with an "
        "internal request, inheriting the parent's tools minus mutating-memory tools.",
        invocation_surfaces=[{"l1_id": "l1.internal.subagent", "trigger": "builtin delegate_task (foreground or background)",
                              "auth_context": "internal request built from parent user_data; request.state.internal=True"}],
        model_config={"provider": "inherits parent", "model": "parent model or chosen subagent model",
                     "config_source": "subagents config + parent metadata", "writers": [],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.delegated_task", "instruction_role": "developer",
                             "precedence": "base", "config_version": "runtime",
                             "writers": [writer("agent.openwebui.primary", None)]},
                            {"surface_id": "ctx.subagent_system_prompt", "instruction_role": "system",
                             "precedence": "base", "config_version": "runtime",
                             "writers": [writer("admin", "l1.api.configs.subagents")]}],
        tool_binding_ids=["tool.primary.knowledge_rag", "tool.primary.web", "tool.primary.code_interpreter",
                         "tool.primary.files"],
        context_source_ids=["ctx.delegated_task", "ctx.subagent_system_prompt", "ctx.tool_results",
                           "ctx.rag_knowledge", "ctx.web_content"],
        memory_ids=["mem.chat_history", "mem.knowledge_vector"],
        output_sink_ids=["sink.delegated_result"],
        control_ids=["ctl.subagent_limits", "ctl.internal_memory_strip"],
        resource_limits={"max_iterations": "subagents.max_iterations (config)", "recursion": "no nested sub-agents",
                        "token_or_cost_budget": "subagents.max_output", "loop_detection": "inherits",
                        "enforced_by": "code"},
        authority_context={"principal_source": "parent user identity (user_data)",
                         "tenant_scope": "same user as parent", "resource_scope": "parent's tool_ids/files/KB",
                         "delegated_identity": "acts as the parent user; background runs drop tool_servers",
                         "authz_enforcement": "code (inherits parent permissions; MUTATING_MEMORY_TOOLS removed)"},
        related_l2_ids=["l2.chat.completion"],
        source_ref="utils/subagents.py:delegate/process_pending_internal_messages",
        notes="Background sub-agents additionally drop non-jupyter code_interpreter and tool_servers.",
    ),
    agent(
        "agent.openwebui.terminal", "Terminal / ACP coding agent", "open-webui", "specialist",
        "External coding agent reached over a terminal server using ACP v1 (JSONL carrier); "
        "Open WebUI brokers prompts/approvals to it.",
        invocation_surfaces=[{"l1_id": "l1.api.terminal", "trigger": "terminal_id on a chat; get_terminal_tools",
                             "auth_context": "user session; terminal server connection config"}],
        model_config={"provider": "external ACP agent (out of process)", "model": "agent-defined",
                     "config_source": "terminal server connection (admin)", "writers": [writer("admin", "l1.api.configs.terminal_servers")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.terminal_system_prompt", "instruction_role": "system",
                            "precedence": "base", "config_version": "runtime",
                            "writers": [writer("external_service", None)]}],
        tool_binding_ids=["tool.primary.terminal"],
        context_source_ids=["ctx.terminal_system_prompt", "ctx.user_message"],
        memory_ids=["mem.chat_history"],
        output_sink_ids=["sink.terminal", "sink.chat_stream"],
        control_ids=["ctl.ask_user_hitl", "ctl.tool_approval"],
        resource_limits=None,
        authority_context={"principal_source": "terminal server identity",
                         "tenant_scope": "terminal working directory", "resource_scope": "terminal filesystem/shell",
                         "delegated_identity": "terminal server's own identity/credentials",
                         "authz_enforcement": "external (delegated to terminal server)"},
        related_l2_ids=[],
        source_ref="utils/agents/acp.py; utils/tools.py:get_terminal_tools/get_terminal_system_prompt",
        notes="ctx.terminal_system_prompt is supplied by the EXTERNAL terminal server into the system channel.",
        reachability=reach("conditionally_mounted", "requires a configured terminal server (ENABLE_TOOL_SERVERS)"),
    ),
    agent(
        "agent.openwebui.task_utility", "Task/utility model", "open-webui", "reviewer",
        "Side LLM calls for titles/tags/autocomplete, tool selection, after-turn memory "
        "review, and the auto tool-approval 'decisions' judgment.",
        invocation_surfaces=[{"l1_id": "l1.api.tasks", "trigger": "internal task pipeline + decisions engine",
                             "auth_context": "user context; task model config"}],
        model_config={"provider": "configurable task model", "model": "task.model config",
                     "config_source": "admin task config", "writers": [writer("admin", "l1.api.configs.task")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.task_prompt_templates", "instruction_role": "system",
                            "precedence": "base", "config_version": "runtime",
                            "writers": [writer("admin", "l1.api.configs.task")]}],
        tool_binding_ids=[],
        context_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.tool_results", "ctx.memory_recall"],
        memory_ids=["mem.memories", "mem.chat_history"],
        output_sink_ids=["sink.memory_write"],
        control_ids=["ctl.untrusted_data_prompt"],
        resource_limits=None,
        authority_context={"principal_source": "originating user",
                         "tenant_scope": "same user", "resource_scope": "that user's memories/chat",
                         "delegated_identity": "runs as the user",
                         "authz_enforcement": "code"},
        related_l2_ids=["l2.chat.completion"],
        source_ref="utils/memory.py:review_memory_after_turn/_generate_memory_operations; utils/tool_permissions.py:review_with_decisions",
        notes="review_with_decisions treats only user messages as authorization; tool output/retrieved "
              "content explicitly flagged non-authorizing (prompt-level).",
    ),
]

# ===========================================================================
# TOOL BINDINGS  (agent_id defaults to primary)
# ===========================================================================
A = "agent.openwebui.primary"


def _code_env(sandbox, egress, fs, by="platform_config"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


_user_ident = {"identity": "the requesting user (extra_params.__user__)",
               "credential_source": "session JWT / API key in request"}
_argh_code = {"validation": "JSON parse + depth<=32 + 64KiB literal cap (tool_calling.normalize_arguments)",
              "authorization": "per-user feature permission + model capability + global flag",
              "normalization": "schema coercion", "enforced_by": "code"}

TOOLS = [
    tool("tool.primary.code_interpreter", A, "execute_code", "native", "code_execution",
         l1_ids=[], capabilities=["run arbitrary Python"],
         server_or_provider="pyodide (browser) or Jupyter server",
         execution_identity={"identity": "pyodide sandbox OR shared Jupyter token",
                            "credential_source": "CODE_INTERPRETER_JUPYTER_AUTH token in server config"},
         execution_environment=_code_env("pyodide WASM (default) or external Jupyter kernel",
                                        "pyodide: via proxy; jupyter: kernel host network (unrestricted)",
                                        "jupyter: kernel container FS", by="platform_config"),
         argument_handling=_argh_code, output_ids=["ctx.tool_results", "sink.code_exec"],
         approval_required="unknown", control_ids=["ctl.tool_approval", "ctl.tool_permission_rbac"],
         related_l2_ids=["l2.chat.completion"],
         source_ref="utils/code_interpreter.py; tools.py get_builtin_tools(code_interpreter)",
         reachability=reach("conditionally_mounted", "code_interpreter.enable + model cap + feature + user perm"),
         notes="Jupyter engine shares one server token across users -> cross-user kernel reach if enabled."),

    tool("tool.primary.web", A, "search_web / fetch_url", "native", "external_send",
         l1_ids=[],
         capabilities=["web search via configured engine", "fetch arbitrary URL"],
         execution_identity={"identity": "server-side HTTP client", "credential_source": "search engine API key in config"},
         execution_environment=_code_env("in-process aiohttp", "unrestricted (arbitrary URL = SSRF surface)",
                                        "none", by="code"),
         argument_handling=_argh_code, output_ids=["ctx.web_content", "ctx.tool_results"],
         control_ids=["ctl.tool_approval", "ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(web_search): search_web, fetch_url",
         reachability=reach("conditionally_mounted", "web.search.enable + model web_search cap + feature + perm"),
         notes="fetch_url takes a model-composed URL with no host allowlist in core -> SSRF to internal services."),

    tool("tool.primary.image", A, "generate_image / edit_image", "native", "external_send",
         capabilities=["image generation/edit via configured backend"],
         execution_identity={"identity": "server image client", "credential_source": "image backend API key in config"},
         output_ids=["ctx.tool_results", "sink.image_gen"], control_ids=["ctl.tool_approval"],
         source_ref="tools.py get_builtin_tools(image_generation)",
         reachability=reach("conditionally_mounted", "image_generation.enable + cap + feature + perm")),

    tool("tool.primary.memory", A, "add/update/replace/delete/search/list memory", "native", "write",
         capabilities=["read and mutate the user's long-term memory bank"],
         execution_identity=_user_ident, argument_handling=_argh_code,
         output_ids=["mem.memories", "ctx.tool_results"], control_ids=["ctl.tool_permission_rbac"],
         source_ref="utils/memory.py; tools.py get_builtin_tools(memory)",
         reachability=reach("conditionally_mounted", "memories.enable + memory feature + cap + perm"),
         notes="Mutating memory tools are stripped for internal/sub-agent runs (MUTATING_MEMORY_TOOLS)."),

    tool("tool.primary.knowledge_rag", A, "knowledge/KB query + kb_exec", "native", "mixed",
         l1_ids=[],
         capabilities=["query/search/grep knowledge bases and files", "kb_exec file ops"],
         execution_identity=_user_ident, output_ids=["ctx.rag_knowledge", "ctx.tool_results"],
         control_ids=["ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(knowledge); ENABLE_KB_EXEC",
         reachability=reach("conditionally_mounted", "knowledge builtin + attached/available KB"),
         notes="Shared knowledge bases are a cross-user read path when a KB is shared to the user/group."),

    tool("tool.primary.files", A, "chat file tools", "native", "read",
         capabilities=["list/query/grep/view/display attached chat files"],
         execution_identity=_user_ident, output_ids=["ctx.tool_results"],
         source_ref="tools.py get_builtin_tools(files)"),

    tool("tool.primary.notes", A, "notes tools", "native", "write",
         capabilities=["search/view/write/replace user notes"], execution_identity=_user_ident,
         output_ids=["mem.notes", "ctx.tool_results"], control_ids=["ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(notes)"),

    tool("tool.primary.chats", A, "search_chats / view_chat", "native", "read",
         capabilities=["search and read the user's own chat history"], execution_identity=_user_ident,
         output_ids=["ctx.tool_results"], source_ref="tools.py get_builtin_tools(chats)"),

    tool("tool.primary.channels", A, "channel tools", "native", "read",
         capabilities=["search channels/messages, view threads"], execution_identity=_user_ident,
         output_ids=["ctx.tool_results"], control_ids=["ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(channels)"),

    tool("tool.primary.calendar", A, "calendar tools", "native", "write",
         capabilities=["search/create/update/delete calendar events"], execution_identity=_user_ident,
         output_ids=["ctx.tool_results"], control_ids=["ctl.tool_approval", "ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(calendar)",
         reachability=reach("conditionally_mounted", "calendar.enable + perm")),

    tool("tool.primary.automations", A, "automation tools", "native", "write",
         capabilities=["create/update/toggle/delete scheduled automations"], execution_identity=_user_ident,
         output_ids=["mem.automations", "ctx.tool_results"], control_ids=["ctl.tool_approval", "ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(automations)",
         reachability=reach("conditionally_mounted", "automations.enable + perm"),
         notes="Creates persistent scheduled triggers that later re-invoke the agent -> durable foothold."),

    tool("tool.primary.notify", A, "notify (user webhooks)", "native", "external_send",
         capabilities=["send notification to the user's configured webhook"], execution_identity=_user_ident,
         output_ids=["sink.notify"], control_ids=["ctl.tool_approval"],
         source_ref="tools.py get_builtin_tools(notifications)",
         reachability=reach("conditionally_mounted", "ui.enable_user_webhooks + perm"),
         notes="Model-composed content delivered to a user-set webhook URL -> exfil channel."),

    tool("tool.primary.tasks", A, "create_tasks / update_task", "native", "write",
         capabilities=["track multi-step task state on the chat row"], execution_identity=_user_ident,
         output_ids=["mem.tasks", "ctx.tool_results"], source_ref="tools.py get_builtin_tools(tasks)"),

    tool("tool.primary.skills", A, "skill read/update tools", "native", "write",
         capabilities=["view/read/grep skill files; update_skill_files"], execution_identity=_user_ident,
         output_ids=["mem.skills", "ctx.tool_results"], control_ids=["ctl.tool_permission_rbac"],
         source_ref="tools.py get_builtin_tools(skills)",
         notes="Skills are reusable instruction bundles injected into context -> writing them is "
               "stored-prompt-injection into future turns (ties to ctx.skill_instructions)."),

    tool("tool.primary.create_skill", A, "create_skill", "native", "write",
         capabilities=["author a new skill (instruction bundle)"], execution_identity=_user_ident,
         output_ids=["mem.skills"], control_ids=["ctl.tool_permission_rbac"],
         approval_required="unknown",
         source_ref="tools.py get_builtin_tools: create_skill (workspace.skills perm or admin)",
         notes="Gated by workspace.skills permission/admin."),

    tool("tool.primary.create_tool", A, "create_tool", "native", "code_execution",
         capabilities=["author a new workspace Python Tool"], execution_identity=_user_ident,
         execution_environment=_code_env("in-process (server)", "server network", "server FS", by="code"),
         control_ids=["ctl.tool_permission_rbac"], approval_required="unknown",
         source_ref="tools.py get_builtin_tools: create_tool (workspace.tools perm or admin)",
         reachability=reach("conditionally_mounted", "ENABLE_TOOLS + workspace.tools perm/admin"),
         notes="Creating a Tool defines server-side Python later executed in-process -> RCE-class if the "
               "model can both create and invoke; gated by workspace.tools permission."),

    tool("tool.primary.subagents", A, "delegate_task / timer", "native", "none",
         capabilities=["spawn a foreground/background sub-agent", "set a timer"],
         execution_identity=_user_ident, output_ids=["ctx.delegated_task", "sink.delegated_result"],
         control_ids=["ctl.subagent_limits"],
         source_ref="tools.py get_builtin_tools(subagents); utils/subagents.py",
         reachability=reach("conditionally_mounted", "subagents.enable; not internal/direct/temporary chat"),
         notes="Delegation edge; effect itself is control-flow (sub-agent carries the real effects)."),

    tool("tool.primary.ask_user", A, "ask_user", "native", "none",
         capabilities=["pause and request structured input from the user"], execution_identity=_user_ident,
         output_ids=["ctx.tool_results"], approval_required=False,
         source_ref="tools.py get_builtin_tools(user_input); tool_approval.py (ask_user special-cased)",
         notes="Human-in-the-loop input primitive; exempt from approval gating."),

    tool("tool.primary.workspace_python", A, "workspace Python tools", "code", "code_execution",
         l1_ids=[], capabilities=["admin/user-authored Python tools"],
         description_source={"source_ref": "tool docstring/spec authored in workspace",
                           "writers": [writer("admin", "l1.api.tools.create"), writer("user", "l1.api.tools.create")]},
         execution_identity={"identity": "server process", "credential_source": "tool's own valves/config"},
         execution_environment=_code_env("in-process server (no sandbox)", "server network", "server FS", by="none"),
         argument_handling=_argh_code, output_ids=["ctx.tool_results"],
         control_ids=["ctl.tool_approval", "ctl.tool_permission_rbac"],
         source_ref="tools.py get_tools (tool_ids not server:/builtin:)",
         notes="Arbitrary Python authored in the Tools workspace runs in-process; tool DESCRIPTION is "
               "model-facing and admin/user-editable -> tool-description injection + RCE class."),

    tool("tool.primary.tool_server", A, "OpenAPI tool-server tools", "api", "mixed",
         l1_ids=[], server_or_provider="configured OpenAPI tool server(s)",
         capabilities=["call external OpenAPI-described operations"],
         description_source={"source_ref": "remote OpenAPI spec (openapi.json)",
                           "writers": [writer("external_service", None), writer("admin", "l1.api.configs.tool_servers")]},
         execution_identity={"identity": "tool-server identity", "credential_source":
                           "server connection headers / OAuth token (build_tool_server_headers)"},
         execution_environment=_code_env("remote server", "per tool server", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "sink.external_tool_call"], control_ids=["ctl.tool_approval"],
         source_ref="tools.py get_tool_servers_data/execute_tool_server",
         reachability=reach("conditionally_mounted", "ENABLE_TOOL_SERVERS + configured server"),
         notes="Tool descriptions come from a remote spec -> rug-pull / description-injection; args model-composed."),

    tool("tool.primary.mcp", A, "MCP server tools", "mcp", "mixed",
         server_or_provider="configured MCP server(s)", capabilities=["call MCP tools; read MCP resources"],
         description_source={"source_ref": "MCP list_tools result (remote)",
                           "writers": [writer("external_service", None), writer("admin", "l1.api.configs.tool_servers")]},
         execution_identity={"identity": "MCP client (OAuthTokenAuth or headers)",
                           "credential_source": "MCP server connection config"},
         execution_environment=_code_env("remote MCP server", "per server", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "ctx.mcp_resource", "sink.external_tool_call"],
         control_ids=["ctl.tool_approval"],
         source_ref="utils/mcp/client.py (list_tools/call_tool/list_resources/read_resource)",
         reachability=reach("conditionally_mounted", "ENABLE_TOOL_SERVERS + MCP server enabled; tool_visible_to(model)"),
         notes="MCP client exposes tools + resources only; NO sampling channel in this version "
               "(no server->client model inference)."),

    tool("tool.primary.terminal", A, "terminal server tools (ACP)", "external", "code_execution",
         l1_ids=[],
         server_or_provider="terminal server (ACP v1)", capabilities=["shell/coding-agent actions in a workspace"],
         description_source={"source_ref": "terminal server tool specs + working_directory_context",
                           "writers": [writer("external_service", None)]},
         execution_identity={"identity": "terminal server identity", "credential_source": "terminal connection config"},
         execution_environment=_code_env("terminal server workspace", "terminal host network",
                                        "terminal working directory", by="external_service"),
         output_ids=["ctx.tool_results", "sink.terminal"], control_ids=["ctl.ask_user_hitl", "ctl.tool_approval"],
         source_ref="utils/tools.py get_terminal_tools; utils/agents/acp.py",
         reachability=reach("conditionally_mounted", "ENABLE_TOOL_SERVERS + configured terminal server")),
]

# ===========================================================================
# CONTEXT SOURCES
# ===========================================================================
_dest_primary = ["agent.openwebui.primary"]

CONTEXT = [
    ctx("ctx.system_prompt", "system_prompt", "trusted_instruction",
        source_ref="params.system / user.settings.ui.system / ui.default_interface_settings (tool_approval.py build_tool_approval_resume_payload)",
        writers=[writer("user", "l1.api.users.settings"), writer("admin", "l1.api.configs.default_settings")],
        destination_agent_ids=_dest_primary, destination_channel="system",
        provenance="user/admin", persistence_scope="user",
        notes="User-settable system prompt -> a user controls a trusted_instruction channel for their own agent."),

    ctx("ctx.user_message", "user_input", "untrusted_data",
        source_ref="chat messages (user role)", writers=[writer("user", "l1.api.chat.completions")],
        destination_agent_ids=_dest_primary, destination_channel="user", provenance="end user",
        persistence_scope="session"),

    ctx("ctx.chat_history", "chat_history", "mixed",
        source_ref="models/chats.py; message output array", writers=[writer("user", "l1.api.chat.completions"),
                                                                     writer("agent.openwebui.primary", None)],
        destination_agent_ids=_dest_primary, destination_channel="user", provenance="user + prior assistant/tool turns",
        persistence_scope="session",
        notes="Carries prior tool_results (untrusted) back into context each turn."),

    ctx("ctx.rag_knowledge", "retrieval", "untrusted_data",
        source_ref="middleware.py rag_template(); chat_completion_files_handler; retrieval",
        writers=[writer("user", "l1.api.files.upload"), writer("admin", "l1.api.knowledge.add")],
        destination_agent_ids=["agent.openwebui.primary", "agent.openwebui.subagent"],
        destination_channel="user", provenance="uploaded documents / knowledge base",
        transformation="rag_template interpolation into context", persistence_scope="tenant",
        related_l2_ids=["l2.chat.completion"],
        notes="Retrieved document text is injected as context -> classic indirect prompt-injection vector; "
              "shared KBs cross user boundaries."),

    ctx("ctx.tool_results", "tool_result", "untrusted_data",
        source_ref="middleware.py tool dispatch; tool_result_with_citations; function_call_output",
        writers=[writer("agent.openwebui.primary", None), writer("external_service", None)],
        destination_agent_ids=_dest_primary, destination_channel="tool", provenance="tool/plugin/server output",
        transformation="citation wrapping; truncation", persistence_scope="session",
        notes="Explicitly treated as data not instructions by policy prompt, but still enters context."),

    ctx("ctx.web_content", "external", "untrusted_data",
        source_ref="search_web / fetch_url results", writers=[writer("external_service", None)],
        destination_agent_ids=["agent.openwebui.primary", "agent.openwebui.subagent"],
        destination_channel="tool", provenance="arbitrary web pages", persistence_scope="session",
        notes="Attacker-controlled web content pulled by fetch_url -> indirect injection + SSRF response reflection."),

    ctx("ctx.memory_recall", "retrieval", "untrusted_data",
        source_ref="utils/memory.py recall_memories/add_memory_context",
        writers=[writer("user", "l1.api.memories.add"), writer("agent.openwebui.task_utility", None),
                 writer("agent.openwebui.primary", None)],
        destination_agent_ids=_dest_primary, destination_channel="system", provenance="prior memory writes",
        persistence_scope="user",
        notes="Memory is auto-written by the after-turn review model from turn content -> poisoned memory "
              "re-injected into later system context (persistence-scope user)."),

    ctx("ctx.files_attached", "document", "untrusted_data",
        source_ref="metadata.files / __files__; file/image attachments",
        writers=[writer("user", "l1.api.files.upload")], destination_agent_ids=_dest_primary,
        destination_channel="user", provenance="user-uploaded files/images", persistence_scope="session"),

    ctx("ctx.skill_instructions", "developer_prompt", "mixed",
        source_ref="skills builtin (view_skill/read_skill_file); __skill_ids__",
        writers=[writer("user", "l1.api.skills.update"), writer("admin", "l1.api.skills.update")],
        destination_agent_ids=_dest_primary, destination_channel="developer", provenance="workspace skills",
        persistence_scope="tenant",
        notes="Skills are instruction content that the model reads/follows; editable via tools -> stored injection."),

    ctx("ctx.tool_descriptions", "external", "untrusted_data",
        source_ref="tool spec 'description' shown to model (builtin + workspace + OpenAPI + MCP)",
        writers=[writer("admin", "l1.api.tools.create"), writer("user", "l1.api.tools.create"),
                 writer("external_service", None)],
        destination_agent_ids=_dest_primary, destination_channel="tool", provenance="tool authors / remote specs",
        persistence_scope="global",
        notes="External/remote tool descriptions are model-facing instructions -> rug-pull / tool-description injection."),

    ctx("ctx.terminal_system_prompt", "external", "untrusted_data",
        source_ref="utils/tools.py get_terminal_system_prompt (remote terminal server)",
        writers=[writer("external_service", None)], destination_agent_ids=["agent.openwebui.terminal"],
        destination_channel="system", provenance="external terminal server",
        notes="A remote server supplies content placed in the SYSTEM channel -> external control of instructions."),

    ctx("ctx.tool_approval_policy", "system_prompt", "trusted_instruction",
        source_ref="utils/tool_approval.py set_tool_approval_prompt (<tool_approval_policy> block)",
        writers=[writer("admin", "l1.api.configs.tool_permissions"), writer("source_code", None)],
        destination_agent_ids=_dest_primary, destination_channel="system", provenance="app/admin",
        persistence_scope="global",
        transformation="stripped and re-added each request (strip_tool_approval_prompt)"),

    ctx("ctx.delegated_task", "delegated_summary", "mixed",
        source_ref="utils/subagents.py delegate(task, context)", writers=[writer("agent.openwebui.primary", None)],
        destination_agent_ids=["agent.openwebui.subagent"], destination_channel="developer",
        provenance="parent agent (model-composed)", persistence_scope="workflow",
        notes="Parent model composes the sub-agent task+context -> prompt-injection can flow parent->child."),

    ctx("ctx.subagent_system_prompt", "system_prompt", "trusted_instruction",
        source_ref="subagents.system_prompt config", writers=[writer("admin", "l1.api.configs.subagents")],
        destination_agent_ids=["agent.openwebui.subagent"], destination_channel="system", provenance="admin",
        persistence_scope="global"),

    ctx("ctx.task_prompt_templates", "system_prompt", "trusted_instruction",
        source_ref="task.*.prompt_template config (titles/tags/tools/voice/memory)",
        writers=[writer("admin", "l1.api.configs.task")], destination_agent_ids=["agent.openwebui.task_utility"],
        destination_channel="system", provenance="admin", persistence_scope="global"),

    ctx("ctx.mcp_resource", "mcp_resource", "untrusted_data",
        source_ref="utils/mcp/client.py read_resource/list_resources",
        writers=[writer("external_service", None)], destination_agent_ids=_dest_primary,
        destination_channel="tool", provenance="remote MCP server resources", persistence_scope="session",
        reachability=reach("conditionally_mounted", "MCP server with resources enabled"),
        notes="MCP resource content read into context = untrusted external data."),
]

# ===========================================================================
# MEMORY STORES
# ===========================================================================
MEMORY = [
    mem("mem.memories", "agent_notes", "open-webui", "user",
        readers=["agent.openwebui.primary", "agent.openwebui.task_utility"],
        writers=[writer("user", "l1.api.memories.add"), writer("agent.openwebui.primary", None),
                 writer("agent.openwebui.task_utility", None)],
        isolation_enforcement="per user_id in repository queries + vector namespace",
        write_provenance="user, the agent's memory tools, AND the after-turn review model (turn-derived)",
        read_path="recall_memories vector + path search injected into system context",
        retention_and_deletion="user-managed; delete_memory tool + memories API",
        source_ref="utils/memory.py; models/memories.py",
        reachability=reach("conditionally_mounted", "memories.enable"),
        notes="Auto-write from turn content is the memory-poisoning sink; re-read as system context next turn."),

    mem("mem.chat_history", "conversation_history", "open-webui", "session",
        readers=["agent.openwebui.primary", "agent.openwebui.subagent", "agent.openwebui.task_utility"],
        writers=[writer("user", "l1.api.chat.completions"), writer("agent.openwebui.primary", None)],
        isolation_enforcement="per chat/user; get_accessible_chat_by_id permission check",
        write_provenance="user turns + assistant/tool outputs",
        read_path="prior messages replayed into context each turn",
        retention_and_deletion="user-managed chats; temporary chats not persisted",
        source_ref="models/chats.py"),

    mem("mem.knowledge_vector", "vector_store", "open-webui", "tenant",
        readers=["agent.openwebui.primary", "agent.openwebui.subagent"],
        writers=[writer("user", "l1.api.files.upload"), writer("admin", "l1.api.knowledge.add")],
        isolation_enforcement="collection/knowledge access control; SHARED KBs cross users by design",
        write_provenance="uploaded docs; anyone who can add to a shared KB",
        read_path="similarity search -> rag_template injection",
        retention_and_deletion="KB/file lifecycle",
        source_ref="retrieval; middleware chat_completion_files_handler",
        notes="Shared knowledge base = cross-user injection/read surface."),

    mem("mem.notes", "database", "open-webui", "user",
        readers=["agent.openwebui.primary"], writers=[writer("user", "l1.api.notes.write")],
        isolation_enforcement="per-user notes ownership", write_provenance="user + notes tools",
        read_path="notes tools", retention_and_deletion="user-managed",
        source_ref="tools.py notes builtin"),

    mem("mem.skills", "database", "open-webui", "tenant",
        readers=["agent.openwebui.primary", "agent.openwebui.subagent"],
        writers=[writer("user", "l1.api.skills.update"), writer("admin", "l1.api.skills.update")],
        isolation_enforcement="workspace.skills permission", write_provenance="skill authors (user/admin)",
        read_path="skill tools inject skill content into context as instructions",
        retention_and_deletion="workspace-managed", source_ref="tools.py skills builtin",
        notes="Instruction content store -> stored-prompt-injection surface."),

    mem("mem.tasks", "task_summary", "open-webui", "workflow",
        readers=["agent.openwebui.primary"], writers=[writer("agent.openwebui.primary", None)],
        isolation_enforcement="stored on the chat row", write_provenance="the agent's task tools",
        read_path="task state surfaced in context", retention_and_deletion="with the chat",
        source_ref="tools.py tasks builtin"),

    mem("mem.automations", "database", "open-webui", "user",
        readers=["agent.openwebui.primary"], writers=[writer("user", "l1.api.automations.create"),
                                                      writer("agent.openwebui.primary", None)],
        isolation_enforcement="per-user automations", write_provenance="user + automation tools",
        read_path="scheduler triggers later agent runs",
        retention_and_deletion="user-managed", source_ref="tools.py automations builtin; utils/automations.py",
        reachability=reach("conditionally_mounted", "automations.enable"),
        notes="Persistent scheduled triggers = durable re-invocation / foothold."),
]

# ===========================================================================
# OUTPUT SINKS
# ===========================================================================
_md_render = {"auto_fetch": "chat UI renders markdown incl. images (auto-loaded) and links",
              "active_content": "markdown/HTML sanitized client-side (utils/sanitize.py + frontend)",
              "enforced_by": "code"}

SINKS = [
    sink("sink.chat_stream", "chat_response", producer_ids=["agent.openwebui.primary", "agent.openwebui.terminal"],
         audience="end user (chat UI)", delivery="streamed markdown over socket/SSE",
         render_side_effects=_md_render, related_l1_ids=["l1.api.chat.completions"],
         related_l2_ids=["l2.chat.completion"],
         source_ref="utils/middleware.py process_chat_response; outlet_filter_handler",
         notes="Model-authored markdown image/link URLs are the data-exfil-on-render channel; sanitize.py "
               "+ outlet filters are the mitigations to verify at runtime."),

    sink("sink.notify", "notification", producer_ids=["tool.primary.notify"],
         audience="user's configured webhook endpoint", delivery="HTTP POST to user webhook",
         source_ref="tools.py notify; utils/webhook.py",
         notes="Model-composed payload to a user-set URL."),

    sink("sink.image_gen", "external_api", producer_ids=["tool.primary.image"],
         audience="image backend", delivery="HTTP to image generation service",
         source_ref="image generation backend"),

    sink("sink.external_tool_call", "external_api", producer_ids=["tool.primary.tool_server", "tool.primary.mcp"],
         audience="external OpenAPI/MCP servers", delivery="HTTP/MCP call with model-composed arguments",
         transformation="header injection via build_tool_server_headers / OAuth",
         related_l2_ids=["l2.chat.completion"], source_ref="utils/tools.py execute_tool_server; utils/mcp/client.py",
         notes="Model-composed args leave to third-party servers under the server's own credentials."),

    sink("sink.code_exec", "external_api", producer_ids=["tool.primary.code_interpreter"],
         audience="pyodide / Jupyter kernel", delivery="WebSocket execute_request to Jupyter (or in-browser pyodide)",
         source_ref="utils/code_interpreter.py",
         notes="Jupyter engine = shared token; kernel has host network/FS."),

    sink("sink.terminal", "external_api", producer_ids=["tool.primary.terminal", "agent.openwebui.terminal"],
         audience="terminal server (ACP)", delivery="ACP JSONL over terminal carrier",
         source_ref="utils/agents/acp.py",
         reachability=reach("conditionally_mounted", "configured terminal server")),

    sink("sink.delegated_result", "delegated_result", producer_ids=["agent.openwebui.subagent"],
         audience="parent agent", delivery="sub-agent summary returned into parent context",
         becomes_context_source_ids=["ctx.tool_results"], source_ref="utils/subagents.py",
         notes="Sub-agent output becomes parent context -> child->parent injection path."),

    sink("sink.memory_write", "database_record", producer_ids=["agent.openwebui.task_utility", "tool.primary.memory"],
         audience="mem.memories", delivery="memory row + vector upsert",
         becomes_context_source_ids=["ctx.memory_recall"], source_ref="utils/memory.py",
         notes="Closes the loop into ctx.memory_recall (poisoning persistence)."),
]

# ===========================================================================
# EXECUTION EDGES
# ===========================================================================
def _S(step, agent="agent.openwebui.primary"):
    return {"agent_id": agent, "step": step, "external_trigger": None}


EDGES = [
    edge("edge.user__primary", "user", source={"agent_id": None, "step": "request", "external_trigger": "chat UI / API"},
         destination={"agent_id": "agent.openwebui.primary"}, condition="user sends a chat completion request",
         input_source_ids=["ctx.user_message", "ctx.system_prompt", "ctx.files_attached"],
         payload="user message + files + model/tool/feature selection", execution_mode="synchronous",
         failure_behavior="abort", related_l1_ids=["l1.api.chat.completions"],
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 1}],
         source_ref="middleware.py process_chat_payload"),

    edge("edge.inlet_filter", "deterministic_code", source=_S("pre-model"),
         destination={"agent_id": "agent.openwebui.primary"}, condition="before model call",
         input_source_ids=["ctx.user_message", "ctx.rag_knowledge"], argument_sources="pipeline/function inlet filters",
         payload="form_data (messages, tools)", control_ids=["ctl.pipeline_inlet_filter", "ctl.function_filters"],
         execution_mode="synchronous", failure_behavior="abort",
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 2}],
         source_ref="middleware.py process_pipeline_inlet_filter / process_filter_functions"),

    edge("edge.primary__tool", "llm", source=_S("tool-call"),
         destination={"tool_binding_id": "(model-selected binding)"},
         condition="model emits a function_call", argument_sources="model-composed arguments (JSON)",
         input_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.rag_knowledge", "ctx.tool_results",
                          "ctx.web_content", "ctx.memory_recall", "ctx.tool_descriptions"],
         payload="tool name + arguments", output_ids=["ctx.tool_results"],
         control_ids=["ctl.arg_validation", "ctl.tool_permission_rbac", "ctl.tool_approval",
                     "ctl.tool_permissions_auto", "ctl.tool_repetition_guard"],
         validation_or_approval="normalize -> RBAC -> approval policy (full/ask/auto) before side effect",
         execution_mode="synchronous", loop_bound="repeats until model stops or repetition guard trips",
         failure_behavior="fail_closed", related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 3}],
         source_ref="middleware.py tool loop; tool_calling.py; tool_approval.py",
         notes="Tool selection + argument composition is fully model-directed -> primary injection->action edge."),

    edge("edge.approval__tool", "human_reviewer", source=_S("approval"),
         destination={"tool_binding_id": "(pending binding)"},
         condition="approval required (mode ask/auto, or auto-decision >= threshold)",
         input_source_ids=["ctx.tool_results"], payload="approve/reject/answer",
         control_ids=["ctl.tool_approval"], validation_or_approval="resolve_tool_call_output (user owns the chat)",
         execution_mode="callback", failure_behavior="fail_closed",
         related_l1_ids=["l1.api.chat.completed"],
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 3}],
         source_ref="tool_approval.py resolve_tool_call_output",
         notes="Approval is user-side; review errors fail closed (require approval). ask_user exempt."),

    edge("edge.tool__primary", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": "agent.openwebui.primary"}, condition="tool result returns",
         argument_sources="tool output serialized to function_call_output", payload="tool result + citations",
         output_ids=["ctx.tool_results"], execution_mode="synchronous", failure_behavior="retry",
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 4}],
         source_ref="middleware.py tool_result_with_citations",
         notes="Untrusted tool output re-enters model context."),

    edge("edge.primary__subagent", "llm", source=_S("delegate"),
         destination={"agent_id": "agent.openwebui.subagent"}, condition="model calls delegate_task",
         argument_sources="model-composed task + context + optional model_id/file_ids",
         input_source_ids=["ctx.user_message", "ctx.chat_history"], payload="task, context, files",
         output_ids=["ctx.delegated_task"], control_ids=["ctl.subagent_limits", "ctl.internal_memory_strip"],
         execution_mode="background", loop_bound="subagents.max_iterations; no nested delegation",
         failure_behavior="partial_effect", related_l1_ids=["l1.internal.subagent"],
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 3}],
         source_ref="utils/subagents.py delegate",
         notes="Internal request (request.state.internal=True) strips mutating-memory tools + tool_servers (bg)."),

    edge("edge.subagent__primary", "deterministic_code",
         source={"agent_id": "agent.openwebui.subagent", "step": "result", "external_trigger": None},
         destination={"agent_id": "agent.openwebui.primary", "output_sink_id": "sink.delegated_result"},
         condition="sub-agent completes", payload="sub-agent summary (<= max_output)",
         output_ids=["sink.delegated_result", "ctx.tool_results"], execution_mode="callback",
         failure_behavior="partial_effect", source_ref="utils/subagents.py process_pending_internal_messages"),

    edge("edge.primary__external", "llm", source=_S("external-tool"),
         destination={"tool_binding_id": "tool.primary.tool_server", "external_surface": "OpenAPI/MCP server"},
         condition="model calls an OpenAPI/MCP tool", argument_sources="model-composed args",
         payload="operation + args", output_ids=["sink.external_tool_call", "ctx.tool_results"],
         control_ids=["ctl.tool_approval"], execution_mode="synchronous", failure_behavior="fail_closed",
         source_ref="utils/tools.py execute_tool_server; utils/mcp/client.py",
         notes="No MCP sampling edge exists in this version (external_trigger path unused)."),

    edge("edge.primary__code", "llm", source=_S("code"),
         destination={"tool_binding_id": "tool.primary.code_interpreter", "external_surface": "Jupyter/pyodide"},
         condition="model calls execute_code", argument_sources="model-composed source code",
         payload="python source", output_ids=["sink.code_exec", "ctx.tool_results"],
         control_ids=["ctl.tool_approval"], execution_mode="synchronous", failure_behavior="abort",
         source_ref="utils/code_interpreter.py"),

    edge("edge.primary__terminal", "llm", source=_S("terminal", "agent.openwebui.terminal"),
         destination={"tool_binding_id": "tool.primary.terminal", "external_surface": "terminal server (ACP)"},
         condition="terminal tool invoked", argument_sources="model-composed; ACP form via ask_user",
         payload="shell/agent action", output_ids=["sink.terminal", "ctx.tool_results"],
         control_ids=["ctl.ask_user_hitl", "ctl.tool_approval"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="utils/agents/acp.py",
         reachability=reach("conditionally_mounted", "terminal server configured")),

    edge("edge.memory_review", "llm", source=_S("post-turn", "agent.openwebui.task_utility"),
         destination={"agent_id": "agent.openwebui.task_utility", "output_sink_id": "sink.memory_write"},
         condition="after-turn memory review (if enabled)", argument_sources="turn content -> memory ops",
         input_source_ids=["ctx.user_message", "ctx.tool_results"], payload="add/update/replace/delete memory ops",
         output_ids=["sink.memory_write", "mem.memories"], validation_or_approval="validate_memory_operations",
         execution_mode="background", failure_behavior="abort",
         source_ref="utils/memory.py review_memory_after_turn",
         notes="Turn-derived auto memory write; the poisoning persistence edge."),

    edge("edge.outlet_filter", "deterministic_code", source=_S("post-model"),
         destination={"output_sink_id": "sink.chat_stream"}, condition="after completion",
         control_ids=["ctl.pipeline_outlet_filter", "ctl.function_filters"], payload="final assistant message",
         output_ids=["sink.chat_stream"], execution_mode="synchronous", failure_behavior="fallback",
         source_ref="middleware.py outlet_filter_handler",
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 5}]),

    edge("edge.primary__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.chat_stream"}, condition="model stops calling tools",
         payload="final answer (tools disabled continuation)", output_ids=["sink.chat_stream"],
         execution_mode="synchronous", failure_behavior="abort",
         source_ref="tool_calling.final_answer_payload",
         related_l2_steps=[{"l2_id": "l2.chat.completion", "order": 5}]),
]

# ===========================================================================
# CONTROLS
# ===========================================================================
_prim = ["agent.openwebui.primary"]
CONTROLS = [
    ctl("ctl.tool_approval", "human_approval", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_prim,
        applies_to_tool_binding_ids=["tool.primary.code_interpreter", "tool.primary.web", "tool.primary.create_tool",
                                    "tool.primary.tool_server", "tool.primary.mcp", "tool.primary.terminal",
                                    "tool.primary.automations", "tool.primary.notify", "tool.primary.calendar"],
        source_ref="utils/tool_approval.py (resolve_tool_approval_mode, requires_tool_approval)",
        notes="Modes full(no gate)/ask(always)/auto(policy). Fingerprint re-approval on arg change. "
              "ask_user exempt. Default 'full' when tool_permissions disabled -> NO approval."),

    ctl("ctl.tool_permissions_auto", "tool_policy", "before_tool", "modifying", "external_service",
        failure_mode="fail_closed", applies_to_agent_ids=_prim,
        source_ref="utils/tool_permissions.py review_with_decisions (external 'decisions' engine) + model __approval__",
        notes="LLM/engine decides if a call needs approval; only user messages treated as authorization; "
              "errors/timeouts -> require approval. Engine '' uses model-self-reported __approval__ (weak)."),

    ctl("ctl.tool_permission_rbac", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_prim,
        source_ref="utils/tools.py has_permission over user.permissions; features.* / workspace.* / chat.* gates",
        notes="Per-user feature + workspace permissions decide which tools are even mounted; admins bypass."),

    ctl("ctl.pipeline_inlet_filter", "input_filter", "before_model", "modifying", "external_service",
        failure_mode="abort", applies_to_agent_ids=_prim,
        source_ref="utils/middleware.py process_pipeline_inlet_filter",
        notes="Pipeline server can rewrite the request before the model."),

    ctl("ctl.pipeline_outlet_filter", "output_filter", "output_delivery", "modifying", "external_service",
        failure_mode="fallback", applies_to_agent_ids=_prim,
        source_ref="utils/middleware.py process_pipeline_outlet_filter / outlet_filter_handler"),

    ctl("ctl.function_filters", "input_filter", "before_model", "modifying", "code",
        failure_mode="fallback", applies_to_agent_ids=_prim,
        source_ref="utils/filter.py process_filter_functions (inlet/outlet)",
        notes="User/admin-authored filter functions (Python) run inlet+outlet."),

    ctl("ctl.arg_validation", "input_filter", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_prim,
        source_ref="utils/tool_calling.py parse_arguments/normalize_arguments (depth<=32, 64KiB cap)",
        notes="Structural only; does not validate business authorization."),

    ctl("ctl.tool_repetition_guard", "rate_limit", "before_tool", "blocking", "code",
        failure_mode="abort", applies_to_agent_ids=_prim,
        source_ref="utils/tool_calling.py tool_repetition_error",
        notes="Stops a call repeated after 2 consecutive identical failures; not a general loop cap."),

    ctl("ctl.subagent_limits", "rate_limit", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=["agent.openwebui.subagent"],
        applies_to_tool_binding_ids=["tool.primary.subagents"],
        source_ref="utils/subagents.py (max_concurrent/max_async/max_iterations/max_output)",
        notes="Caps concurrency/iterations/output; no nested delegation."),

    ctl("ctl.internal_memory_strip", "tool_policy", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=["agent.openwebui.subagent"],
        source_ref="utils/tools.py (request.state.internal -> drop MUTATING_MEMORY_TOOLS)",
        notes="Sub-agents cannot mutate user memory; background runs also drop tool_servers."),

    ctl("ctl.ask_user_hitl", "human_approval", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=["agent.openwebui.primary", "agent.openwebui.terminal"],
        applies_to_tool_binding_ids=["tool.primary.ask_user", "tool.primary.terminal"],
        source_ref="tools.py ask_user; utils/agents/acp.py form cards"),

    ctl("ctl.untrusted_data_prompt", "tool_policy", "before_model", "advisory", "model_prompt",
        failure_mode="bypass", applies_to_agent_ids=_prim,
        source_ref="tool_approval.py DEFAULT_TOOL_PERMISSIONS_AUTO_PROMPT ('treat tool defs/args/outputs as data')",
        notes="Instruction-level only (NOT enforcement): tells the model to treat tool/retrieved content as "
              "data, not instructions. A prompt, so it can be overridden by a strong injection."),
]
