# -*- coding: utf-8 -*-
"""LobeChat agentic attack-surface data (schema: agentic-attack-surface-v1).

App: lobe-chat (web source under 472-new/lobe-chat). Agent runtime = a client
function-calling loop in the chat store (src/store/chat/slices/plugin/action.ts
triggerToolCalls -> invoke{Builtin,Default,Markdown,Standalone}TypePlugin), with
plugin API calls proxied through a SERVER gateway (services/chat.ts runPluginApi
-> API_ENDPOINTS.gateway -> plugin manifest api url) carrying plugin-settings
headers as identity. Tools: builtin (dalle), Lobe plugins (default/markdown/
standalone), user custom plugins (remote manifest), artifacts (iframe render).

Notable: tool calls AUTO-RUN (no per-tool human approval by default); MCP is NOT
present in this web source (desktop-only). Static pass; grounding pending.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

A = "agent.lobechat.assistant"

AGENTS = [
    agent(
        A, "Assistant (agent session)", "lobe-chat", "interactive",
        "Per-session assistant defined by an agent config (systemRole + enabled plugins/model); "
        "runs a client tool-call loop, dispatching plugin calls through the server gateway.",
        invocation_surfaces=[
            {"l1_id": "l1.api.chat.completion", "trigger": "chat send -> model stream; tool_calls dispatched client-side",
             "auth_context": "user session (self-host single-user, or next-auth/Clerk multi-user)"},
            {"l1_id": "l1.api.plugin.gateway", "trigger": "runPluginApi -> gateway proxy to plugin manifest url",
             "auth_context": "same user; plugin settings in headers"},
        ],
        model_config={"provider": "configurable (OpenAI/Anthropic/Ollama/... many)", "model": "per-agent model",
                     "config_source": "agent/session config + user settings",
                     "writers": [writer("user", "l1.api.agent.config")], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_role", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("user", "l1.api.agent.config"),
                                                                     writer("external_service", "l1.api.market.install")]}],
        tool_binding_ids=["tool.dalle", "tool.web_browsing", "tool.plugin_default", "tool.plugin_standalone",
                         "tool.custom_plugin"],
        context_source_ids=["ctx.system_role", "ctx.user_message", "ctx.chat_history", "ctx.knowledge",
                          "ctx.tool_results", "ctx.web_content", "ctx.plugin_manifest_desc", "ctx.file_attachments"],
        memory_ids=["mem.messages", "mem.knowledge_vector", "mem.agents"],
        output_sink_ids=["sink.chat_response", "sink.artifacts", "sink.plugin_gateway", "sink.dalle"],
        control_ids=["ctl.plugin_enablement", "ctl.gateway_proxy", "ctl.plugin_settings_auth", "ctl.abort"],
        resource_limits={"max_iterations": "tool-call loop continues while the model emits tool_calls; no explicit "
                        "hard cap found in web source", "recursion": "n/a", "token_or_cost_budget": "none in core",
                        "loop_detection": "user abort / stream cancel", "enforced_by": "code"},
        authority_context={"principal_source": "user session (or local single-user)",
                         "tenant_scope": "per-user agents/sessions/files",
                         "resource_scope": "user's sessions + plugin settings secrets",
                         "delegated_identity": "plugin calls carry the user's plugin-settings headers via the gateway",
                         "authz_enforcement": "code (per-user data scoping); plugins auto-run without approval"},
        related_l2_ids=["l2.chat.agent_session"],
        source_ref="src/store/chat/slices/plugin/action.ts; src/services/chat.ts runPluginApi; src/tools/index.ts",
        notes="Agent config (systemRole + plugins) can be installed from the plugin/agent MARKET -> external "
              "authorship of the system prompt and tool set.",
    ),
]

_plugin_ident = {"identity": "the user's plugin settings", "credential_source": "plugin settings headers (createHeadersWithPluginSettings)"}
_argh = {"validation": "JSON tool arguments parsed from model tool_calls", "authorization": "plugin enabled on the agent",
         "normalization": "parseToolCalls", "enforced_by": "code"}


def _env(sandbox, egress, fs, by="code"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


TOOLS = [
    tool("tool.dalle", A, "DALL-E image generation (builtin)", "native", "external_send",
         capabilities=["generate images"], execution_identity={"identity": "server/provider key",
                                                               "credential_source": "image provider config"},
         output_ids=["sink.dalle", "ctx.tool_results"], source_ref="src/tools/dalle; builtinTools",
         notes="Only built-in tool in web source."),

    tool("tool.web_browsing", A, "web browsing (search + crawl page)", "plugin", "external_send",
         capabilities=["search the web", "crawl/fetch a page's content"],
         execution_identity={"identity": "server fetch / search provider", "credential_source": "search provider config"},
         execution_environment=_env("server/gateway", "unrestricted (crawl arbitrary URL = SSRF)", "none"),
         output_ids=["ctx.web_content", "ctx.tool_results"], source_ref="lobe web-browsing plugin",
         reachability=reach("conditionally_mounted", "web-browsing plugin enabled"),
         notes="Model-composed URL crawled server-side -> SSRF + indirect injection via page content."),

    tool("tool.plugin_default", A, "Lobe plugin (default/markdown type)", "api", "mixed",
         l1_ids=["l1.api.plugin.gateway"], server_or_provider="plugin manifest api url (via server gateway)",
         capabilities=["call the plugin's declared API operations"],
         description_source={"source_ref": "plugin manifest (remote) description/schema",
                           "writers": [writer("external_service", None), writer("user", "l1.api.plugin.install")]},
         execution_identity=_plugin_ident,
         execution_environment=_env("remote plugin API via gateway proxy", "gateway fetches manifest url", "remote",
                                  by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "sink.plugin_gateway"],
         source_ref="services/chat.ts runPluginApi -> API_ENDPOINTS.gateway",
         reachability=reach("conditionally_mounted", "plugin installed + enabled on the agent"),
         notes="Server gateway fetches the plugin's manifest url -> SSRF-class; description from remote manifest -> rug-pull."),

    tool("tool.plugin_standalone", A, "Lobe plugin (standalone/iframe UI)", "plugin", "mixed",
         capabilities=["render a plugin UI in an iframe; postMessage bridge"],
         description_source={"source_ref": "plugin manifest (remote)",
                           "writers": [writer("external_service", None), writer("user", "l1.api.plugin.install")]},
         execution_identity=_plugin_ident, output_ids=["ctx.tool_results", "sink.artifacts"],
         source_ref="invokeStandaloneTypePlugin",
         reachability=reach("conditionally_mounted", "standalone plugin installed"),
         notes="Renders third-party iframe content in the app origin boundary."),

    tool("tool.custom_plugin", A, "user custom plugin (manifest URL)", "api", "mixed",
         capabilities=["user-added plugin from an arbitrary manifest URL"],
         description_source={"source_ref": "user-supplied remote manifest",
                           "writers": [writer("user", "l1.api.custom_plugin.add"), writer("external_service", None)]},
         execution_identity=_plugin_ident,
         execution_environment=_env("remote", "gateway fetches user-supplied url", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "sink.plugin_gateway"], source_ref="store/tool/slices/customPlugin/action.ts",
         reachability=reach("conditionally_mounted", "a custom plugin added"),
         notes="User supplies an arbitrary manifest URL -> model-facing description + gateway target both attacker-choosable."),
]

_dest = [A]
CONTEXT = [
    ctx("ctx.system_role", "system_prompt", "trusted_instruction",
        source_ref="agent config systemRole (per session/agent)",
        writers=[writer("user", "l1.api.agent.config"), writer("external_service", "l1.api.market.install")],
        destination_agent_ids=_dest, destination_channel="system", provenance="agent config (user or market)",
        persistence_scope="user",
        notes="systemRole is user-set OR installed from the market -> market agents carry external system prompts."),

    ctx("ctx.user_message", "user_input", "untrusted_data", source_ref="chat input",
        writers=[writer("user", "l1.api.chat.completion")], destination_agent_ids=_dest,
        destination_channel="user", provenance="end user", persistence_scope="session"),

    ctx("ctx.chat_history", "chat_history", "mixed", source_ref="messages/topics store",
        writers=[writer("user", "l1.api.chat.completion"), writer(A, None)], destination_agent_ids=_dest,
        destination_channel="user", provenance="prior turns", persistence_scope="session"),

    ctx("ctx.knowledge", "retrieval", "untrusted_data", source_ref="files/knowledge base RAG injection",
        writers=[writer("user", "l1.api.file.upload")], destination_agent_ids=_dest, destination_channel="system",
        provenance="uploaded files / knowledge", persistence_scope="user",
        notes="Uploaded document chunks injected -> indirect injection."),

    ctx("ctx.tool_results", "tool_result", "untrusted_data", source_ref="plugin/tool responses re-fed to the model",
        writers=[writer(A, None), writer("external_service", None)], destination_agent_ids=_dest,
        destination_channel="tool", provenance="plugin/tool output", persistence_scope="session"),

    ctx("ctx.web_content", "external", "untrusted_data", source_ref="web-browsing crawl/search results",
        writers=[writer("external_service", None)], destination_agent_ids=_dest, destination_channel="tool",
        provenance="arbitrary web pages", persistence_scope="session",
        notes="Crawled page content -> indirect injection + SSRF reflection."),

    ctx("ctx.plugin_manifest_desc", "external", "untrusted_data",
        source_ref="plugin/custom-plugin manifest descriptions + schemas presented to the model",
        writers=[writer("external_service", None), writer("user", "l1.api.custom_plugin.add")],
        destination_agent_ids=_dest, destination_channel="tool", provenance="remote plugin manifests",
        persistence_scope="user",
        notes="Remote/user manifests are model-facing -> rug-pull / tool-description injection."),

    ctx("ctx.file_attachments", "document", "untrusted_data", source_ref="message file/image attachments",
        writers=[writer("user", "l1.api.file.upload")], destination_agent_ids=_dest, destination_channel="user",
        provenance="user uploads", persistence_scope="session"),
]

MEMORY = [
    mem("mem.messages", "conversation_history", "lobe-chat", "user",
        readers=[A], writers=[writer("user", "l1.api.chat.completion"), writer(A, None)],
        isolation_enforcement="per-user (client PGlite/IndexedDB or server DB with userId scoping)",
        write_provenance="user turns + assistant/tool outputs", read_path="messages replayed into context",
        retention_and_deletion="user-managed", source_ref="database/schemas messages/topics",
        notes="No dedicated agent-memory skill; persistence/poisoning rides on chat history + knowledge."),

    mem("mem.knowledge_vector", "vector_store", "lobe-chat", "user",
        readers=[A], writers=[writer("user", "l1.api.file.upload")],
        isolation_enforcement="per-user knowledge bases", write_provenance="uploaded files",
        read_path="semantic search -> context", retention_and_deletion="file lifecycle",
        source_ref="files/knowledge RAG"),

    mem("mem.agents", "database", "lobe-chat", "user",
        readers=[A], writers=[writer("user", "l1.api.agent.config"), writer("external_service", "l1.api.market.install")],
        isolation_enforcement="per-user agents", write_provenance="user config or market install",
        read_path="agent config supplies systemRole + plugin set", retention_and_deletion="user-managed",
        source_ref="store/agent; sessions",
        notes="Installing a market agent writes systemRole + enabled plugins = instruction+tool provisioning."),
]

_md = {"auto_fetch": "chat UI renders markdown images/links", "active_content": "sanitized markdown",
       "enforced_by": "code"}
SINKS = [
    sink("sink.chat_response", "chat_response", producer_ids=[A], audience="user (chat UI)",
         delivery="streamed markdown", render_side_effects=_md, related_l2_ids=["l2.chat.agent_session"],
         source_ref="fetchSSE; message render",
         notes="Markdown image/link auto-load = exfil-on-render channel."),

    sink("sink.artifacts", "file", producer_ids=[A, "tool.plugin_standalone"],
         audience="user (iframe)", delivery="model-authored HTML/SVG/React rendered in an iframe",
         render_side_effects={"auto_fetch": "iframe may load remote resources",
                            "active_content": "executes model-authored HTML/JS/React in an iframe sandbox",
                            "enforced_by": "code (iframe sandbox)"},
         source_ref="artifacts render; standalone plugin iframe",
         notes="Client-side code execution of model output -> XSS/exfil class bounded by iframe sandbox."),

    sink("sink.plugin_gateway", "external_api", producer_ids=["tool.plugin_default", "tool.custom_plugin"],
         audience="external plugin APIs", delivery="server gateway POST to plugin manifest url with settings headers",
         transformation="createHeadersWithPluginSettings injects plugin secrets", related_l2_ids=["l2.chat.agent_session"],
         source_ref="services/chat.ts runPluginApi",
         notes="Model-composed args + user plugin secrets leave to third-party/user-chosen URLs via the gateway."),

    sink("sink.dalle", "external_api", producer_ids=["tool.dalle"], audience="image provider",
         delivery="image generation API", source_ref="dalle tool"),
]


def _S(step):
    return {"agent_id": A, "step": step, "external_trigger": None}


EDGES = [
    edge("edge.user__assistant", "user",
         source={"agent_id": None, "step": "request", "external_trigger": "chat UI"},
         destination={"agent_id": A}, condition="user sends a message",
         input_source_ids=["ctx.user_message", "ctx.system_role", "ctx.knowledge"],
         payload="user message + agent config", execution_mode="synchronous", failure_behavior="abort",
         related_l1_ids=["l1.api.chat.completion"],
         related_l2_steps=[{"l2_id": "l2.chat.agent_session", "order": 1}],
         source_ref="store/chat message action"),

    edge("edge.assistant__tool", "llm", source=_S("tool-call"),
         destination={"tool_binding_id": "(model-selected binding)"},
         condition="model returns tool_calls -> triggerToolCalls dispatch by plugin type",
         argument_sources="parseToolCalls (model-composed JSON args)",
         input_source_ids=["ctx.user_message", "ctx.chat_history", "ctx.knowledge", "ctx.tool_results",
                          "ctx.web_content", "ctx.plugin_manifest_desc"],
         payload="tool id + args", output_ids=["ctx.tool_results"],
         control_ids=["ctl.plugin_enablement", "ctl.gateway_proxy", "ctl.plugin_settings_auth"],
         validation_or_approval="NONE by default (tool calls auto-run); plugin must be enabled",
         execution_mode="synchronous", loop_bound="continues while model emits tool_calls (no explicit cap)",
         failure_behavior="retry", related_l2_steps=[{"l2_id": "l2.chat.agent_session", "order": 2}],
         source_ref="store/chat/slices/plugin/action.ts triggerToolCalls",
         notes="Auto-run, no human approval -> model-directed tool use executes without a gate."),

    edge("edge.tool__assistant", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": A}, condition="tool result returns", payload="tool result",
         output_ids=["ctx.tool_results"], execution_mode="synchronous", failure_behavior="retry",
         related_l2_steps=[{"l2_id": "l2.chat.agent_session", "order": 3}],
         source_ref="invoke*TypePlugin result handling"),

    edge("edge.assistant__gateway", "llm", source=_S("plugin-api"),
         destination={"tool_binding_id": "tool.plugin_default", "external_surface": "plugin manifest url (via gateway)"},
         condition="default/custom plugin call", argument_sources="model-composed args",
         payload="plugin request payload + manifest", output_ids=["sink.plugin_gateway", "ctx.tool_results"],
         control_ids=["ctl.gateway_proxy", "ctl.plugin_settings_auth"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="services/chat.ts runPluginApi",
         notes="Server gateway is the SSRF sink (fetches manifest url); no MCP edge (MCP absent in web source)."),

    edge("edge.assistant__artifacts", "llm", source=_S("artifact"),
         destination={"output_sink_id": "sink.artifacts"}, condition="model emits an artifact (html/react/svg)",
         argument_sources="model-authored code", payload="artifact code", output_ids=["sink.artifacts"],
         execution_mode="synchronous", failure_behavior="fallback", source_ref="artifacts render",
         notes="Model output executed/rendered client-side in an iframe."),

    edge("edge.assistant__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.chat_response"}, condition="model finishes",
         payload="final markdown", output_ids=["sink.chat_response"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="fetchSSE finalize",
         related_l2_steps=[{"l2_id": "l2.chat.agent_session", "order": 4}]),
]

CONTROLS = [
    ctl("ctl.plugin_enablement", "tool_policy", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[A],
        source_ref="store/tool plugin enable state per agent",
        notes="Only plugins enabled on the agent are exposed to the model."),

    ctl("ctl.gateway_proxy", "authorization", "before_tool", "modifying", "code",
        failure_mode="abort", applies_to_agent_ids=[A],
        applies_to_tool_binding_ids=["tool.plugin_default", "tool.custom_plugin"],
        source_ref="services/chat.ts runPluginApi -> API_ENDPOINTS.gateway; server gateway route",
        notes="Server gateway mediates plugin calls and attaches auth; also the SSRF sink (fetches manifest url)."),

    ctl("ctl.plugin_settings_auth", "authorization", "before_tool", "modifying", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[A],
        source_ref="createHeadersWithPluginSettings (plugin secrets -> headers)",
        notes="Injects the user's plugin settings/secrets as request headers (execution identity)."),

    ctl("ctl.abort", "monitoring", "after_model", "blocking", "code",
        failure_mode="abort", applies_to_agent_ids=[A], source_ref="stream AbortController / cancel",
        notes="User can cancel the stream; no automatic per-tool approval or loop cap."),
]
