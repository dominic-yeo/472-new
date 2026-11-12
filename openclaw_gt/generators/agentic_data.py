# -*- coding: utf-8 -*-
"""OpenClaw agentic attack-surface data (schema: agentic-attack-surface-v1).

App: openclaw (self-hosted multi-agent gateway under 472-new/openclaw). A fleet
of agents, each a coding-agent-style run (built-in runner or external runtimes:
claude-cli / codex / copilot / muse) driven over MESSAGING CHANNELS (WhatsApp,
Feishu, Slack, A2A). Native shell+file tools, browser tools, subagent spawn,
cross-agent (agent-to-agent) send, MCP, and skills. Tool execution can run in a
Docker sandbox (default network:none, readOnlyRoot, capDrop ALL) or Crabbox
cloud lease. Gateway hooks (before_tool_call) can block tool calls.

Model is DERIVED FROM REPO DOCS (docs/concepts, docs/gateway, docs/tools) --
authoritative design docs but code symbols not yet confirmed; evidence_status
source_confirmed, visibility white_box; see annotation_issues (doc-derived).
Static pass; runtime grounding pending.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

P = "agent.openclaw.primary"

AGENTS = [
    agent(
        P, "Fleet agent (per channel/role)", "openclaw", "interactive",
        "An agent entry in the fleet; runs a coding-agent loop (built-in or external runtime) over "
        "shell/file/browser/MCP/skill tools, reachable via messaging channels.",
        invocation_surfaces=[
            {"l1_id": "l1.channel.whatsapp", "trigger": "inbound WhatsApp DM/group message (dmPolicy pairing/allowlist)",
             "auth_context": "channel identity gated by DM allowlist; bound agent"},
            {"l1_id": "l1.channel.feishu", "trigger": "inbound Feishu/Slack/other channel message",
             "auth_context": "channel account; agent binding"},
            {"l1_id": "l1.gateway.rpc", "trigger": "Gateway RPC / Control UI talk", "auth_context": "operator/owner"},
            {"l1_id": "l1.a2a.inbound", "trigger": "agent-to-agent message from a peer agent",
             "auth_context": "tools.agentToAgent allow policy"},
        ],
        model_config={"provider": "configurable per agentRuntime (claude-cli/codex/copilot/muse/openclaw)",
                     "model": "provider/model runtime policy", "config_source": "agents.defaults + agents.entries.* (operator)",
                     "writers": [writer("operator", "l1.config.agents"), writer("plugin", "l1.plugin.before_prompt_build")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[
            {"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
             "config_version": "runtime", "writers": [writer("operator", "l1.config.agents")]},
            {"surface_id": "ctx.skill_instructions", "instruction_role": "developer", "precedence": "injected",
             "config_version": "runtime", "writers": [writer("operator", "l1.workspace.skills"), writer("agent", None)]},
            {"surface_id": "ctx.plugin_injected", "instruction_role": "system", "precedence": "injected",
             "config_version": "runtime", "writers": [writer("plugin", "l1.plugin.before_prompt_build")]},
        ],
        tool_binding_ids=["tool.exec", "tool.file", "tool.browser", "tool.message", "tool.subagent_spawn",
                         "tool.agent_send", "tool.mcp", "tool.skills", "tool.session"],
        context_source_ids=["ctx.system_prompt", "ctx.skill_instructions", "ctx.plugin_injected",
                          "ctx.channel_message", "ctx.session_history", "ctx.tool_results", "ctx.browser_content",
                          "ctx.tool_descriptions", "ctx.subagent_task", "ctx.cross_agent_message"],
        memory_ids=["mem.sessions", "mem.workspace", "mem.skills", "mem.fleet_config"],
        output_sink_ids=["sink.channel_reply", "sink.exec", "sink.browser", "sink.file_write",
                         "sink.agent_send", "sink.mcp_call"],
        control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.dm_allowlist", "ctl.agent_to_agent",
                     "ctl.skill_allowlist", "ctl.owner_trust", "ctl.tool_arg_validation", "ctl.session_visibility"],
        resource_limits={"max_iterations": "turn-scoped; model attempt timeout aborts a stuck attempt",
                        "recursion": "subagent spawn depth + child limits", "token_or_cost_budget": "global capacity + per-turn",
                        "loop_detection": "session controller serialization + host stop decisions", "enforced_by": "code"},
        authority_context={"principal_source": "messaging-channel sender (gated) or operator",
                         "tenant_scope": "per-agent workspace/session; fleet isolation",
                         "resource_scope": "agent workspace + sandbox; channel account; allowed peer agents",
                         "delegated_identity": "tools run in the agent's workspace/sandbox; messaging under the channel account",
                         "authz_enforcement": "code/config (DM allowlist + agentToAgent allow + skill allowlist + sandbox + hooks)"},
        related_l2_ids=["l2.agent.channel_run"],
        source_ref="docs/concepts/agent-loop.md; agent-runtimes.md; docs/gateway/*; src (TS monorepo)",
        notes="Untrusted entry is a channel message: anyone who passes the DM allowlist can drive the agent "
              "and its tools. The core attack surface.",
    ),
    agent(
        "agent.openclaw.subagent", "Sub-agent (background spawn)", "openclaw", "specialist",
        "Background run spawned from a parent (agent:<id>:subagent:<uuid>), session-separated, with a "
        "deliberately restricted tool surface (no session/message tools by default).",
        invocation_surfaces=[{"l1_id": "l1.internal.subagent_spawn", "trigger": "sessions_spawn / subagent tool",
                            "auth_context": "parent agent; operator approval for creation hierarchy"}],
        model_config={"provider": "agents.defaults.subagents.model or per-agent override", "model": "subagent model",
                     "config_source": "subagents config", "writers": [writer("operator", "l1.config.agents")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.subagent_task", "instruction_role": "developer", "precedence": "base",
                            "config_version": "runtime", "writers": [writer(P, None)]}],
        tool_binding_ids=["tool.exec", "tool.file", "tool.browser", "tool.mcp"],
        context_source_ids=["ctx.subagent_task", "ctx.tool_results", "ctx.browser_content"],
        memory_ids=["mem.sessions", "mem.workspace"],
        output_sink_ids=["sink.exec", "sink.browser", "sink.file_write", "sink.subagent_result"],
        control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.subagent_policy"],
        resource_limits={"max_iterations": "turn-scoped", "recursion": "own spawn depth/child limits still govern",
                        "token_or_cost_budget": "subagent model budget", "loop_detection": "lifecycle owner",
                        "enforced_by": "code"},
        authority_context={"principal_source": "parent agent (inherited sender)",
                         "tenant_scope": "separate session; optional separate sandbox",
                         "resource_scope": "restricted: no session/message tools by default",
                         "delegated_identity": "inherited sender + sandbox/channel restrictions",
                         "authz_enforcement": "code (tools.subagents.tools; allowAgents; spawn limits)"},
        related_l2_ids=["l2.agent.channel_run"],
        source_ref="docs/concepts/multi-agent.md; docs/tools/subagents.md",
        notes="Hidden subagents get the restrictive tool denies; visible spawned sessions are interactive and "
              "get message/session tools."),
    agent(
        "agent.openclaw.system", "System agent (ring-zero)", "openclaw", "other",
        "Privileged system/owner agent governing fleet creation, onboarding, and owner-trust decisions.",
        invocation_surfaces=[{"l1_id": "l1.gateway.system", "trigger": "system-agent chat / ring-zero setup",
                            "auth_context": "owner/operator; ring-zero"}],
        model_config={"provider": "configured", "model": "system model", "config_source": "operator",
                     "writers": [writer("operator", "l1.config.agents")], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("operator", "l1.config.agents")]}],
        tool_binding_ids=["tool.subagent_spawn", "tool.agent_send", "tool.session", "tool.message"],
        context_source_ids=["ctx.system_prompt", "ctx.channel_message", "ctx.session_history"],
        memory_ids=["mem.fleet_config", "mem.sessions"],
        output_sink_ids=["sink.agent_send", "sink.channel_reply"],
        control_ids=["ctl.owner_trust", "ctl.before_tool_hook"], resource_limits=None,
        authority_context={"principal_source": "owner/operator", "tenant_scope": "fleet-wide",
                         "resource_scope": "fleet creation + role assignment", "delegated_identity": "ring-zero/owner",
                         "authz_enforcement": "human approval for creation/role instructions + owner trust"},
        related_l2_ids=["l2.agent.channel_run"],
        source_ref="docs/concepts/multi-agent.md (ownership, ring-zero); qa/scenarios/config/system-agent-ring-zero-setup.yaml",
        notes="Elevated authority node; role instructions require human approval before taking effect."),
]

_ws_sandbox = {"identity": "agent workspace/sandbox process", "credential_source": "agent config / sandbox lease"}
_argh = {"validation": "tool args validated against the tool schema before execution", "authorization": "before_tool_call hook + policy",
         "normalization": "runtime-specific", "enforced_by": "code"}


def _env(sandbox, egress, fs, by="platform_config"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


TOOLS = [
    tool("tool.exec", P, "shell / exec (native)", "native", "code_execution",
         capabilities=["run shell commands; background exec"], execution_identity=_ws_sandbox,
         execution_environment=_env("Docker sandbox (default network:none, readOnlyRoot, capDrop ALL) or Crabbox lease "
                                  "or UNSANDBOXED host if sandbox off", "none by default; host network if unsandboxed",
                                  "agent/sandbox workspace", by="platform_config"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "sink.exec"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook"],
         source_ref="docs/gateway/sandboxing/docker-backend.md; agent-loop tool execution",
         notes="Arbitrary command execution; isolation depends on sandbox config -> UNSANDBOXED host runs = full RCE."),

    tool("tool.file", P, "file read/write (native)", "native", "mixed",
         capabilities=["read/write/edit files in the workspace"], execution_identity=_ws_sandbox,
         execution_environment=_env("sandbox or host workspace", "none", "workspace root", by="platform_config"),
         output_ids=["mem.workspace", "ctx.tool_results", "sink.file_write"], control_ids=["ctl.sandbox", "ctl.before_tool_hook"],
         source_ref="docs agent-runtimes (native shell and file tools)",
         notes="Writing workspace files incl. skills = stored-instruction injection (ties ctx.skill_instructions)."),

    tool("tool.browser", P, "browser tools", "native", "mixed",
         capabilities=["drive a (sandboxed) browser: navigate, read, act"], execution_identity=_ws_sandbox,
         execution_environment=_env("sandboxed browser container (hot containers)", "browser egress",
                                  "browser profile", by="platform_config"),
         output_ids=["ctx.browser_content", "ctx.tool_results", "sink.browser"], control_ids=["ctl.sandbox", "ctl.before_tool_hook"],
         source_ref="docs/tools/browser/agent-tools.md; sandboxed browser",
         reachability=reach("conditionally_mounted", "browser tools enabled"),
         notes="Fetches arbitrary web content -> indirect injection + egress; sandboxed browser bounds it."),

    tool("tool.message", P, "messaging / session send", "native", "external_send",
         capabilities=["reply/send to messaging channels; session/conversation sends"],
         execution_identity={"identity": "channel account", "credential_source": "channel connection (WhatsApp/Feishu/...)"},
         output_ids=["sink.channel_reply"], control_ids=["ctl.before_tool_hook"],
         source_ref="docs agent-loop (messaging tool sends tracked)",
         notes="Delivers model-composed content to real messaging recipients under the channel account."),

    tool("tool.subagent_spawn", P, "spawn sub-agent / sessions_spawn", "native", "none",
         capabilities=["spawn background or visible sub-agent sessions"], execution_identity=_ws_sandbox,
         output_ids=["ctx.subagent_task", "sink.subagent_result"], control_ids=["ctl.subagent_policy", "ctl.owner_trust"],
         source_ref="docs/concepts/multi-agent.md; docs/tools/subagents.md",
         notes="Delegation; spawn depth/child limits + allowAgents + operator approval govern creation."),

    tool("tool.agent_send", P, "agent-to-agent send (A2A)", "native", "external_send",
         capabilities=["send a message to a peer agent in the fleet"], execution_identity={"identity": "this agent",
                                                                                           "credential_source": "fleet auth"},
         output_ids=["sink.agent_send"], control_ids=["ctl.agent_to_agent"],
         source_ref="docs/tools/agent-send.md; tools.agentToAgent",
         reachability=reach("conditionally_mounted", "tools.agentToAgent.enabled + allow pair"),
         notes="Cross-agent messaging -> a compromised/injected agent can drive peers (lateral movement), bounded by allow."),

    tool("tool.mcp", P, "MCP server tools", "mcp", "mixed",
         server_or_provider="configured MCP servers", capabilities=["call MCP tools (bundled or external)"],
         description_source={"source_ref": "MCP tool listing (remote)",
                           "writers": [writer("external_service", None), writer("operator", "l1.config.mcp")]},
         execution_identity={"identity": "MCP client", "credential_source": "MCP server config"},
         execution_environment=_env("remote MCP server", "per server", "remote", by="external_service"),
         output_ids=["ctx.tool_results", "ctx.tool_descriptions", "sink.mcp_call"], control_ids=["ctl.before_tool_hook"],
         source_ref="docs/tools/multi-agent-sandbox-tools.md; docker-agent-bundle-mcp-tools qa",
         reachability=reach("conditionally_mounted", "MCP server configured"),
         notes="Remote tool descriptions model-facing -> rug-pull; MCP can also be bundled in the sandbox."),

    tool("tool.skills", P, "skills (read/use)", "native", "read",
         capabilities=["load and use workspace/shared skills (allowlisted)"], execution_identity=_ws_sandbox,
         output_ids=["ctx.skill_instructions", "ctx.tool_results"], control_ids=["ctl.skill_allowlist"],
         source_ref="docs multi-agent (skills allowlist); ~/.openclaw/skills",
         notes="Skills are instruction content filtered by the agent skill allowlist; editable -> stored injection."),

    tool("tool.session", P, "session / conversation tools", "native", "read",
         capabilities=["read sessions/transcripts; cross-agent session access (visibility-governed)"],
         execution_identity=_ws_sandbox, output_ids=["ctx.session_history", "ctx.tool_results"],
         control_ids=["ctl.session_visibility", "ctl.agent_to_agent"],
         source_ref="docs multi-agent (tools.sessions.visibility; cross-agent session access)",
         notes="Cross-agent session visibility (tree/all) can expose other agents' transcripts."),
]

_dest = [P, "agent.openclaw.subagent"]
CONTEXT = [
    ctx("ctx.system_prompt", "system_prompt", "trusted_instruction", source_ref="prompt assembly; agent role instructions",
        writers=[writer("operator", "l1.config.agents")], destination_agent_ids=[P, "agent.openclaw.system"],
        destination_channel="system", provenance="operator/role config", persistence_scope="tenant",
        notes="Role instructions require human approval before taking effect."),

    ctx("ctx.skill_instructions", "developer_prompt", "mixed", source_ref="workspace/shared skill files (allowlisted)",
        writers=[writer("operator", "l1.workspace.skills"), writer("agent", None)], destination_agent_ids=_dest,
        destination_channel="developer", provenance="skill files", persistence_scope="tenant",
        notes="Skill files are instruction content; writable by file tools -> stored prompt injection."),

    ctx("ctx.plugin_injected", "system_prompt", "mixed", source_ref="before_prompt_build hook (prependContext/systemPrompt)",
        writers=[writer("plugin", "l1.plugin.before_prompt_build")], destination_agent_ids=[P],
        destination_channel="system", provenance="plugins (pluginOwnerId trust)", persistence_scope="global",
        notes="Plugins can inject system context; trust tied to pluginOwnerId."),

    ctx("ctx.channel_message", "user_input", "untrusted_data", source_ref="inbound messaging (WhatsApp/Feishu/Slack/...)",
        writers=[writer("channel_sender", "l1.channel.whatsapp")], destination_agent_ids=[P, "agent.openclaw.system"],
        destination_channel="user", provenance="messaging sender (DM allowlist)", persistence_scope="session",
        notes="PRIMARY untrusted entry: a message drives the agent + its tools; gated only by DM allowlist/pairing."),

    ctx("ctx.session_history", "chat_history", "mixed", source_ref="session transcript",
        writers=[writer("channel_sender", "l1.channel.whatsapp"), writer(P, None)], destination_agent_ids=[P, "agent.openclaw.system"],
        destination_channel="user", provenance="prior turns", persistence_scope="session"),

    ctx("ctx.tool_results", "tool_result", "untrusted_data", source_ref="exec/file/browser/MCP tool output",
        writers=[writer(P, None), writer("external_service", None)], destination_agent_ids=_dest,
        destination_channel="tool", provenance="tool output", persistence_scope="session"),

    ctx("ctx.browser_content", "external", "untrusted_data", source_ref="browser tool page content",
        writers=[writer("external_service", None)], destination_agent_ids=_dest, destination_channel="tool",
        provenance="arbitrary web", persistence_scope="session",
        notes="Fetched page content -> indirect injection."),

    ctx("ctx.tool_descriptions", "external", "untrusted_data", source_ref="MCP tool listings presented to the model",
        writers=[writer("external_service", None), writer("operator", "l1.config.mcp")], destination_agent_ids=_dest,
        destination_channel="tool", provenance="remote MCP specs", persistence_scope="tenant",
        notes="Remote MCP descriptions model-facing -> rug-pull."),

    ctx("ctx.subagent_task", "delegated_summary", "mixed", source_ref="parent -> subagent task",
        writers=[writer(P, None)], destination_agent_ids=["agent.openclaw.subagent"], destination_channel="developer",
        provenance="parent agent", persistence_scope="workflow",
        notes="Parent-composed subagent task -> parent->child injection."),

    ctx("ctx.cross_agent_message", "external", "untrusted_data", source_ref="A2A inbound from a peer agent",
        writers=[writer("peer_agent", "l1.a2a.inbound")], destination_agent_ids=[P], destination_channel="user",
        provenance="peer fleet agent", persistence_scope="session",
        reachability=reach("conditionally_mounted", "agentToAgent enabled + allowed pair"),
        notes="Cross-agent message = another agent's (possibly injected) output driving this one -> lateral injection."),
]

MEMORY = [
    mem("mem.sessions", "conversation_history", "openclaw", "session",
        readers=[P, "agent.openclaw.subagent", "agent.openclaw.system"],
        writers=[writer("channel_sender", "l1.channel.whatsapp"), writer(P, None)],
        isolation_enforcement="per session identity; cross-agent access governed by tools.sessions.visibility",
        write_provenance="channel messages + agent turns", read_path="session transcript replayed into turn",
        retention_and_deletion="session lifecycle", source_ref="docs session/workspace preparation",
        notes="Cross-agent session visibility (tree/all) can cross agent boundaries."),

    mem("mem.workspace", "database", "openclaw", "tenant",
        readers=[P, "agent.openclaw.subagent"], writers=[writer(P, None), writer("operator", "l1.workspace.files")],
        isolation_enforcement="per-agent workspace root; sandbox redirect for sandboxed runs",
        write_provenance="file tools + operator", read_path="file tools read the workspace",
        retention_and_deletion="workspace lifecycle", source_ref="docs workspace preparation",
        notes="Agent workspace filesystem; sandboxed runs use a sandbox workspace root."),

    mem("mem.skills", "database", "openclaw", "tenant",
        readers=[P, "agent.openclaw.subagent"], writers=[writer("operator", "l1.workspace.skills"), writer(P, None)],
        isolation_enforcement="agent skill allowlist", write_provenance="skill authors + file tools",
        read_path="skills loaded into context (allowlist-filtered)", retention_and_deletion="workspace-managed",
        source_ref="docs/tools/skills; multi-agent skill allowlists",
        notes="Instruction store -> stored prompt injection surface."),

    mem("mem.fleet_config", "database", "openclaw", "global",
        readers=[P, "agent.openclaw.system"], writers=[writer("operator", "l1.config.agents")],
        isolation_enforcement="operator-only config; ownership explicit", write_provenance="operator",
        read_path="agent entries/roles/allowlists resolved per run", retention_and_deletion="operator-managed",
        source_ref="docs multi-agent (agents.defaults/entries, ownership, allowAgents)",
        notes="Fleet wiring: roles, allowlists, owner, agentToAgent allow -- the policy that bounds everything."),
]

SINKS = [
    sink("sink.channel_reply", "notification", producer_ids=[P, "tool.message", "agent.openclaw.system"],
         audience="messaging recipients (WhatsApp/Feishu/Slack)", delivery="channel send under the channel account",
         render_side_effects={"auto_fetch": "recipient client may render links/media",
                            "active_content": "channel-dependent", "enforced_by": "external_service"},
         related_l2_ids=["l2.agent.channel_run"], source_ref="docs channels; agent-loop messaging sends",
         notes="Model-composed content delivered to real recipients; exfil/abuse via outbound messages."),

    sink("sink.exec", "external_api", producer_ids=["tool.exec"], audience="sandbox/host shell",
         delivery="command execution in sandbox (or host if unsandboxed)", source_ref="docker/crabbox backend",
         notes="RCE-class if sandbox disabled; network:none by default in docker sandbox."),

    sink("sink.browser", "external_api", producer_ids=["tool.browser"], audience="arbitrary web",
         delivery="sandboxed browser actions", becomes_context_source_ids=["ctx.browser_content"],
         source_ref="sandboxed browser"),

    sink("sink.file_write", "file", producer_ids=["tool.file"], audience="agent workspace",
         delivery="file write", becomes_context_source_ids=["ctx.skill_instructions", "ctx.tool_results"],
         source_ref="file tools", notes="Writing skills/files feeds back as instructions/context."),

    sink("sink.agent_send", "delegated_result", producer_ids=["tool.agent_send", "agent.openclaw.system"],
         audience="peer fleet agents", delivery="A2A message", becomes_context_source_ids=["ctx.cross_agent_message"],
         related_l2_ids=["l2.agent.channel_run"], source_ref="docs/tools/agent-send.md",
         notes="Becomes a peer's ctx.cross_agent_message -> lateral movement path (allow-gated)."),

    sink("sink.mcp_call", "external_api", producer_ids=["tool.mcp"], audience="MCP servers",
         delivery="MCP call", source_ref="MCP tools"),

    sink("sink.subagent_result", "delegated_result", producer_ids=["agent.openclaw.subagent"],
         audience="parent agent", delivery="subagent result delivered to parent",
         becomes_context_source_ids=["ctx.tool_results"], source_ref="docs/concepts/multi-agent.md",
         notes="Child->parent path."),
]


def _S(step, ag=P):
    return {"agent_id": ag, "step": step, "external_trigger": None}


EDGES = [
    edge("edge.channel__primary", "external_event",
         source={"agent_id": None, "step": "inbound", "external_trigger": "messaging channel (WhatsApp/Feishu/...)"},
         destination={"agent_id": P}, condition="inbound channel message passes DM allowlist -> agent run",
         input_source_ids=["ctx.channel_message", "ctx.system_prompt", "ctx.skill_instructions"],
         payload="channel message", control_ids=["ctl.dm_allowlist"], execution_mode="queued",
         failure_behavior="abort", related_l1_ids=["l1.channel.whatsapp"],
         related_l2_steps=[{"l2_id": "l2.agent.channel_run", "order": 1}],
         source_ref="docs channels; agent-loop intake",
         notes="THE external attack entry: untrusted messaging drives the agent, gated only by DM allowlist."),

    edge("edge.primary__tool", "llm", source=_S("tool-call"),
         destination={"tool_binding_id": "(model-selected binding)"},
         condition="model emits a tool call -> validated + before_tool_call hook",
         argument_sources="model-composed args (validated against schema)",
         input_source_ids=["ctx.channel_message", "ctx.session_history", "ctx.tool_results", "ctx.browser_content",
                          "ctx.skill_instructions", "ctx.tool_descriptions", "ctx.cross_agent_message"],
         payload="tool name + args", output_ids=["ctx.tool_results"],
         control_ids=["ctl.tool_arg_validation", "ctl.before_tool_hook", "ctl.sandbox"],
         validation_or_approval="schema validation + before_tool_call hook ({block:true} terminal) + sandbox",
         execution_mode="synchronous", loop_bound="turn-scoped; attempt timeout",
         failure_behavior="fail_closed", related_l2_steps=[{"l2_id": "l2.agent.channel_run", "order": 2}],
         source_ref="docs agent-loop tool execution + hooks",
         notes="Programmable gateway hook can block a tool call; sandbox bounds exec/browser."),

    edge("edge.tool__primary", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": P}, condition="tool returns (tool_result_persist hook transforms)",
         payload="tool result", output_ids=["ctx.tool_results"], control_ids=["ctl.before_tool_hook"],
         execution_mode="synchronous", failure_behavior="retry",
         related_l2_steps=[{"l2_id": "l2.agent.channel_run", "order": 3}],
         source_ref="docs hooks (after_tool_call / tool_result_persist)"),

    edge("edge.primary__subagent", "llm", source=_S("spawn"),
         destination={"agent_id": "agent.openclaw.subagent"}, condition="model spawns a sub-agent",
         argument_sources="model-composed task", payload="subagent task", output_ids=["ctx.subagent_task"],
         control_ids=["ctl.subagent_policy", "ctl.owner_trust"], execution_mode="background",
         loop_bound="spawn depth + child limits", failure_behavior="partial_effect",
         related_l1_ids=["l1.internal.subagent_spawn"], source_ref="docs/tools/subagents.md",
         notes="Restricted child tool surface by default; operator approval for creation hierarchy."),

    edge("edge.subagent__primary", "deterministic_code",
         source={"agent_id": "agent.openclaw.subagent", "step": "result", "external_trigger": None},
         destination={"agent_id": P, "output_sink_id": "sink.subagent_result"}, condition="subagent run ends",
         payload="subagent result", output_ids=["sink.subagent_result", "ctx.tool_results"],
         execution_mode="callback", failure_behavior="partial_effect", source_ref="docs multi-agent"),

    edge("edge.primary__peer", "llm", source=_S("a2a"),
         destination={"tool_binding_id": "tool.agent_send", "external_surface": "peer fleet agent"},
         condition="model sends to a peer agent", argument_sources="model-composed message",
         payload="cross-agent message", output_ids=["sink.agent_send"], control_ids=["ctl.agent_to_agent"],
         execution_mode="synchronous", failure_behavior="fail_closed", source_ref="docs/tools/agent-send.md",
         notes="Lateral path -> peer's ctx.cross_agent_message; bounded by agentToAgent allow."),

    edge("edge.primary__exec", "llm", source=_S("exec"),
         destination={"tool_binding_id": "tool.exec", "external_surface": "sandbox/host shell"},
         condition="model runs a shell command", argument_sources="model-composed command",
         payload="shell command", output_ids=["sink.exec", "ctx.tool_results"], control_ids=["ctl.sandbox", "ctl.before_tool_hook"],
         execution_mode="synchronous", failure_behavior="abort", source_ref="docs sandboxing",
         notes="Isolation depends on sandbox config; unsandboxed = host RCE."),

    edge("edge.primary__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.channel_reply"}, condition="agent produces a reply",
         payload="reply to channel", output_ids=["sink.channel_reply"], execution_mode="synchronous",
         failure_behavior="abort", source_ref="docs agent-loop streaming/persistence",
         related_l2_steps=[{"l2_id": "l2.agent.channel_run", "order": 4}]),
]

_all = [P, "agent.openclaw.subagent", "agent.openclaw.system"]
CONTROLS = [
    ctl("ctl.sandbox", "tool_policy", "before_tool", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.openclaw.subagent"],
        applies_to_tool_binding_ids=["tool.exec", "tool.file", "tool.browser"],
        source_ref="docs/gateway/sandboxing/{docker-backend,crabbox-backend}.md",
        notes="Docker sandbox defaults network:none + readOnlyRoot + capDrop ALL; Crabbox cloud lease. "
              "If sandboxing is DISABLED, exec/file/browser run on the host -> major posture change."),

    ctl("ctl.before_tool_hook", "tool_policy", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="docs agent-loop hooks (before_tool_call {block:true} terminal; outbound guards)",
        notes="Programmable gateway/plugin hook can block any tool call; also after_tool_call / tool_result_persist."),

    ctl("ctl.dm_allowlist", "authorization", "before_model", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.openclaw.system"],
        source_ref="docs channels (dmPolicy: allowlist/pairing; allowFrom)",
        notes="Decides WHO can message (invoke) the agent. Global per channel account, not per agent. The "
              "primary external authorization boundary."),

    ctl("ctl.agent_to_agent", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        applies_to_tool_binding_ids=["tool.agent_send", "tool.session"],
        source_ref="docs multi-agent (tools.agentToAgent allow/enabled; sessions.visibility)",
        notes="Bounds cross-agent messaging + session visibility -> limits lateral movement across the fleet."),

    ctl("ctl.subagent_policy", "tool_policy", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, "agent.openclaw.system"],
        applies_to_tool_binding_ids=["tool.subagent_spawn"],
        source_ref="docs/tools/subagents.md; multi-agent (allowAgents, spawn depth, child limits)",
        notes="Subagents get a restricted tool surface by default (no session/message tools); spawn targets allowlisted."),

    ctl("ctl.skill_allowlist", "tool_policy", "before_model", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        applies_to_tool_binding_ids=["tool.skills"],
        source_ref="docs multi-agent + skills (agent skill allowlist)",
        notes="Filters which skills (instruction bundles) load per agent."),

    ctl("ctl.owner_trust", "human_approval", "delegation", "blocking", "human_process",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="docs multi-agent (ownership explicit; operator approval for creation/role instructions; ring-zero)",
        notes="Human/operator approval governs fleet creation hierarchy and role-instruction changes; pluginOwnerId trust."),

    ctl("ctl.tool_arg_validation", "input_filter", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="docs agent-loop (tool arguments validated against schema before execution)",
        notes="Structural validation; also hides serialized shadow tool-call copies from replies."),

    ctl("ctl.session_visibility", "authorization", "memory_read", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        applies_to_tool_binding_ids=["tool.session"],
        source_ref="docs multi-agent (tools.sessions.visibility: tree/all/none)",
        notes="Controls cross-agent transcript reads."),
]
