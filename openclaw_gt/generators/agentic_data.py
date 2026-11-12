# -*- coding: utf-8 -*-
"""OpenClaw agentic attack-surface data (schema: agentic-attack-surface-v1).

App: openclaw (self-hosted multi-agent gateway under 472-new/openclaw). A fleet
of agents, each a coding-agent-style run (built-in runner or external runtimes:
claude-cli / codex / copilot / muse) driven over MESSAGING CHANNELS (WhatsApp,
Feishu, Slack, ...) plus a gateway RPC/control surface, agent-to-agent (A2A)
fleet messaging, and a cron scheduler that can trigger the agent's own future
turns. Native terminal(bash)/file/web/computer tools, subagent spawn, A2A send,
MCP, skills, media + github tools. Tool execution runs in a Docker sandbox
(default network "none", readOnlyRoot true, capDrop ALL) or Crabbox lease, or on
the host if the sandbox is disabled. A before_tool_call hook/policy chain can
block any tool call.

CODE-GROUNDED pass (Phases A-D). Every record's source_ref now cites TypeScript
symbols in src/ + packages/ (not docs). evidence_status=source_confirmed,
visibility white_box. Runtime grounding (Phase E -> observed) is blocked in this
offline environment (no network/docker/model provider); reachability is set from
source gating and a per-record grounding runbook is in environment.yaml. See
annotation_issues (code-grounded, phase-e-offline). Phase F (L1/L2 linkage) is
closed against ../l1_gt.yaml + ../l2_gt.yaml.
"""
from agentic_lib import agent, tool, ctx, mem, sink, edge, ctl, reach, writer

P = "agent.openclaw.primary"
SUB = "agent.openclaw.subagent"
SYS = "agent.openclaw.system"

# ---- L2 operations this layer participates in (defined in ../l2_gt.yaml) ----
L2_RUN = "l2.agent.channel_run"
L2_CRON = "l2.agent.scheduled_run"
L2_SPAWN = "l2.agent.subagent_delegation"
L2_A2A = "l2.agent.a2a_dispatch"

AGENTS = [
    agent(
        P, "Fleet agent (per channel/role)", "openclaw", "interactive",
        "An agent entry in the fleet; runs the agent-core loop (packages/agent-core/src/agent-loop.ts, "
        "built-in or external runtime) over terminal/file/web/computer/MCP/skill tools, reachable via "
        "messaging channels, gateway RPC, A2A, and the cron scheduler.",
        invocation_surfaces=[
            {"l1_id": "l1.channel.whatsapp", "trigger": "inbound WhatsApp DM/group message (dmPolicy pairing/allowlist)",
             "auth_context": "channel identity gated by DM allowlist; bound agent"},
            {"l1_id": "l1.channel.feishu", "trigger": "inbound Feishu/Slack/other channel message",
             "auth_context": "channel account; agent binding"},
            {"l1_id": "l1.gateway.rpc", "trigger": "Gateway RPC / Control UI talk", "auth_context": "operator/owner"},
            {"l1_id": "l1.a2a.inbound", "trigger": "agent-to-agent message from a peer agent",
             "auth_context": "tools.agentToAgent allow policy"},
            {"l1_id": "l1.cron.scheduled", "trigger": "cron/scheduled self-triggered turn",
             "auth_context": "job creator identity; creator cap"},
        ],
        model_config={"provider": "configurable per agentRuntime (claude-cli/codex/copilot/muse/openclaw)",
                     "model": "provider/model runtime policy", "config_source": "agents.defaults + agents.entries.* (operator)",
                     "writers": [writer("operator", "l1.config.agents"), writer("plugin", "l1.plugin.hook")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[
            {"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
             "config_version": "runtime", "writers": [writer("operator", "l1.config.agents")]},
            {"surface_id": "ctx.skill_instructions", "instruction_role": "developer", "precedence": "injected",
             "config_version": "runtime", "writers": [writer("operator", "l1.workspace.skills"), writer("agent", None)]},
            {"surface_id": "ctx.plugin_injected", "instruction_role": "system", "precedence": "injected",
             "config_version": "runtime", "writers": [writer("plugin", "l1.plugin.hook")]},
        ],
        tool_binding_ids=["tool.primary.terminal", "tool.primary.file_read", "tool.primary.apply_patch",
                         "tool.primary.web_fetch", "tool.primary.web_search", "tool.primary.computer",
                         "tool.primary.message", "tool.primary.sessions_send", "tool.primary.sessions_spawn",
                         "tool.primary.sessions_read", "tool.primary.cron", "tool.primary.ask_user",
                         "tool.primary.mcp", "tool.primary.skills", "tool.primary.github",
                         "tool.primary.media", "tool.primary.gateway"],
        context_source_ids=["ctx.system_prompt", "ctx.skill_instructions", "ctx.plugin_injected",
                          "ctx.channel_message", "ctx.session_history", "ctx.tool_results", "ctx.web_content",
                          "ctx.tool_descriptions", "ctx.subagent_task", "ctx.cross_agent_message",
                          "ctx.cron_prompt", "ctx.ask_user_response"],
        memory_ids=["mem.sessions", "mem.workspace", "mem.skills", "mem.fleet_config", "mem.cron_jobs"],
        output_sink_ids=["sink.channel_reply", "sink.exec", "sink.web_egress", "sink.file_write",
                         "sink.agent_send", "sink.mcp_call", "sink.github", "sink.media", "sink.cron_schedule"],
        control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.dm_allowlist", "ctl.agent_to_agent",
                     "ctl.skill_allowlist", "ctl.owner_trust", "ctl.tool_arg_validation", "ctl.session_visibility",
                     "ctl.exec_approval", "ctl.net_policy_ssrf", "ctl.requester_tool_policy", "ctl.cron_creator_cap"],
        resource_limits={"max_iterations": "turn/attempt scoped; model attempt timeout aborts a stuck attempt",
                        "recursion": "subagent spawn depth + child limits (sessions-spawn)",
                        "token_or_cost_budget": "global capacity + per-turn (agent-loop steering)",
                        "loop_detection": "assistant-repetition-guard.ts + repetition-guard.ts; session serialization",
                        "enforced_by": "code"},
        authority_context={"principal_source": "messaging-channel sender (gated) or operator",
                         "tenant_scope": "per-agent workspace/session; fleet isolation",
                         "resource_scope": "agent workspace + sandbox; channel account; allowed peer agents",
                         "delegated_identity": "tools run in the agent's workspace/sandbox; messaging under the channel account",
                         "authz_enforcement": "code/config (DM allowlist + agentToAgent allow + requester tool policy + "
                                              "skill allowlist + sandbox + before_tool_call hook)"},
        related_l2_ids=[L2_RUN, L2_CRON],
        source_ref="packages/agent-core/src/agent-loop.ts; agent-loop-tool-execution.ts; src/agents/* "
                   "(embedded-agent-runner, cli-runner); src/channels/* (inbound-event); src/cron/*",
        notes="Untrusted entry is a channel message (or A2A/cron prompt): anyone who passes the DM allowlist can "
              "drive the agent + its tools. The core attack surface."),

    agent(
        SUB, "Sub-agent (background spawn)", "openclaw", "specialist",
        "Background run spawned from a parent (sessions_spawn / subagents-tool), session-separated, with a "
        "deliberately restricted tool surface (no session/message/spawn tools by default).",
        invocation_surfaces=[{"l1_id": "l1.internal.subagent_spawn", "trigger": "sessions_spawn / subagents tool",
                            "auth_context": "parent agent; allowAgents + spawn limits"}],
        model_config={"provider": "agents.defaults.subagents.model or per-agent override", "model": "subagent model",
                     "config_source": "subagents config", "writers": [writer("operator", "l1.config.agents")],
                     "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.subagent_task", "instruction_role": "developer", "precedence": "base",
                            "config_version": "runtime", "writers": [writer(P, None)]}],
        tool_binding_ids=["tool.subagent.terminal", "tool.subagent.file_read", "tool.subagent.apply_patch",
                         "tool.subagent.web_fetch", "tool.subagent.computer", "tool.subagent.mcp"],
        context_source_ids=["ctx.subagent_task", "ctx.tool_results", "ctx.web_content"],
        memory_ids=["mem.sessions", "mem.workspace"],
        output_sink_ids=["sink.exec", "sink.web_egress", "sink.file_write", "sink.subagent_result"],
        control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.subagent_policy", "ctl.net_policy_ssrf",
                     "ctl.requester_tool_policy"],
        resource_limits={"max_iterations": "turn/attempt scoped", "recursion": "own spawn depth/child limits still govern",
                        "token_or_cost_budget": "subagent model budget", "loop_detection": "lifecycle owner",
                        "enforced_by": "code"},
        authority_context={"principal_source": "parent agent (inherited sender)",
                         "tenant_scope": "separate session; optional separate sandbox",
                         "resource_scope": "restricted: no session/message/spawn tools by default",
                         "delegated_identity": "inherited sender + sandbox/channel restrictions",
                         "authz_enforcement": "code (tools.subagents.tools denylist; allowAgents; spawn limits)"},
        related_l2_ids=[L2_SPAWN],
        source_ref="src/agents/tools/subagents-tool.ts; sessions-spawn-tool.ts; sessions-spawn-access-program.ts; "
                   "delegated-tool-policy.ts",
        notes="Hidden subagents get the restrictive tool denies; visible spawned sessions are interactive and "
              "get message/session tools."),

    agent(
        SYS, "System agent (ring-zero)", "openclaw", "other",
        "Privileged system/owner agent governing fleet creation, onboarding, and owner-trust decisions "
        "(system-agent-tool).",
        invocation_surfaces=[{"l1_id": "l1.gateway.system", "trigger": "system-agent chat / ring-zero setup",
                            "auth_context": "owner/operator; ring-zero"}],
        model_config={"provider": "configured", "model": "system model", "config_source": "operator",
                     "writers": [writer("operator", "l1.config.agents")], "evidence_status": "source_confirmed"},
        instruction_sources=[{"surface_id": "ctx.system_prompt", "instruction_role": "system", "precedence": "base",
                            "config_version": "runtime", "writers": [writer("operator", "l1.config.agents")]}],
        tool_binding_ids=["tool.system.system_agent", "tool.system.sessions_spawn", "tool.system.sessions_send",
                         "tool.system.message"],
        context_source_ids=["ctx.system_prompt", "ctx.channel_message", "ctx.session_history"],
        memory_ids=["mem.fleet_config", "mem.sessions"],
        output_sink_ids=["sink.agent_send", "sink.channel_reply"],
        control_ids=["ctl.owner_trust", "ctl.before_tool_hook"], resource_limits=None,
        authority_context={"principal_source": "owner/operator", "tenant_scope": "fleet-wide",
                         "resource_scope": "fleet creation + role assignment", "delegated_identity": "ring-zero/owner",
                         "authz_enforcement": "human approval (owner trust) for creation/role instructions"},
        related_l2_ids=[L2_RUN],
        source_ref="src/agents/tools/system-agent-tool.ts; src/agents/execution-authority.ts "
                   "(resolveGatewayExecAuthority); qa/scenarios/config/system-agent-ring-zero-setup.yaml",
        notes="Elevated authority node; role instructions require human approval before taking effect."),
]

# ---- shared tool fragments -------------------------------------------------
_ws_sandbox = {"identity": "agent workspace/sandbox process",
               "credential_source": "agent config / sandbox lease; resolveGatewayExecAuthority (execution-authority.ts)"}
_argh = {"validation": "tool args validated against the tool JSON schema before execution (agent-loop validation.ts)",
         "authorization": "before_tool_call hook/policy chain (agent-tools.before-tool-call.policy.ts)",
         "normalization": "runtime-specific (tool-call-repair)", "enforced_by": "code"}


def _env(sandbox, egress, fs, by="platform_config"):
    return {"sandbox": sandbox, "network_egress": egress, "filesystem_scope": fs, "enforced_by": by}


_SANDBOX_EXEC = _env(
    "Docker sandbox (src/agents/sandbox/config.ts: network default 'none', readOnlyRoot default true; "
    "container-allocation.ts applies --network + capDrop) or Crabbox lease; UNSANDBOXED host if sandbox disabled",
    "none by default (network 'none'); host network if unsandboxed", "agent/sandbox workspace", by="platform_config")

TOOLS = [
    # ---------- primary agent tools ----------
    tool("tool.primary.terminal", P, "terminal / bash exec", "native", "code_execution",
         l1_ids=["l1.tool.exec_shell"], capabilities=["run shell commands; background/durable exec"],
         execution_identity=_ws_sandbox, execution_environment=_SANDBOX_EXEC, argument_handling=_argh,
         approval_required=True, output_ids=["ctx.tool_results", "sink.exec"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.exec_approval", "ctl.requester_tool_policy"],
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/terminal-tool.ts; src/agents/bash-tools.exec-run.ts; "
                    "bash-tools.exec-approval-request.ts; bash-process-registry.ts",
         notes="Arbitrary command execution; isolation depends on sandbox config -> UNSANDBOXED host runs = full RCE. "
               "Exec can require approval (bash-tools.exec-approval-*)."),

    tool("tool.primary.file_read", P, "read (file)", "native", "read",
         capabilities=["read workspace files"], execution_identity=_ws_sandbox,
         execution_environment=_env("sandbox or host workspace (fs-bridge path-safety)", "none", "workspace root"),
         argument_handling=_argh, output_ids=["ctx.tool_results"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.requester_tool_policy"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/agent-tools.read.ts; src/agents/sandbox/fs-bridge-path-safety.ts",
         notes="Reads workspace files into context; fs-bridge path safety bounds traversal under the workspace root."),

    tool("tool.primary.apply_patch", P, "apply_patch / edit file", "native", "mixed",
         capabilities=["write/edit files in the workspace via apply_patch"], execution_identity=_ws_sandbox,
         execution_environment=_env("sandbox or host workspace", "none", "workspace root"), argument_handling=_argh,
         output_ids=["mem.workspace", "ctx.tool_results", "sink.file_write"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/apply-patch-file-ops.ts; src/agents/sandbox/fs-bridge-mutation-helper.ts",
         notes="Writing workspace files incl. skills = stored-instruction injection (feeds ctx.skill_instructions)."),

    tool("tool.primary.web_fetch", P, "web_fetch", "native", "mixed",
         l1_ids=["l1.tool.web_fetch"], capabilities=["fetch an arbitrary URL and return its content"],
         execution_identity={"identity": "gateway/agent process", "credential_source": "none (anonymous outbound)"},
         execution_environment=_env("host/gateway egress guarded by net-policy SSRF check", "outbound HTTP (SSRF-guarded)",
                                   "n/a", by="code"), argument_handling=_argh,
         output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_egress"],
         control_ids=["ctl.net_policy_ssrf", "ctl.before_tool_hook", "ctl.requester_tool_policy"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/web-fetch.ts; web-guarded-fetch.ts; src/infra/net/ssrf.ts; packages/net-policy/src/{ip,ipv4,url-protocol}.ts",
         notes="Fetches arbitrary web content -> indirect injection + egress. net-policy blocks private/internal IPs (SSRF)."),

    tool("tool.primary.web_search", P, "web_search", "native", "read",
         l1_ids=["l1.tool.web_search"], server_or_provider="configured search provider",
         capabilities=["query a web search provider; return results/citations"],
         execution_identity={"identity": "search-provider API client", "credential_source": "provider credentials (config)"},
         execution_environment=_env("provider API", "outbound to provider", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_egress"],
         control_ids=["ctl.before_tool_hook", "ctl.requester_tool_policy"],
         reachability=reach("conditionally_mounted", "search provider configured (web-search-provider-config.ts)"),
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/web-search.ts; web-search-provider-common.ts; web-search-citation-redirect.ts",
         notes="Returns external search content -> indirect injection; results carry provider citation redirects."),

    tool("tool.primary.computer", P, "computer / browser (computer-use)", "native", "code_execution",
         l1_ids=["l1.tool.browser"], capabilities=["drive a sandboxed browser/computer: navigate, read, click, type"],
         execution_identity=_ws_sandbox,
         execution_environment=_env("sandboxed browser container (bridge network; 'none' unsupported for browser) "
                                   "- sandbox/browser.ts", "browser egress (bridge)", "browser profile", by="platform_config"),
         argument_handling=_argh, output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_egress"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.requester_tool_policy"],
         reachability=reach("conditionally_mounted", "computer/browser tool enabled; sandbox browser bridge required"),
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/computer-tool.ts; computer-tool-gateway.ts; src/agents/sandbox/browser.ts; browser-network.ts",
         notes="Fetches/acts on arbitrary web content -> indirect injection + egress; sandboxed browser bounds it "
               "(network mode 'none' rejected because CDP needs a host-reachable port)."),

    tool("tool.primary.message", P, "message (channel send)", "native", "external_send",
         l1_ids=["l1.tool.message_send"], capabilities=["reply/send to messaging channels; explicit-target + group-thread sends"],
         execution_identity={"identity": "channel account", "credential_source": "channel connection (WhatsApp/Feishu/...)"},
         argument_handling=_argh, output_ids=["sink.channel_reply"],
         control_ids=["ctl.before_tool_hook"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/message-tool-execution.ts; message-tool-explicit-target.ts; message-tool-source-policy.ts",
         notes="Delivers model-composed content to real messaging recipients under the channel account; source policy "
               "bounds which targets are reachable."),

    tool("tool.primary.sessions_send", P, "sessions_send (A2A)", "native", "external_send",
         capabilities=["send a message to a peer agent session in the fleet (A2A)"],
         execution_identity={"identity": "this agent", "credential_source": "fleet auth"},
         argument_handling=_argh, output_ids=["sink.agent_send"], control_ids=["ctl.agent_to_agent"],
         reachability=reach("conditionally_mounted", "tools.agentToAgent.enabled + allowed pair (sessions-send-tool.a2a.ts)"),
         related_l2_ids=[L2_A2A],
         source_ref="src/agents/tools/sessions-send-tool.a2a.ts (runSessionsSendA2AFlow, replyMode peer|one-way); "
                    "sessions-send-tool.delivery.ts",
         notes="Cross-agent messaging -> a compromised/injected agent can drive peers (lateral movement), bounded by "
               "agentToAgent allow policy."),

    tool("tool.primary.sessions_spawn", P, "sessions_spawn / subagent", "native", "none",
         capabilities=["spawn background or visible sub-agent sessions"], execution_identity=_ws_sandbox,
         argument_handling=_argh, output_ids=["ctx.subagent_task", "sink.subagent_result"],
         control_ids=["ctl.subagent_policy", "ctl.owner_trust"], related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts; sessions-spawn-access-program.ts",
         notes="Delegation; spawn depth/child limits + allowAgents + operator approval govern creation."),

    tool("tool.primary.sessions_read", P, "sessions read/history/search", "native", "read",
         capabilities=["read sessions/transcripts; cross-agent session access (visibility-governed)"],
         execution_identity=_ws_sandbox, argument_handling=_argh, output_ids=["ctx.session_history", "ctx.tool_results"],
         control_ids=["ctl.session_visibility", "ctl.agent_to_agent"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/sessions-tool.ts; sessions-history-tool.ts; sessions-search-tool.ts; "
                    "src/plugin-sdk/session-visibility.ts",
         notes="Cross-agent session visibility (tree/all/none) can expose other agents' transcripts."),

    tool("tool.primary.cron", P, "cron / schedule", "native", "write",
         capabilities=["create/list scheduled jobs that trigger future agent turns"], execution_identity=_ws_sandbox,
         argument_handling=_argh, output_ids=["mem.cron_jobs", "sink.cron_schedule", "ctx.tool_results"],
         control_ids=["ctl.cron_creator_cap", "ctl.before_tool_hook"],
         reachability=reach("conditionally_mounted", "cron tool enabled (cron-tool.ts creator cap)"), related_l2_ids=[L2_CRON],
         source_ref="src/agents/tools/cron-tool.ts; cron-tool-creator-cap.ts; cron-tool-write.ts; "
                    "src/cron/agent-turn-command-prompt.ts; src/cron/agent-availability.ts",
         notes="Model can schedule its OWN future turns -> durable, deferred self-trigger (ctx.cron_prompt). "
               "Creator cap bounds how many jobs an agent may create."),

    tool("tool.primary.ask_user", P, "ask_user", "native", "read",
         capabilities=["ask a human a question and await the answer"],
         execution_identity={"identity": "agent", "credential_source": "n/a"}, argument_handling=_argh,
         output_ids=["ctx.ask_user_response", "ctx.tool_results"], control_ids=["ctl.before_tool_hook"],
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/ask-user-tool.ts; ask-user-tool-normalization.ts; question-prompt-send.ts",
         notes="Human answer re-enters context as untrusted user input (ctx.ask_user_response)."),

    tool("tool.primary.mcp", P, "MCP server tools", "mcp", "mixed",
         l1_ids=["l1.mcp.call"], server_or_provider="configured MCP servers (bundled or external)",
         capabilities=["call MCP tools exposed by configured servers"],
         description_source={"source_ref": "MCP tool listing (remote) - agent-bundle-mcp-catalog",
                           "writers": [writer("external_service", None), writer("operator", "l1.config.mcp")]},
         execution_identity={"identity": "MCP client", "credential_source": "MCP server config"},
         execution_environment=_env("remote/bundled MCP server", "per server", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "ctx.tool_descriptions", "sink.mcp_call"],
         control_ids=["ctl.before_tool_hook", "ctl.requester_tool_policy"],
         reachability=reach("conditionally_mounted", "MCP server configured (agent-bundle-mcp-manager.ts)"),
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/agent-bundle-mcp-manager.ts; agent-bundle-mcp-combined.ts; "
                    "src/agents/native-mcp-runtime-client.ts; src/mcp/openclaw-tools-serve.ts",
         notes="Remote tool descriptions are model-facing -> rug-pull; MCP can also be bundled inside the sandbox. "
               "openclaw is MCP client (calls servers) and server (exposes built-ins); no MCP sampling path observed in source."),

    tool("tool.primary.skills", P, "skills_search / skills_read", "native", "read",
         capabilities=["find + load installed/eligible skills (allowlist-filtered instruction bundles)"],
         execution_identity=_ws_sandbox, argument_handling=_argh, output_ids=["ctx.skill_instructions", "ctx.tool_results"],
         control_ids=["ctl.skill_allowlist"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/installed-skill-tools.ts (createInstalledSkillTools; skills_search/skills_read); "
                    "installed-skill-catalog.ts; skill-instruction-result.ts",
         notes="Skills are instruction content gated by an eligibility/allowlist; editable via file tools -> stored injection."),

    tool("tool.primary.github", P, "github_publish", "native", "external_send",
         l1_ids=["l1.tool.github"], capabilities=["publish workspace content to GitHub"],
         execution_identity={"identity": "configured GitHub identity", "credential_source": "github auth profile (auth-profiles)"},
         execution_environment=_env("GitHub API", "outbound to github", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["sink.github", "ctx.tool_results"], control_ids=["ctl.before_tool_hook"],
         reachability=reach("conditionally_mounted", "github tool + identity configured"), related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/github-publish-tool.ts; github-identity-status-tool.ts; src/agents/sandbox/github-publication.ts",
         notes="Model-driven external publication under the configured GitHub identity (data exfil / unwanted publish surface)."),

    tool("tool.primary.media", P, "media generate (image/video/tts)", "native", "external_send",
         l1_ids=["l1.tool.media"], server_or_provider="configured media providers",
         capabilities=["generate images/video/tts via provider APIs"],
         execution_identity={"identity": "media-provider API client", "credential_source": "provider credentials (config)"},
         execution_environment=_env("provider API", "outbound to provider", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["sink.media", "ctx.tool_results"], control_ids=["ctl.before_tool_hook"],
         reachability=reach("conditionally_mounted", "media provider configured"), related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/image-generate-tool.ts; video-generate-tool.ts; tts-tool.ts; media-generation-tool-providers.ts",
         notes="Outbound provider calls with model-composed prompts; cost + egress surface."),

    tool("tool.primary.gateway", P, "gateway (control RPC)", "native", "none",
         capabilities=["call gateway control operations via the in-process/embedded gateway"],
         execution_identity={"identity": "agent via gateway caller context", "credential_source": "gateway caller receipt"},
         argument_handling=_argh, output_ids=["ctx.tool_results"], control_ids=["ctl.before_tool_hook", "ctl.requester_tool_policy"],
         related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/gateway-tool.ts; gateway-caller-context.ts; in-process-gateway.ts",
         notes="Bridges the agent to gateway control operations; scoped by gateway caller context/receipt."),

    # ---------- sub-agent tools (restricted subset) ----------
    tool("tool.subagent.terminal", SUB, "terminal / bash exec (subagent)", "native", "code_execution",
         l1_ids=["l1.tool.exec_shell"], capabilities=["run shell commands"], execution_identity=_ws_sandbox,
         execution_environment=_SANDBOX_EXEC, argument_handling=_argh, approval_required=True,
         output_ids=["ctx.tool_results", "sink.exec"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.exec_approval", "ctl.subagent_policy"],
         related_l2_ids=[L2_SPAWN], source_ref="src/agents/tools/terminal-tool.ts via delegated-tool-policy.ts (subagent surface)",
         notes="Same exec surface as primary, inside the subagent's (optionally separate) sandbox."),

    tool("tool.subagent.file_read", SUB, "read (file) (subagent)", "native", "read",
         capabilities=["read workspace files"], execution_identity=_ws_sandbox, argument_handling=_argh,
         output_ids=["ctx.tool_results"], control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.subagent_policy"],
         related_l2_ids=[L2_SPAWN], source_ref="src/agents/agent-tools.read.ts (subagent surface)"),

    tool("tool.subagent.apply_patch", SUB, "apply_patch / edit file (subagent)", "native", "mixed",
         capabilities=["write/edit workspace files"], execution_identity=_ws_sandbox, argument_handling=_argh,
         output_ids=["mem.workspace", "ctx.tool_results", "sink.file_write"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.subagent_policy"], related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/apply-patch-file-ops.ts (subagent surface)"),

    tool("tool.subagent.web_fetch", SUB, "web_fetch (subagent)", "native", "mixed",
         l1_ids=["l1.tool.web_fetch"], capabilities=["fetch an arbitrary URL"],
         execution_identity={"identity": "gateway/agent process", "credential_source": "none"},
         execution_environment=_env("egress guarded by net-policy SSRF check", "outbound HTTP (SSRF-guarded)", "n/a", by="code"),
         argument_handling=_argh, output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_egress"],
         control_ids=["ctl.net_policy_ssrf", "ctl.before_tool_hook", "ctl.subagent_policy"], related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/tools/web-guarded-fetch.ts; src/infra/net/ssrf.ts (subagent surface)"),

    tool("tool.subagent.computer", SUB, "computer / browser (subagent)", "native", "code_execution",
         l1_ids=["l1.tool.browser"], capabilities=["drive a sandboxed browser"], execution_identity=_ws_sandbox,
         execution_environment=_env("sandboxed browser container", "browser egress (bridge)", "browser profile"),
         argument_handling=_argh, output_ids=["ctx.web_content", "ctx.tool_results", "sink.web_egress"],
         control_ids=["ctl.sandbox", "ctl.before_tool_hook", "ctl.subagent_policy"],
         reachability=reach("conditionally_mounted", "browser enabled for subagent"), related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/tools/computer-tool.ts; src/agents/sandbox/browser.ts (subagent surface)"),

    tool("tool.subagent.mcp", SUB, "MCP server tools (subagent)", "mcp", "mixed",
         l1_ids=["l1.mcp.call"], server_or_provider="configured MCP servers",
         description_source={"source_ref": "MCP tool listing (remote)",
                           "writers": [writer("external_service", None), writer("operator", "l1.config.mcp")]},
         execution_identity={"identity": "MCP client", "credential_source": "MCP server config"},
         execution_environment=_env("remote/bundled MCP server", "per server", "remote", by="external_service"),
         argument_handling=_argh, output_ids=["ctx.tool_results", "ctx.tool_descriptions", "sink.mcp_call"],
         control_ids=["ctl.before_tool_hook", "ctl.subagent_policy"],
         reachability=reach("conditionally_mounted", "MCP configured + allowed for subagent"), related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/agent-bundle-mcp-manager.ts (subagent surface)"),

    # ---------- system agent tools ----------
    tool("tool.system.system_agent", SYS, "system-agent op", "native", "none",
         capabilities=["fleet creation / onboarding / owner-trust operations"],
         execution_identity={"identity": "ring-zero/owner", "credential_source": "owner trust (execution-authority.ts)"},
         argument_handling=_argh, output_ids=["mem.fleet_config", "ctx.tool_results"], control_ids=["ctl.owner_trust"],
         related_l2_ids=[L2_RUN], source_ref="src/agents/tools/system-agent-tool.ts; src/agents/execution-authority.ts",
         notes="Privileged fleet-config operations; human owner approval gates creation/role instructions."),

    tool("tool.system.sessions_spawn", SYS, "sessions_spawn (system)", "native", "none",
         capabilities=["spawn agents in the fleet"], execution_identity={"identity": "ring-zero/owner", "credential_source": "owner trust"},
         argument_handling=_argh, output_ids=["ctx.subagent_task", "sink.subagent_result"],
         control_ids=["ctl.subagent_policy", "ctl.owner_trust"], related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/tools/sessions-spawn-tool.ts (system agent surface)"),

    tool("tool.system.sessions_send", SYS, "sessions_send / A2A (system)", "native", "external_send",
         capabilities=["message peer agents"], execution_identity={"identity": "system agent", "credential_source": "fleet auth"},
         argument_handling=_argh, output_ids=["sink.agent_send"], control_ids=["ctl.agent_to_agent"], related_l2_ids=[L2_A2A],
         source_ref="src/agents/tools/sessions-send-tool.ts (system agent surface)"),

    tool("tool.system.message", SYS, "message (system)", "native", "external_send",
         l1_ids=["l1.tool.message_send"], capabilities=["send to channels"],
         execution_identity={"identity": "channel account", "credential_source": "channel connection"},
         argument_handling=_argh, output_ids=["sink.channel_reply"], control_ids=["ctl.before_tool_hook"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/message-tool-execution.ts (system agent surface)"),
]

_dest = [P, SUB]
CONTEXT = [
    ctx("ctx.system_prompt", "system_prompt", "trusted_instruction",
        source_ref="src/agents/cli-runner/prompt-context.ts; agent role instructions (config/zod-schema.agent-runtime.ts)",
        writers=[writer("operator", "l1.config.agents")], destination_agent_ids=[P, SYS],
        destination_channel="system", provenance="operator/role config", persistence_scope="tenant",
        related_l2_ids=[L2_RUN], notes="Role instructions require human approval (owner trust) before taking effect."),

    ctx("ctx.skill_instructions", "developer_prompt", "mixed",
        source_ref="src/agents/tools/installed-skill-tools.ts; installed-skill-catalog.ts; ~/.openclaw/skills files",
        writers=[writer("operator", "l1.workspace.skills"), writer("agent", None)], destination_agent_ids=_dest,
        destination_channel="developer", provenance="skill files", persistence_scope="tenant", related_l2_ids=[L2_RUN],
        notes="Skill files are instruction content; writable by apply_patch/file tools -> stored prompt injection."),

    ctx("ctx.plugin_injected", "system_prompt", "mixed",
        source_ref="src/agents/cli-runner/execute-plugin.steered-transcript.ts; plugin prompt-context steering",
        writers=[writer("plugin", "l1.plugin.hook")], destination_agent_ids=[P],
        destination_channel="system", provenance="plugins (pluginOwnerId trust)", persistence_scope="global",
        related_l2_ids=[L2_RUN], notes="Plugins can steer/inject transcript+system context; trust tied to pluginOwnerId."),

    ctx("ctx.channel_message", "user_input", "untrusted_data",
        source_ref="src/channels/inbound-event/context.ts; message-access/decision.ts; direct-dm.ts",
        writers=[writer("channel_sender", "l1.channel.whatsapp")], destination_agent_ids=[P, SYS],
        destination_channel="user", provenance="messaging sender (DM allowlist)", persistence_scope="session",
        related_l2_ids=[L2_RUN],
        notes="PRIMARY untrusted entry: a message drives the agent + its tools; gated only by DM allowlist/pairing."),

    ctx("ctx.session_history", "chat_history", "mixed", source_ref="session transcript store (src/agents sessions; mem.sessions)",
        writers=[writer("channel_sender", "l1.channel.whatsapp"), writer(P, None)], destination_agent_ids=[P, SYS],
        destination_channel="user", provenance="prior turns", persistence_scope="session", related_l2_ids=[L2_RUN]),

    ctx("ctx.tool_results", "tool_result", "untrusted_data",
        source_ref="packages/agent-core/src/agent-loop-tool-execution.ts; tool-call-outcome.ts; src/agents/tools/tool-results.ts",
        writers=[writer(P, None), writer("external_service", None)], destination_agent_ids=_dest,
        destination_channel="tool", provenance="tool output", persistence_scope="session", related_l2_ids=[L2_RUN]),

    ctx("ctx.web_content", "external", "untrusted_data",
        source_ref="src/agents/tools/web-fetch.ts; web-search-output.ts; computer-tool page content",
        writers=[writer("external_service", None)], destination_agent_ids=_dest, destination_channel="tool",
        provenance="arbitrary web / search provider", persistence_scope="session", related_l2_ids=[L2_RUN],
        notes="Fetched/searched/browsed page content -> indirect prompt injection."),

    ctx("ctx.tool_descriptions", "external", "untrusted_data",
        source_ref="src/agents/agent-bundle-mcp-catalog-projection.ts; agent-bundle-mcp-instructions.ts (MCP listings)",
        writers=[writer("external_service", None), writer("operator", "l1.config.mcp")], destination_agent_ids=_dest,
        destination_channel="tool", provenance="remote MCP specs", persistence_scope="tenant", related_l2_ids=[L2_RUN],
        notes="Remote MCP tool descriptions are model-facing -> rug-pull / tool-description injection."),

    ctx("ctx.subagent_task", "delegated_summary", "mixed",
        source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts (parent-composed task)",
        writers=[writer(P, None)], destination_agent_ids=[SUB], destination_channel="developer",
        provenance="parent agent", persistence_scope="workflow", related_l2_ids=[L2_SPAWN],
        notes="Parent-composed subagent task -> parent->child injection."),

    ctx("ctx.cross_agent_message", "external", "untrusted_data",
        source_ref="src/agents/tools/sessions-send-tool.a2a.ts (inbound A2A); channels/inbound-event",
        writers=[writer("peer_agent", "l1.a2a.inbound")], destination_agent_ids=[P], destination_channel="user",
        provenance="peer fleet agent", persistence_scope="session",
        reachability=reach("conditionally_mounted", "agentToAgent enabled + allowed pair"), related_l2_ids=[L2_A2A],
        notes="Cross-agent message = another agent's (possibly injected) output driving this one -> lateral injection."),

    ctx("ctx.cron_prompt", "other", "mixed",
        source_ref="src/cron/agent-turn-command-prompt.ts; src/agents/tools/cron-tool-write.ts",
        writers=[writer("operator", "l1.config.agents"), writer(P, None)], destination_agent_ids=[P],
        destination_channel="user", provenance="scheduled job prompt (agent- or operator-authored)",
        persistence_scope="session", reachability=reach("conditionally_mounted", "cron job scheduled"), related_l2_ids=[L2_CRON],
        notes="A cron job delivers a stored prompt to a future turn -> deferred self-trigger; an agent can schedule "
              "its own (or a poisoned) instruction to run later."),

    ctx("ctx.ask_user_response", "user_input", "untrusted_data",
        source_ref="src/agents/tools/ask-user-tool.ts; question-prompt-send.ts (human answer returns)",
        writers=[writer("channel_sender", "l1.channel.whatsapp")], destination_agent_ids=[P], destination_channel="user",
        provenance="human answer to ask_user", persistence_scope="session", related_l2_ids=[L2_RUN],
        notes="Human answer re-enters as untrusted user content."),
]

MEMORY = [
    mem("mem.sessions", "conversation_history", "openclaw", "session",
        readers=[P, SUB, SYS], writers=[writer("channel_sender", "l1.channel.whatsapp"), writer(P, None)],
        isolation_enforcement="per session identity; cross-agent access governed by tools.sessions.visibility "
                              "(src/plugin-sdk/session-visibility.ts)",
        write_provenance="channel messages + agent turns", read_path="session transcript replayed into turn",
        retention_and_deletion="session lifecycle", related_l2_ids=[L2_RUN],
        source_ref="src/agents sessions store; src/agents/tools/sessions-history-tool.ts",
        notes="Cross-agent session visibility (tree/all) can cross agent boundaries."),

    mem("mem.workspace", "database", "openclaw", "tenant",
        readers=[P, SUB], writers=[writer(P, None), writer("operator", "l1.workspace.files")],
        isolation_enforcement="per-agent workspace root; sandbox fs-bridge redirect for sandboxed runs "
                              "(src/agents/sandbox/fs-bridge.ts)",
        write_provenance="apply_patch/file tools + operator", read_path="read tool reads the workspace",
        retention_and_deletion="workspace lifecycle", related_l2_ids=[L2_RUN],
        source_ref="src/agents/sandbox/fs-bridge.ts; fs-paths.ts; host-paths.ts",
        notes="Agent workspace filesystem; sandboxed runs use a sandbox workspace root."),

    mem("mem.skills", "database", "openclaw", "tenant",
        readers=[P, SUB], writers=[writer("operator", "l1.workspace.skills"), writer(P, None)],
        isolation_enforcement="agent skill eligibility/allowlist (installed-skill-catalog.ts)",
        write_provenance="skill authors + file tools", read_path="skills loaded into context (allowlist-filtered)",
        retention_and_deletion="workspace-managed", related_l2_ids=[L2_RUN],
        source_ref="src/agents/installed-skill-catalog.ts; src/agents/tools/installed-skill-tools.ts",
        notes="Instruction store -> stored prompt injection surface."),

    mem("mem.fleet_config", "database", "openclaw", "global",
        readers=[P, SYS], writers=[writer("operator", "l1.config.agents")],
        isolation_enforcement="operator-only config; ownership explicit (config/zod-schema.agent-runtime.ts)",
        write_provenance="operator", read_path="agent entries/roles/allowlists resolved per run",
        retention_and_deletion="operator-managed", related_l2_ids=[L2_RUN],
        source_ref="src/config/zod-schema.agent-runtime.ts; src/commands/agents.config.ts",
        notes="Fleet wiring: roles, allowlists, owner, agentToAgent allow -- the policy that bounds everything."),

    mem("mem.cron_jobs", "event_log", "openclaw", "tenant",
        readers=[P], writers=[writer(P, None), writer("operator", "l1.config.agents")],
        isolation_enforcement="per-agent creator cap (cron-tool-creator-cap.ts); active-jobs scope",
        write_provenance="cron tool (agent) + operator", read_path="scheduler fires job -> ctx.cron_prompt into a turn",
        retention_and_deletion="job lifecycle (src/cron/active-jobs.ts)", related_l2_ids=[L2_CRON],
        source_ref="src/cron/active-jobs.ts; src/cron/agent-turn-command-prompt.ts; src/agents/tools/cron-tool-write.ts",
        notes="Durable scheduled jobs; a stored job is a deferred self-trigger of a future agent turn."),
]

SINKS = [
    sink("sink.channel_reply", "notification", producer_ids=[P, "tool.primary.message", "tool.system.message", SYS],
         audience="messaging recipients (WhatsApp/Feishu/Slack)", delivery="channel send under the channel account",
         render_side_effects={"auto_fetch": "recipient client may render links/media",
                            "active_content": "channel-dependent", "enforced_by": "external_service"},
         related_l1_ids=["l1.tool.message_send"], related_l2_ids=[L2_RUN],
         source_ref="src/agents/tools/message-tool-execution.ts; src/channels/*",
         notes="Model-composed content delivered to real recipients; exfil/abuse via outbound messages."),

    sink("sink.exec", "external_api", producer_ids=["tool.primary.terminal", "tool.subagent.terminal"],
         audience="sandbox/host shell", delivery="command execution in sandbox (or host if unsandboxed)",
         related_l1_ids=["l1.tool.exec_shell"],
         source_ref="src/agents/bash-tools.exec-run.ts; src/agents/sandbox/docker-backend.ts",
         notes="RCE-class if sandbox disabled; network 'none' by default in docker sandbox."),

    sink("sink.web_egress", "external_api",
         producer_ids=["tool.primary.web_fetch", "tool.primary.web_search", "tool.primary.computer",
                       "tool.subagent.web_fetch", "tool.subagent.computer"],
         audience="arbitrary web / search+browser providers", delivery="guarded outbound HTTP / sandboxed browser actions",
         becomes_context_source_ids=["ctx.web_content"], related_l1_ids=["l1.tool.web_fetch", "l1.tool.web_search", "l1.tool.browser"],
         source_ref="src/agents/tools/web-guarded-fetch.ts; src/infra/net/ssrf.ts; src/agents/sandbox/browser.ts",
         notes="Outbound egress channel; net-policy SSRF guard blocks private/internal IPs for fetch."),

    sink("sink.file_write", "file", producer_ids=["tool.primary.apply_patch", "tool.subagent.apply_patch"],
         audience="agent workspace", delivery="apply_patch file write",
         becomes_context_source_ids=["ctx.skill_instructions", "ctx.tool_results"],
         source_ref="src/agents/apply-patch-file-ops.ts", notes="Writing skills/files feeds back as instructions/context."),

    sink("sink.agent_send", "delegated_result",
         producer_ids=["tool.primary.sessions_send", "tool.system.sessions_send", SYS],
         audience="peer fleet agents", delivery="A2A message", becomes_context_source_ids=["ctx.cross_agent_message"],
         related_l2_ids=[L2_A2A], source_ref="src/agents/tools/sessions-send-tool.a2a.ts",
         notes="Becomes a peer's ctx.cross_agent_message -> lateral movement path (allow-gated)."),

    sink("sink.mcp_call", "external_api", producer_ids=["tool.primary.mcp", "tool.subagent.mcp"],
         audience="MCP servers", delivery="MCP call", related_l1_ids=["l1.mcp.call"],
         source_ref="src/agents/native-mcp-runtime-client.ts"),

    sink("sink.subagent_result", "delegated_result", producer_ids=[SUB, "tool.primary.sessions_spawn", "tool.system.sessions_spawn"],
         audience="parent agent", delivery="subagent result delivered to parent",
         becomes_context_source_ids=["ctx.tool_results"], related_l2_ids=[L2_SPAWN],
         source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts", notes="Child->parent path."),

    sink("sink.github", "external_api", producer_ids=["tool.primary.github"], audience="GitHub",
         delivery="github publish under configured identity", related_l1_ids=["l1.tool.github"],
         source_ref="src/agents/tools/github-publish-tool.ts; src/agents/sandbox/github-publication.ts",
         notes="External publication sink -> exfil / unwanted publish."),

    sink("sink.media", "external_api", producer_ids=["tool.primary.media"], audience="media providers",
         delivery="media generation provider call", related_l1_ids=["l1.tool.media"],
         source_ref="src/agents/tools/image-generate-tool.ts; media-generation-tool-providers.ts"),

    sink("sink.cron_schedule", "database_record", producer_ids=["tool.primary.cron"], audience="scheduler store",
         delivery="write a scheduled job", becomes_context_source_ids=["ctx.cron_prompt"], related_l2_ids=[L2_CRON],
         source_ref="src/agents/tools/cron-tool-write.ts; src/cron/active-jobs.ts",
         notes="Writing a job becomes a future ctx.cron_prompt -> deferred self-trigger loop."),
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
         related_l2_steps=[{"l2_id": L2_RUN, "order": 1}],
         source_ref="src/channels/message-access/decision.ts; src/channels/direct-dm-access.ts; inbound-event/context.ts",
         reachability=reach("black_box_reachable", "sending a channel message from an allowlisted sender triggers a run"),
         notes="THE external attack entry: untrusted messaging drives the agent, gated only by DM allowlist."),

    edge("edge.cron__primary", "external_event",
         source={"agent_id": None, "step": "scheduled", "external_trigger": "cron scheduler (active-jobs)"},
         destination={"agent_id": P}, condition="scheduled job fires -> agent turn with stored prompt",
         input_source_ids=["ctx.cron_prompt", "ctx.system_prompt"], payload="scheduled prompt",
         control_ids=["ctl.cron_creator_cap"], execution_mode="queued", loop_bound="job schedule + creator cap",
         failure_behavior="abort", related_l1_ids=["l1.cron.scheduled"], related_l2_steps=[{"l2_id": L2_CRON, "order": 1}],
         source_ref="src/cron/active-jobs.ts; src/cron/agent-turn-command-prompt.ts; src/cron/agent-availability.ts",
         reachability=reach("conditionally_mounted", "a cron job must exist (agent- or operator-created)"),
         notes="Scheduler-driven self-trigger: a stored job runs a future agent turn without a live human in the loop."),

    edge("edge.primary__tool", "llm", source=_S("tool-call"),
         destination={"tool_binding_id": "(model-selected binding)"},
         condition="model emits a tool call -> schema validation + before_tool_call policy chain",
         argument_sources="model-composed args (validated against tool JSON schema)",
         input_source_ids=["ctx.channel_message", "ctx.session_history", "ctx.tool_results", "ctx.web_content",
                          "ctx.skill_instructions", "ctx.tool_descriptions", "ctx.cross_agent_message", "ctx.cron_prompt"],
         payload="tool name + args", output_ids=["ctx.tool_results"],
         control_ids=["ctl.tool_arg_validation", "ctl.before_tool_hook", "ctl.requester_tool_policy", "ctl.sandbox"],
         validation_or_approval="schema validation + before_tool_call policy chain (block terminal) + requester tool policy",
         execution_mode="synchronous", loop_bound="turn-scoped; attempt timeout + repetition guard",
         failure_behavior="fail_closed", related_l2_steps=[{"l2_id": L2_RUN, "order": 2}],
         source_ref="packages/agent-core/src/agent-loop-tool-execution.ts; src/agents/agent-tools.before-tool-call.policy.ts "
                    "(runBeforeToolCallHook)",
         notes="Programmable before_tool_call policy chain can block a tool call; requester tool policy gates which tools "
               "an external/delegated requester may use."),

    edge("edge.tool__primary", "deterministic_code", source=_S("tool-return"),
         destination={"agent_id": P}, condition="tool returns (result persisted + transformed)",
         payload="tool result", output_ids=["ctx.tool_results"], control_ids=["ctl.before_tool_hook"],
         execution_mode="synchronous", failure_behavior="retry", related_l2_steps=[{"l2_id": L2_RUN, "order": 3}],
         source_ref="packages/agent-core/src/tool-call-outcome.ts; src/agents/tools/tool-results.ts"),

    edge("edge.primary__exec", "llm", source=_S("exec"),
         destination={"tool_binding_id": "tool.primary.terminal", "external_surface": "sandbox/host shell"},
         condition="model runs a shell command", argument_sources="model-composed command",
         payload="shell command", output_ids=["sink.exec", "ctx.tool_results"],
         control_ids=["ctl.sandbox", "ctl.exec_approval", "ctl.before_tool_hook"],
         execution_mode="synchronous", failure_behavior="abort", related_l2_steps=[{"l2_id": L2_RUN, "order": 2}],
         source_ref="src/agents/bash-tools.exec-run.ts; src/agents/sandbox/docker-backend.ts",
         notes="Isolation depends on sandbox config; unsandboxed = host RCE; exec may require approval."),

    edge("edge.primary__fetch", "llm", source=_S("fetch"),
         destination={"tool_binding_id": "tool.primary.web_fetch", "external_surface": "arbitrary URL"},
         condition="model fetches a URL -> net-policy SSRF guard", argument_sources="model-composed URL",
         payload="target URL", output_ids=["sink.web_egress", "ctx.web_content"],
         control_ids=["ctl.net_policy_ssrf", "ctl.before_tool_hook"], execution_mode="synchronous",
         failure_behavior="fail_closed", related_l1_ids=["l1.tool.web_fetch"], related_l2_steps=[{"l2_id": L2_RUN, "order": 2}],
         source_ref="src/agents/tools/web-guarded-fetch.ts; src/infra/net/ssrf.ts",
         notes="SSRF surface; net-policy blocks private/internal targets but model picks the URL (egress + indirect injection)."),

    edge("edge.primary__subagent", "llm", source=_S("spawn"),
         destination={"agent_id": SUB}, condition="model spawns a sub-agent",
         argument_sources="model-composed task", payload="subagent task", output_ids=["ctx.subagent_task"],
         control_ids=["ctl.subagent_policy", "ctl.owner_trust"], execution_mode="background",
         loop_bound="spawn depth + child limits", failure_behavior="partial_effect",
         related_l1_ids=["l1.internal.subagent_spawn"], related_l2_steps=[{"l2_id": L2_SPAWN, "order": 1}],
         source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts; sessions-spawn-access-program.ts",
         notes="Restricted child tool surface by default; operator approval for creation hierarchy."),

    edge("edge.subagent__primary", "deterministic_code",
         source={"agent_id": SUB, "step": "result", "external_trigger": None},
         destination={"agent_id": P, "output_sink_id": "sink.subagent_result"}, condition="subagent run ends",
         payload="subagent result", output_ids=["sink.subagent_result", "ctx.tool_results"],
         execution_mode="callback", failure_behavior="partial_effect", related_l2_steps=[{"l2_id": L2_SPAWN, "order": 2}],
         source_ref="src/agents/tools/sessions-spawn-tool.ts (result delivery)"),

    edge("edge.primary__peer", "llm", source=_S("a2a"),
         destination={"tool_binding_id": "tool.primary.sessions_send", "external_surface": "peer fleet agent"},
         condition="model sends to a peer agent", argument_sources="model-composed message",
         payload="cross-agent message", output_ids=["sink.agent_send"], control_ids=["ctl.agent_to_agent"],
         execution_mode="synchronous", failure_behavior="fail_closed", related_l2_steps=[{"l2_id": L2_A2A, "order": 1}],
         source_ref="src/agents/tools/sessions-send-tool.a2a.ts (runSessionsSendA2AFlow)",
         notes="Lateral path -> peer's ctx.cross_agent_message; bounded by agentToAgent allow."),

    edge("edge.primary__cron", "llm", source=_S("schedule"),
         destination={"tool_binding_id": "tool.primary.cron", "external_surface": "scheduler store"},
         condition="model creates a scheduled job", argument_sources="model-composed schedule + prompt",
         payload="cron job (schedule + prompt)", output_ids=["sink.cron_schedule", "mem.cron_jobs"],
         control_ids=["ctl.cron_creator_cap", "ctl.before_tool_hook"], execution_mode="synchronous",
         failure_behavior="fail_closed", related_l2_steps=[{"l2_id": L2_CRON, "order": 0}],
         source_ref="src/agents/tools/cron-tool-write.ts; cron-tool-creator-cap.ts",
         notes="Model writes a durable self-trigger; creator cap bounds job count. Closes a loop with edge.cron__primary."),

    edge("edge.primary__askuser", "llm", source=_S("ask"),
         destination={"tool_binding_id": "tool.primary.ask_user", "external_surface": "human via channel"},
         condition="model asks a human a question and awaits reply", argument_sources="model-composed question",
         payload="question -> human answer", output_ids=["ctx.ask_user_response"], control_ids=["ctl.before_tool_hook"],
         execution_mode="callback", failure_behavior="abort", related_l2_steps=[{"l2_id": L2_RUN, "order": 2}],
         source_ref="src/agents/tools/ask-user-tool.ts; question-prompt-send.ts",
         notes="Human answer re-enters as untrusted ctx.ask_user_response."),

    edge("edge.primary__output", "deterministic_code", source=_S("final"),
         destination={"output_sink_id": "sink.channel_reply"}, condition="agent produces a reply",
         payload="reply to channel", output_ids=["sink.channel_reply"], execution_mode="synchronous",
         failure_behavior="abort", related_l2_steps=[{"l2_id": L2_RUN, "order": 4}],
         source_ref="packages/agent-core/src/agent-stream-response.ts; src/agents (streaming/persistence)"),
]

_all = [P, SUB, SYS]
CONTROLS = [
    ctl("ctl.sandbox", "tool_policy", "before_tool", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SUB],
        applies_to_tool_binding_ids=["tool.primary.terminal", "tool.primary.apply_patch", "tool.primary.computer",
                                     "tool.primary.file_read", "tool.subagent.terminal", "tool.subagent.apply_patch",
                                     "tool.subagent.computer", "tool.subagent.file_read"],
        related_l1_ids=["l1.tool.exec_shell", "l1.tool.browser"],
        source_ref="src/agents/sandbox/config.ts (network default 'none', readOnlyRoot default true); "
                   "container-allocation.ts (--network, capDrop); docker-backend.ts; sandbox-tool-policy.ts",
        reachability=reach("black_box_reachable", "default-on; posture observable via container inspect"),
        notes="Docker sandbox defaults: network 'none' + readOnlyRoot + capDrop. Crabbox lease alt. If sandboxing is "
              "DISABLED (UNSANDBOXED), exec/file/browser run on the host -> major posture change."),

    ctl("ctl.before_tool_hook", "tool_policy", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="src/agents/agent-tools.before-tool-call.policy.ts (runBeforeToolCallHook; approvalMode "
                   "request|report|deny|defer); agent-tools.before-tool-call.wrapper.ts; plugins/trusted-tool-policy.ts",
        reachability=reach("black_box_reachable", "runs on every wrapped tool call"),
        notes="Programmable ordered before_tool_call policy chain (plugin + trusted-tool policies) can block any tool "
              "call; fail-closed ('Tool call blocked because before_tool_call hook failed')."),

    ctl("ctl.dm_allowlist", "authorization", "before_model", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SYS],
        related_l1_ids=["l1.channel.whatsapp", "l1.channel.feishu"],
        source_ref="src/channels/allow-from.ts; allowlist-match.ts; direct-dm-access.ts; message-access/decision.ts",
        reachability=reach("black_box_reachable", "every inbound channel message is matched against the allowlist"),
        notes="Decides WHO can message (invoke) the agent. Per channel account. The primary external authorization boundary."),

    ctl("ctl.agent_to_agent", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        applies_to_tool_binding_ids=["tool.primary.sessions_send", "tool.primary.sessions_read",
                                     "tool.system.sessions_send"],
        source_ref="src/config/zod-schema.agent-runtime.ts (tools.agentToAgent allow/enabled); "
                   "src/agents/tools/sessions-send-tool.a2a.ts; src/plugin-sdk/session-visibility.ts",
        notes="Bounds cross-agent messaging + session visibility -> limits lateral movement across the fleet."),

    ctl("ctl.subagent_policy", "tool_policy", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SYS, SUB],
        applies_to_tool_binding_ids=["tool.primary.sessions_spawn", "tool.system.sessions_spawn",
                                     "tool.subagent.terminal", "tool.subagent.apply_patch", "tool.subagent.web_fetch",
                                     "tool.subagent.computer", "tool.subagent.mcp", "tool.subagent.file_read"],
        source_ref="src/agents/delegated-tool-policy.ts; src/agents/tools/subagents-tool.ts; "
                   "sessions-spawn-access-program.ts (allowAgents, spawn depth, child limits)",
        notes="Subagents get a restricted tool surface by default (no session/message/spawn tools); spawn targets allowlisted."),

    ctl("ctl.skill_allowlist", "tool_policy", "before_model", "blocking", "platform_config",
        failure_mode="fail_closed", applies_to_agent_ids=_all, applies_to_tool_binding_ids=["tool.primary.skills"],
        source_ref="src/agents/installed-skill-catalog.ts; src/agents/tools/installed-skill-tools.ts (eligibility/allowlist)",
        notes="Filters which skills (instruction bundles) are eligible/loaded per agent."),

    ctl("ctl.owner_trust", "human_approval", "delegation", "blocking", "human_process",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        applies_to_tool_binding_ids=["tool.system.system_agent", "tool.primary.sessions_spawn"],
        source_ref="src/agents/execution-authority.ts (resolveGatewayExecAuthority, hasUnrestrictedGatewayExecution); "
                   "qa/scenarios/config/system-agent-ring-zero-setup.yaml",
        notes="Human/operator approval governs fleet creation hierarchy and role-instruction changes; pluginOwnerId trust."),

    ctl("ctl.tool_arg_validation", "input_filter", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all,
        source_ref="packages/agent-core/src/validation.ts; agent-loop.prepare-arguments.test.ts; packages/tool-call-repair",
        notes="Structural validation of model-composed tool args against the tool JSON schema before execution."),

    ctl("ctl.session_visibility", "authorization", "memory_read", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=_all, applies_to_tool_binding_ids=["tool.primary.sessions_read"],
        source_ref="src/plugin-sdk/session-visibility.ts; session-visibility-internal.ts "
                   "(tools.sessions.visibility: tree/all/none)",
        notes="Controls cross-agent transcript reads."),

    ctl("ctl.exec_approval", "human_approval", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SUB],
        applies_to_tool_binding_ids=["tool.primary.terminal", "tool.subagent.terminal"],
        source_ref="src/agents/bash-tools.exec-approval-request.ts; exec-approval-followup.ts; exec-approval-binding.ts",
        reachability=reach("conditionally_mounted", "exec approval mode = request|deny (per policy)"),
        notes="Human approval gate for shell exec when approval mode requires it (approvalMode request/deny)."),

    ctl("ctl.net_policy_ssrf", "output_filter", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SUB],
        applies_to_tool_binding_ids=["tool.primary.web_fetch", "tool.subagent.web_fetch"],
        related_l1_ids=["l1.tool.web_fetch"],
        source_ref="src/infra/net/ssrf.ts; packages/net-policy/src/{ip,ipv4,url-protocol,url-userinfo,redact-sensitive-url}.ts; "
                   "src/agents/tools/web-guarded-fetch.ts",
        notes="SSRF guard: blocks private/internal IPs + disallowed protocols/userinfo for model-chosen fetch URLs."),

    ctl("ctl.requester_tool_policy", "authorization", "before_tool", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P, SUB],
        source_ref="src/agents/requester-tool-policy.ts; src/agents/tool-policy-match.ts (isToolAllowedByPolicies); "
                   "src/channels/inbound-event/legacy-tool-policy.ts",
        notes="Per-requester/delegated-run tool allowlist: which tools a given (external) requester may invoke."),

    ctl("ctl.cron_creator_cap", "rate_limit", "delegation", "blocking", "code",
        failure_mode="fail_closed", applies_to_agent_ids=[P], applies_to_tool_binding_ids=["tool.primary.cron"],
        related_l1_ids=["l1.cron.scheduled"],
        source_ref="src/agents/tools/cron-tool-creator-cap.ts; src/cron/active-jobs.ts",
        notes="Caps how many scheduled jobs an agent/creator may register -> bounds the self-trigger surface."),
]
