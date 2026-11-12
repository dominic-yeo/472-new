# -*- coding: utf-8 -*-
"""Phase F link layer for openclaw: emit a FOCUSED L1 + L2 GT that catalogs the
invocation / config-write / tool-backing surfaces the agentic layer references,
so every cross-layer id (tool.l1_ids, agents.invocation_surfaces[].l1_id,
writers[].l1_id, *.related_l1_ids, related_l2_ids / related_l2_steps) resolves.

Scope note (honest): this is a TARGETED L1/L2 built to close the agentic layer's
cross-layer references -- the surfaces an agent run actually touches -- NOT a
full-app HTTP/route sweep of the whole gateway (openclaw is primarily driven over
messaging channels + RPC, not a public HTTP API). Node ids are stable symbolic
surface identifiers; `key` carries the concrete locus. Schema: pengent-web-gt-v1.

Run: PYTHONIOENCODING=utf-8 python build_links.py  (emits ../l1_gt.yaml, ../l2_gt.yaml)
"""
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentic_data as D  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_ID = "openclaw-oss"
SCHEMA = "pengent-web-gt-v1"


def gt(visibility="grey_box", reachable=True, conds=None, evidence=None, notes=""):
    return {"visibility": {"minimum": visibility, "reason": notes},
            "black_box_reachable": reachable, "reachability_conditions": conds or [],
            "evidence": evidence or [], "notes": notes}


def l1(id, key, kind, surface_class, *, methods=None, auth="", inputs=None, outputs=None,
       reachable=True, conds=None, source_ref="", notes=""):
    return {
        "id": id, "key": key, "kind": kind, "surface_class": surface_class,
        "methods": methods or [], "auth_context": auth,
        "inputs": inputs or [], "outputs": outputs or [],
        "source_ref": source_ref,
        "gt": gt(reachable=reachable, conds=conds, notes=notes),
        "notes": notes,
    }


# --- L1 nodes: invocation surfaces, config/write surfaces, tool-backing surfaces ---
L1_NODES = [
    # invocation surfaces (how an agent run is started/resumed)
    l1("l1.channel.whatsapp", "channel:whatsapp/inbound", "channel", "invocation",
       auth="channel identity gated by DM allowlist/pairing",
       inputs=["message_text", "sender", "attachments"], outputs=["agent_reply"],
       conds=["sender passes dmPolicy allowlist/pairing"],
       source_ref="src/channels/* (direct-dm.ts, inbound-event/context.ts); message-access/decision.ts",
       notes="PRIMARY untrusted entry. Inbound WhatsApp DM/group message drives an agent turn."),
    l1("l1.channel.feishu", "channel:feishu-slack-other/inbound", "channel", "invocation",
       auth="channel account; agent binding", inputs=["message_text", "sender"], outputs=["agent_reply"],
       conds=["sender passes channel dmPolicy"],
       source_ref="src/channels/*", notes="Other messaging channels (Feishu/Slack/...) as invocation surfaces."),
    l1("l1.gateway.rpc", "gateway:rpc/control", "rpc", "invocation",
       auth="operator/owner (gateway caller context + receipt)", inputs=["rpc_call"], outputs=["rpc_result"],
       source_ref="src/gateway/*; src/agents/tools/gateway-caller-context.ts; in-process-gateway.ts",
       notes="Gateway RPC / Control UI talk surface (operator-facing)."),
    l1("l1.gateway.system", "gateway:system-agent/ring-zero", "rpc", "invocation",
       auth="owner/operator; ring-zero", inputs=["system_instruction"], outputs=["fleet_change"],
       source_ref="src/agents/tools/system-agent-tool.ts; execution-authority.ts; qa/scenarios/config/system-agent-ring-zero-setup.yaml",
       notes="Privileged system-agent / ring-zero setup surface."),
    l1("l1.a2a.inbound", "fleet:agent-to-agent/inbound", "internal", "invocation",
       auth="tools.agentToAgent allow policy", inputs=["peer_message"], outputs=["agent_reply"],
       reachable=False, conds=["agentToAgent enabled + allowed sender pair"],
       source_ref="src/agents/tools/sessions-send-tool.a2a.ts; src/channels/inbound-event",
       notes="Peer-agent (A2A) message as an invocation surface -> lateral movement entry."),
    l1("l1.internal.subagent_spawn", "fleet:subagent/spawn", "internal", "invocation",
       auth="parent agent; allowAgents + spawn limits", inputs=["subagent_task"], outputs=["subagent_result"],
       source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts; sessions-spawn-access-program.ts",
       notes="Internal spawn of a background sub-agent run."),
    l1("l1.cron.scheduled", "scheduler:cron/agent-turn", "scheduler", "invocation",
       auth="job creator identity; creator cap", inputs=["scheduled_prompt"], outputs=["agent_reply"],
       reachable=False, conds=["a cron job exists (agent- or operator-created)"],
       source_ref="src/cron/active-jobs.ts; agent-turn-command-prompt.ts; agent-availability.ts",
       notes="Scheduler-driven self-trigger of a future agent turn."),

    # config / write surfaces (how instruction/policy content is populated)
    l1("l1.config.agents", "config:agents.defaults+entries", "config", "config_write",
       auth="operator", inputs=["agent_role", "allowlists", "owner", "model"], outputs=["fleet_config"],
       source_ref="src/config/zod-schema.agent-runtime.ts; src/commands/agents.config.ts",
       notes="Fleet wiring: roles, system prompts, allowlists, ownership, agentToAgent allow."),
    l1("l1.config.mcp", "config:mcp-servers", "config", "config_write",
       auth="operator", inputs=["mcp_server_spec"], outputs=["mcp_catalog"],
       source_ref="src/agents/agent-bundle-mcp-manager.ts; config MCP server entries",
       notes="Operator-configured MCP servers (whose tool descriptions become model-facing)."),
    l1("l1.workspace.skills", "workspace:skills/files", "config", "config_write",
       auth="operator + agent file tools", inputs=["skill_file"], outputs=["skill_instruction"],
       source_ref="src/agents/installed-skill-catalog.ts; ~/.openclaw/skills",
       notes="Skill instruction files (stored-instruction surface)."),
    l1("l1.workspace.files", "workspace:agent-root/files", "config", "config_write",
       auth="agent file tools + operator", inputs=["file_content"], outputs=["workspace_file"],
       source_ref="src/agents/sandbox/fs-bridge.ts; fs-paths.ts",
       notes="Agent workspace filesystem writes."),
    l1("l1.plugin.hook", "plugin:prompt-context+tool-policy/hook", "internal", "config_write",
       auth="pluginOwnerId trust", inputs=["prepend_context", "tool_policy"], outputs=["injected_context", "tool_decision"],
       source_ref="src/agents/cli-runner/execute-plugin.steered-transcript.ts; plugins/trusted-tool-policy.ts",
       notes="Plugin hooks that steer context and gate tool calls; trust bound to pluginOwnerId."),

    # tool-backing surfaces (what a tool call actually reaches)
    l1("l1.tool.exec_shell", "tool-backend:shell", "tool_backend", "egress",
       auth="sandbox/host process identity", inputs=["command"], outputs=["stdout", "stderr"],
       source_ref="src/agents/bash-tools.exec-run.ts; src/agents/sandbox/docker-backend.ts",
       notes="Shell/exec backend (sandboxed by default; host if unsandboxed)."),
    l1("l1.tool.web_fetch", "tool-backend:http-fetch", "tool_backend", "egress",
       auth="anonymous outbound (net-policy guarded)", inputs=["url"], outputs=["response_body"],
       source_ref="src/agents/tools/web-guarded-fetch.ts; src/infra/net/ssrf.ts; packages/net-policy",
       notes="Outbound HTTP fetch backend; SSRF-guarded."),
    l1("l1.tool.web_search", "tool-backend:search-provider", "tool_backend", "egress",
       auth="provider credentials", inputs=["query"], outputs=["results"], reachable=False,
       conds=["search provider configured"],
       source_ref="src/agents/tools/web-search.ts; web-search-provider-common.ts",
       notes="Search provider API backend."),
    l1("l1.tool.browser", "tool-backend:sandboxed-browser-cdp", "tool_backend", "egress",
       auth="sandbox browser profile", inputs=["navigate", "action"], outputs=["page_content"], reachable=False,
       conds=["computer/browser tool enabled; sandbox browser bridge"],
       source_ref="src/agents/sandbox/browser.ts; browser-network.ts; computer-tool-gateway.ts",
       notes="Sandboxed browser (CDP) backend."),
    l1("l1.tool.message_send", "tool-backend:channel-send", "tool_backend", "egress",
       auth="channel account", inputs=["target", "message"], outputs=["delivery_receipt"],
       source_ref="src/agents/tools/message-tool-execution.ts; message-tool-source-policy.ts",
       notes="Outbound channel message backend (under the channel account)."),
    l1("l1.tool.github", "tool-backend:github-api", "tool_backend", "egress",
       auth="configured GitHub identity", inputs=["repo", "content"], outputs=["publish_result"], reachable=False,
       conds=["github tool + identity configured"],
       source_ref="src/agents/tools/github-publish-tool.ts; src/agents/sandbox/github-publication.ts",
       notes="GitHub publish backend."),
    l1("l1.tool.media", "tool-backend:media-providers", "tool_backend", "egress",
       auth="provider credentials", inputs=["prompt"], outputs=["media_asset"], reachable=False,
       conds=["media provider configured"],
       source_ref="src/agents/tools/image-generate-tool.ts; media-generation-tool-providers.ts",
       notes="Media generation provider backend."),
    l1("l1.mcp.call", "tool-backend:mcp-server", "tool_backend", "egress",
       auth="MCP server config", inputs=["mcp_tool_args"], outputs=["mcp_tool_result"], reachable=False,
       conds=["MCP server configured"],
       source_ref="src/agents/native-mcp-runtime-client.ts; src/mcp/openclaw-tools-serve.ts",
       notes="MCP server call backend (remote or bundled)."),
]


# --- L2 operations the agentic layer participates in ---
def subj(id, identity, role, auth):
    return {"id": id, "identity": identity, "role": role, "auth_context": auth}


def l2(id, name, kind, action_key, description, subject, business, crud, obj, *,
       requirements=None, effects=None, related_l1_ids=None, source_ref=""):
    return {
        "id": id, "name": name, "kind": kind, "action_key": action_key, "description": description,
        "subject": subject, "operation": {"business": business, "crud": crud}, "object": obj,
        "requirements": requirements or [], "effects": effects or [],
        "related_l1_ids": related_l1_ids or [], "source_ref": source_ref,
    }


L2_NODES = [
    l2("l2.agent.channel_run", "Agent run from a channel message", "normal", "agent_channel_run",
       "An allowlisted channel sender's message drives a full agent turn: context assembly -> model -> "
       "model-selected tool calls (gated by the before_tool_call policy chain + sandbox) -> streamed reply.",
       subj("sender", "Channel sender (allowlisted)", "External", "DM allowlist / pairing"),
       "agent_turn", "Execute",
       {"kind": "process", "id": "agent_turn", "type": "AgentTurn", "name": "Agent turn",
        "entity": "AgentTurn", "role": "executed"},
       requirements=[
           {"type": "authorization", "fact": "sender ∈ channel DM allowlist", "reason": "ctl.dm_allowlist gates invocation"},
           {"type": "state", "fact": "agent bound to channel", "reason": "fleet config binds an agent to the channel"},
       ],
       effects=[
           {"fact": "tools may execute in sandbox under agent identity", "basis": "ctl.sandbox + ctl.before_tool_hook",
            "reason": "model-selected tool calls run with workspace/sandbox authority"},
           {"fact": "model-composed reply delivered to sender", "basis": "sink.channel_reply", "reason": "turn output"},
       ],
       related_l1_ids=["l1.channel.whatsapp", "l1.channel.feishu", "l1.tool.exec_shell", "l1.tool.web_fetch",
                       "l1.tool.message_send"],
       source_ref="packages/agent-core/src/agent-loop.ts; src/channels/inbound-event; src/agents/embedded-agent-runner"),

    l2("l2.agent.scheduled_run", "Scheduled (cron) agent run", "normal", "agent_scheduled_run",
       "A stored cron job fires and drives an agent turn with a saved prompt, without a live human in the loop "
       "(deferred self-trigger).",
       subj("scheduler", "Cron scheduler (job creator identity)", "System", "job creator + creator cap"),
       "agent_turn", "Execute",
       {"kind": "process", "id": "scheduled_turn", "type": "AgentTurn", "name": "Scheduled agent turn",
        "entity": "AgentTurn", "role": "executed"},
       requirements=[
           {"type": "state", "fact": "a cron job exists", "reason": "job was created via the cron tool (ctl.cron_creator_cap)"},
           {"type": "state", "fact": "agent available at fire time", "reason": "src/cron/agent-availability.ts"},
       ],
       effects=[{"fact": "stored prompt runs as a future turn", "basis": "ctx.cron_prompt",
                 "reason": "scheduler delivers the saved prompt"}],
       related_l1_ids=["l1.cron.scheduled"],
       source_ref="src/cron/active-jobs.ts; agent-turn-command-prompt.ts"),

    l2("l2.agent.subagent_delegation", "Sub-agent delegation", "normal", "agent_subagent_delegation",
       "The agent spawns a background sub-agent with a restricted tool surface and a parent-composed task; the "
       "child's result is delivered back to the parent.",
       subj("parent", "Parent agent", "Internal", "inherited sender + spawn policy"),
       "delegation", "Create",
       {"kind": "process", "id": "subagent_run", "type": "SubAgentRun", "name": "Sub-agent run",
        "entity": "SubAgentRun", "role": "created"},
       requirements=[
           {"type": "authorization", "fact": "spawn target ∈ allowAgents, within spawn/child limits",
            "reason": "ctl.subagent_policy"},
       ],
       effects=[{"fact": "child result returns to parent context", "basis": "sink.subagent_result",
                 "reason": "child->parent delivery"}],
       related_l1_ids=["l1.internal.subagent_spawn"],
       source_ref="src/agents/tools/sessions-spawn-tool.ts; subagents-tool.ts"),

    l2("l2.agent.a2a_dispatch", "Agent-to-agent (A2A) dispatch", "normal", "agent_a2a_dispatch",
       "The agent sends a message to a peer agent in the fleet; the message becomes the peer's inbound context "
       "(lateral movement path), bounded by the agentToAgent allow policy.",
       subj("sender_agent", "Sending agent", "Internal", "agentToAgent allow policy"),
       "messaging", "Create",
       {"kind": "message", "id": "a2a_message", "type": "A2AMessage", "name": "A2A message",
        "entity": "A2AMessage", "role": "created"},
       requirements=[
           {"type": "authorization", "fact": "agentToAgent enabled + sender/target pair allowed",
            "reason": "ctl.agent_to_agent"},
       ],
       effects=[{"fact": "peer receives ctx.cross_agent_message", "basis": "sink.agent_send -> ctx.cross_agent_message",
                 "reason": "A2A delivery closes a lateral edge"}],
       related_l1_ids=["l1.a2a.inbound"],
       source_ref="src/agents/tools/sessions-send-tool.a2a.ts"),
]


def _collect_agentic_l1():
    ids = set()
    for a in D.AGENTS:
        for s in a["invocation_surfaces"]:
            if s.get("l1_id"):
                ids.add(s["l1_id"])
        for w in a["model_config"].get("writers", []):
            if w.get("l1_id"):
                ids.add(w["l1_id"])
        for isrc in a["instruction_sources"]:
            for w in isrc.get("writers", []):
                if w.get("l1_id"):
                    ids.add(w["l1_id"])
    for t in D.TOOLS:
        ids |= set(t["l1_ids"])
        if t.get("description_source"):
            for w in t["description_source"].get("writers", []):
                if w.get("l1_id"):
                    ids.add(w["l1_id"])
    for c in D.CONTEXT:
        for w in c["writers"]:
            if w.get("l1_id"):
                ids.add(w["l1_id"])
    for m in D.MEMORY:
        for w in m["writers"]:
            if w.get("l1_id"):
                ids.add(w["l1_id"])
    for s in D.SINKS:
        ids |= set(s["related_l1_ids"])
    for e in D.EDGES:
        ids |= set(e["related_l1_ids"])
    for c in D.CONTROLS:
        ids |= set(c["related_l1_ids"])
    return {i for i in ids if i}


def _collect_agentic_l2():
    ids = set()
    for grp in (D.AGENTS, D.TOOLS, D.CONTEXT, D.MEMORY, D.SINKS):
        for r in grp:
            ids |= set(r.get("related_l2_ids", []))
    for e in D.EDGES:
        for st in e["related_l2_steps"]:
            if st.get("l2_id"):
                ids.add(st["l2_id"])
    return {i for i in ids if i}


def main():
    l1_ids = {n["id"] for n in L1_NODES}
    l2_ids = {n["id"] for n in L2_NODES}
    need_l1 = _collect_agentic_l1()
    need_l2 = _collect_agentic_l2()
    missing_l1 = need_l1 - l1_ids
    missing_l2 = need_l2 - l2_ids
    if missing_l1 or missing_l2:
        print("LINK LAYER INCOMPLETE:")
        for i in sorted(missing_l1):
            print("  missing L1 node for:", i)
        for i in sorted(missing_l2):
            print("  missing L2 node for:", i)
        sys.exit(1)

    extra_l1 = sorted(l1_ids - need_l1)
    if extra_l1:
        print("note: L1 nodes not referenced by agentic layer (ok, catalog surface):", extra_l1)

    l1_doc = {"schema_version": SCHEMA, "environment_id": ENV_ID,
              "scope": "focused: agentic invocation/config/tool-backing surfaces (not a full-app HTTP sweep)",
              "nodes": L1_NODES}
    l2_doc = {"schema_version": SCHEMA, "environment_id": ENV_ID,
              "scope": "focused: agent-run operations referenced by the agentic layer",
              "nodes": L2_NODES}
    for name, doc in [("l1_gt.yaml", l1_doc), ("l2_gt.yaml", l2_doc)]:
        out = os.path.normpath(os.path.join(HERE, "..", name))
        with open(out, "w", encoding="utf-8") as f:
            yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
        print(f"wrote {out} ({len(doc['nodes'])} nodes)")
    print(f"LINK OK: agentic references {len(need_l1)} L1 ids + {len(need_l2)} L2 ids, all resolved.")


if __name__ == "__main__":
    main()
