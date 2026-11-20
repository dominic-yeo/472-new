# -*- coding: utf-8 -*-
"""Validate + assemble agentic_gt.yaml from agentic_data. Run with PYTHONIOENCODING=utf-8.

Folds the methodology's validate_agentic.py checks inline (referential integrity,
lineage closure, enum conformance, writers, no-secrets, evidence/reachability
separation). Cross-layer L1 checks run only if ../l1_gt.yaml exists.
"""
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentic_data as D  # noqa: E402

# --- Runtime grounding (Phase E) ---------------------------------------------
# Observed live 2026-11-20 by building openclaw:local from source and driving
# `openclaw agent --local` embedded turns on a local qwen2.5 (ollama provider,
# baseUrl host.docker.internal:11436; needed a num_ctx=32768 model variant --
# the 14k-token system prompt overflows the default 4096 ctx). Tools confirmed by
# EFFECT/response: terminal (echo executed), apply_patch (wrote /tmp/gtx.txt=pengent),
# file_read (/etc/hostname), web_fetch (invoked -> blocked by the SSRF control). The
# SSRF before-tool hook fired: "[security] blocked URL fetch ... private/internal IP".
# No secrets recorded. Re-applied every build.
_RUNTIME_OBSERVED = {
    "agent.openclaw.primary",
    "tool.primary.terminal", "tool.primary.apply_patch", "tool.primary.file_read",
    "tool.primary.web_fetch",
    "ctx.system_prompt", "ctx.tool_descriptions", "ctx.tool_results", "ctx.session_history",
    "mem.sessions", "mem.workspace",
    "sink.channel_reply", "sink.exec", "sink.file_write",
    "edge.primary__tool", "edge.tool__primary", "edge.primary__exec",
    "edge.primary__fetch", "edge.primary__output",
    "ctl.net_policy_ssrf", "ctl.before_tool_hook", "ctl.sandbox",
}
_RUNTIME_NOTE = ("RUNTIME 2026-11-20: observed via `openclaw agent --local` on local qwen2.5 "
                 "(num_ctx 32768). Tools executed: terminal (echo), apply_patch (file write), "
                 "file_read; web_fetch invoked and BLOCKED by the SSRF net-policy before-tool hook "
                 "('[security] blocked URL fetch ... private/internal IP').")
for _seq in (D.AGENTS, D.TOOLS, D.CONTEXT, D.MEMORY, D.SINKS, D.EDGES, D.CONTROLS):
    for _r in _seq:
        if _r.get("id") in _RUNTIME_OBSERVED:
            _r["evidence_status"] = "observed"
            _r["notes"] = ((_r.get("notes") or "").rstrip(" .") + " | " + _RUNTIME_NOTE).lstrip(" |")

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "agentic_gt.yaml"))
ENV_ID = "openclaw-oss"
SCHEMA_VERSION = "agentic-attack-surface-v1"

META = {
    "app": "openclaw", "app_version": "repo @ 472-new checkout", "git_ref": "see source_root",
    "applicability": {
        "verdict": "qualifies",
        "evidence": "multi-agent gateway running coding-agent loops (packages/agent-core/src/agent-loop.ts, "
                    "built-in or external runtimes) over terminal/file/web/computer/MCP/subagent/A2A tools, driven "
                    "by messaging channels (src/channels/*), gateway RPC, A2A, and a cron scheduler (src/cron/*).",
    },
    "phase_status": {"static_A_to_D": "complete (CODE-GROUNDED; source_ref cites src/ + packages/ symbols)",
                     "runtime_E": "performed offline: reachability set from source gating + per-record grounding "
                                  "runbook written; live 'observed' upgrade blocked (no network/docker/model provider "
                                  "in this environment) -- see environment.yaml runtime_grounding_plan + annotation "
                                  "issue phase-e-offline. No record is marked 'observed'.",
                     "link_F": "complete (../l1_gt.yaml + ../l2_gt.yaml built via build_links.py; all cross-layer "
                               "l1/l2 references resolved and enforced below)"},
}

ENUMS = {
    "agent_kind": {"interactive", "orchestrator", "specialist", "reviewer", "other"},
    "tool_source": {"native", "mcp", "api", "plugin", "code", "external", "other"},
    "effect_class": {"read", "write", "external_send", "financial", "destructive", "code_execution",
                     "mixed", "none", "unknown"},
    "source_kind": {"system_prompt", "developer_prompt", "user_input", "chat_history", "tool_result",
                    "document", "retrieval", "mcp_resource", "mcp_prompt", "delegated_summary",
                    "external", "other"},
    "destination_channel": {"system", "developer", "user", "tool", "other", "unknown"},
    "trust_class": {"trusted_instruction", "untrusted_data", "mixed", "unknown"},
    "store_kind": {"conversation_history", "agent_notes", "task_summary", "vector_store", "database",
                   "cache", "event_log", "external", "other"},
    "sink_kind": {"chat_response", "email", "file", "database_record", "external_api", "notification",
                  "delegated_result", "log", "other"},
    "decision_maker": {"deterministic_code", "llm", "user", "scheduler", "external_event",
                       "human_reviewer", "unknown"},
    "execution_mode": {"synchronous", "background", "queued", "repeated", "callback", "unknown"},
    "control_kind": {"input_filter", "output_filter", "tool_policy", "authorization", "human_approval",
                     "rate_limit", "monitoring", "webhook", "other"},
    "applies_at": {"before_model", "after_model", "before_tool", "after_tool", "delegation",
                   "memory_read", "memory_write", "output_delivery", "other"},
    "enforcement_mode": {"blocking", "modifying", "advisory", "observe_only", "unknown"},
    "implementation": {"code", "model_prompt", "external_service", "platform_config", "human_process", "unknown"},
    "evidence_status": {"observed", "source_confirmed", "inferred", "unknown"},
    "visibility": {"black_box_observable", "grey_box_required", "white_box_required"},
    "reach_status": {"black_box_reachable", "requires_guessed_path", "conditionally_mounted",
                     "blocked_by_control", "unreachable_in_source", "unknown"},
    "scope": {"turn", "session", "workflow", "user", "tenant", "global", "external", "none", "unknown"},
    "failure_behavior": {"fail_closed", "fail_open", "retry", "fallback", "abort", "partial_effect",
                         "bypass", "unknown"},
}

_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_\-]{20,}\.)")


def main():
    errors, warnings = [], []

    agent_ids = {a["id"] for a in D.AGENTS}
    tool_ids = {t["id"] for t in D.TOOLS}
    ctx_ids = {c["id"] for c in D.CONTEXT}
    mem_ids = {m["id"] for m in D.MEMORY}
    sink_ids = {s["id"] for s in D.SINKS}
    ctl_ids = {c["id"] for c in D.CONTROLS}
    edge_ids = {e["id"] for e in D.EDGES}
    content_ids = ctx_ids | mem_ids | sink_ids           # lineage-carrying targets
    linkable = agent_ids | tool_ids | content_ids

    # ---- duplicate ids ----
    for name, ids, seq in [("agents", agent_ids, D.AGENTS), ("tools", tool_ids, D.TOOLS),
                           ("context", ctx_ids, D.CONTEXT), ("memory", mem_ids, D.MEMORY),
                           ("sinks", sink_ids, D.SINKS), ("controls", ctl_ids, D.CONTROLS),
                           ("edges", edge_ids, D.EDGES)]:
        if len(ids) != len(seq):
            errors.append(f"duplicate id in {name}")

    def ref(where, ids, pool, *, allow_placeholder=False):
        for i in ids:
            if i is None:
                continue
            if allow_placeholder and not re.match(r"^(agent|tool|ctx|mem|sink|ctl)\.", str(i)):
                continue
            if i not in pool:
                errors.append(f"{where}: dangling ref '{i}'")

    def enum(where, val, key):
        if val is not None and val not in ENUMS[key]:
            errors.append(f"{where}: invalid {key} '{val}'")

    def no_secret(where, obj):
        if _SECRET_RE.search(yaml.safe_dump(obj, allow_unicode=True)):
            errors.append(f"{where}: possible secret value present")

    # ---- agents ----
    for a in D.AGENTS:
        w = f"agent {a['id']}"
        enum(w, a["agent_kind"], "agent_kind")
        enum(w, a["evidence_status"], "evidence_status")
        enum(w, a["visibility"], "visibility")
        enum(w, a["reachability"]["status"], "reach_status")
        ref(w + ".tools", a["tool_binding_ids"], tool_ids)
        ref(w + ".ctx", a["context_source_ids"], ctx_ids)
        ref(w + ".mem", a["memory_ids"], mem_ids)
        ref(w + ".sinks", a["output_sink_ids"], sink_ids)
        ref(w + ".ctl", a["control_ids"], ctl_ids)
        no_secret(w, a)

    # ---- tools ----
    for t in D.TOOLS:
        w = f"tool {t['id']}"
        if t["agent_id"] not in agent_ids:
            errors.append(f"{w}: agent_id '{t['agent_id']}' not an agent")
        enum(w, t["tool_source"], "tool_source")
        enum(w, t["effect_class"], "effect_class")
        enum(w, t["evidence_status"], "evidence_status")
        enum(w, t["reachability"]["status"], "reach_status")
        if t["approval_required"] not in (True, False, "unknown"):
            errors.append(f"{w}: approval_required must be bool|unknown")
        ref(w + ".out", t["output_ids"], content_ids)
        ref(w + ".ctl", t["control_ids"], ctl_ids)
        no_secret(w, t)

    # ---- context ----
    for c in D.CONTEXT:
        w = f"ctx {c['id']}"
        enum(w, c["source_kind"], "source_kind")
        enum(w, c["destination_channel"], "destination_channel")
        enum(w, c["trust_class"], "trust_class")
        enum(w, c["persistence_scope"], "scope")
        enum(w, c["reachability"]["status"], "reach_status")
        ref(w + ".dest", c["destination_agent_ids"], agent_ids)
        if not c["writers"] and c["source_kind"] not in ("system_prompt",):
            warnings.append(f"{w}: no writers (entry point of lineage) -- confirm source-fixed")
        no_secret(w, c)

    # ---- memory ----
    for m in D.MEMORY:
        w = f"mem {m['id']}"
        enum(w, m["store_kind"], "store_kind")
        enum(w, m["scope"], "scope")
        enum(w, m["reachability"]["status"], "reach_status")
        ref(w + ".readers", [r for r in m["readers"] if str(r).startswith("agent.")], agent_ids)
        no_secret(w, m)

    # ---- sinks ----
    for s in D.SINKS:
        w = f"sink {s['id']}"
        enum(w, s["sink_kind"], "sink_kind")
        enum(w, s["reachability"]["status"], "reach_status")
        ref(w + ".producers", s["producer_ids"], agent_ids | tool_ids)
        ref(w + ".becomes", s["becomes_context_source_ids"], ctx_ids)
        no_secret(w, s)

    # ---- edges ----
    for e in D.EDGES:
        w = f"edge {e['id']}"
        enum(w, e["decision_maker"], "decision_maker")
        enum(w, e["execution_mode"], "execution_mode")
        enum(w, e["failure_behavior"], "failure_behavior")
        enum(w, e["reachability"]["status"], "reach_status")
        src_a, dst = e["source"].get("agent_id"), e["destination"]
        if src_a is not None and src_a not in agent_ids:
            errors.append(f"{w}: source.agent_id '{src_a}' not an agent")
        if dst.get("agent_id") and dst["agent_id"] not in agent_ids:
            errors.append(f"{w}: destination.agent_id dangling")
        if dst.get("tool_binding_id") and str(dst["tool_binding_id"]).startswith("tool.") \
                and dst["tool_binding_id"] not in tool_ids:
            errors.append(f"{w}: destination.tool_binding_id dangling")
        if dst.get("output_sink_id") and dst["output_sink_id"] not in sink_ids:
            errors.append(f"{w}: destination.output_sink_id dangling")
        ref(w + ".in", e["input_source_ids"], ctx_ids | mem_ids)
        ref(w + ".out", e["output_ids"], content_ids | agent_ids)
        ref(w + ".ctl", e["control_ids"], ctl_ids)

    # ---- controls ----
    for c in D.CONTROLS:
        w = f"ctl {c['id']}"
        enum(w, c["control_kind"], "control_kind")
        enum(w, c["applies_at"], "applies_at")
        enum(w, c["enforcement_mode"], "enforcement_mode")
        enum(w, c["implementation"], "implementation")
        enum(w, c["failure_mode"], "failure_behavior")
        enum(w, c["reachability"]["status"], "reach_status")
        ref(w + ".agents", c["applies_to_agent_ids"], agent_ids)
        ref(w + ".tools", c["applies_to_tool_binding_ids"], tool_ids)

    # ---- lineage closure: every content id is produced or written somewhere ----
    produced = set()
    for t in D.TOOLS:
        produced |= set(t["output_ids"])
    for e in D.EDGES:
        produced |= set(e["output_ids"])
    for s in D.SINKS:
        produced |= set(s["becomes_context_source_ids"])
    for a in D.AGENTS:
        produced |= set(a["output_sink_ids"])
    for sid in sink_ids:
        if sid not in produced and sid not in {p for s in D.SINKS for p in []}:
            # a sink with no producer edge/tool is only ok if an agent lists it
            if not any(sid in a["output_sink_ids"] for a in D.AGENTS) \
                    and not any(sid in t["output_ids"] for t in D.TOOLS) \
                    and not any(sid in e["output_ids"] for e in D.EDGES):
                warnings.append(f"sink {sid}: no producer (tool/edge/agent) writes it")

    # ---- cross-layer L1/L2 check (Phase F): every l1/l2 reference must resolve ----
    base = os.path.dirname(__file__)
    l1_path = os.path.normpath(os.path.join(base, "..", "l1_gt.yaml"))
    l2_path = os.path.normpath(os.path.join(base, "..", "l2_gt.yaml"))

    if os.path.exists(l1_path):
        with open(l1_path, encoding="utf-8") as f:
            l1 = yaml.safe_load(f)
        l1_ids = {n.get("id") or n.get("key") for n in (l1.get("nodes") or [])}

        def l1ref(where, ids):
            for i in ids:
                if i and i not in l1_ids:
                    errors.append(f"{where}: dangling L1 ref '{i}'")

        for a in D.AGENTS:
            l1ref(f"agent {a['id']}.invocation", [s.get("l1_id") for s in a["invocation_surfaces"]])
            l1ref(f"agent {a['id']}.model_writers",
                  [w.get("l1_id") for w in a["model_config"].get("writers", [])])
            for isrc in a["instruction_sources"]:
                l1ref(f"agent {a['id']}.instr_writers", [w.get("l1_id") for w in isrc.get("writers", [])])
        for t in D.TOOLS:
            l1ref(f"tool {t['id']}.l1", t["l1_ids"])
            if t.get("description_source"):
                l1ref(f"tool {t['id']}.desc_writers",
                      [w.get("l1_id") for w in t["description_source"].get("writers", [])])
        for c in D.CONTEXT:
            l1ref(f"ctx {c['id']}.writers", [w.get("l1_id") for w in c["writers"]])
        for m in D.MEMORY:
            l1ref(f"mem {m['id']}.writers", [w.get("l1_id") for w in m["writers"]])
        for s in D.SINKS:
            l1ref(f"sink {s['id']}.l1", s["related_l1_ids"])
        for e in D.EDGES:
            l1ref(f"edge {e['id']}.l1", e["related_l1_ids"])
        for c in D.CONTROLS:
            l1ref(f"ctl {c['id']}.l1", c["related_l1_ids"])
    else:
        errors.append("l1_gt.yaml not present -> Phase F incomplete (run build_links.py)")

    if os.path.exists(l2_path):
        with open(l2_path, encoding="utf-8") as f:
            l2 = yaml.safe_load(f)
        l2_ids = {n.get("id") for n in (l2.get("nodes") or [])}

        def l2ref(where, ids):
            for i in ids:
                if i and i not in l2_ids:
                    errors.append(f"{where}: dangling L2 ref '{i}'")

        for grp, label in [(D.AGENTS, "agent"), (D.TOOLS, "tool"), (D.CONTEXT, "ctx"),
                           (D.MEMORY, "mem"), (D.SINKS, "sink")]:
            for r in grp:
                l2ref(f"{label} {r['id']}.l2", r.get("related_l2_ids", []))
        for e in D.EDGES:
            l2ref(f"edge {e['id']}.l2", [st.get("l2_id") for st in e["related_l2_steps"]])
    else:
        errors.append("l2_gt.yaml not present -> Phase F incomplete (run build_links.py)")

    # ---- report ----
    for ww in warnings:
        print("WARN:", ww)
    if errors:
        print(f"\nVALIDATION FAILED ({len(errors)} errors):")
        for er in errors:
            print("  ERROR:", er)
        sys.exit(1)

    doc = {
        "schema_version": SCHEMA_VERSION, "environment_id": ENV_ID, "meta": META,
        "agents": D.AGENTS, "tool_bindings": D.TOOLS, "context_sources": D.CONTEXT,
        "memory_stores": D.MEMORY, "output_sinks": D.SINKS, "execution_edges": D.EDGES,
        "controls": D.CONTROLS,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False)
    print(f"\nAGENTIC OK: {len(D.AGENTS)} agents, {len(D.TOOLS)} tool_bindings, "
          f"{len(D.CONTEXT)} context_sources, {len(D.MEMORY)} memory_stores, {len(D.SINKS)} output_sinks, "
          f"{len(D.EDGES)} execution_edges, {len(D.CONTROLS)} controls "
          f"({len(warnings)} warnings) -> {OUT}")


if __name__ == "__main__":
    main()
