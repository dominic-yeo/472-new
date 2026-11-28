#!/usr/bin/env python3
"""
gt_validate_all.py -- corpus-wide validation runner.

Consolidates the validation results the report relies on into one reproducible
summary. For each application it:

  * runs validate_gt.py (the L1/L2 structural core: closed vocabularies, semantic
    IO consistency, cross-layer L2->L1 closure, L1 key uniqueness, L2 coverage);
  * adds two checks the report claims but the core did not implement:
      - L2 action id uniqueness (within the application's dataset);
      - method-level L1 binding consistency (each L2 binding's methods are a
        subset of the bound L1 node's methods);
  * validates the agentic records (referential integrity, lineage closure,
    enum validity, evidence-grading invariants).

Semantic correctness is NOT checked here -- this establishes structural
consistency only. Exit code is nonzero if any check fails.
"""
import glob, os, subprocess, sys, yaml

ROOT = os.path.dirname(os.path.abspath(__file__))

# ---- agentic closed vocabularies (from the data) ----
EFFECT = {"code_execution", "external_send", "write", "read", "mixed", "none"}
TRUST = {"untrusted_data", "mixed", "trusted_instruction"}
ENFORCE = {"blocking", "modifying", "advisory"}
EVID = {"observed", "source_confirmed"}
BLOCKERS = {"local_not_driven", "scheduling_required", "external_integration", "crypto_blocked"}

def load(p):
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def run_core(l1p, l2p):
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "validate_gt.py"),
                        "--l1", l1p, "--l2", l2p],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout.strip() + ("\n" + r.stderr.strip() if r.stderr.strip() else "")

def check_l1l2_extra(l1, l2):
    errs = []
    l1_methods = {}
    for n in (l1.get("nodes") or []):
        if n.get("key"):
            l1_methods[n["key"]] = set(n.get("methods") or [])
    # L2 id uniqueness (within app)
    seen = set()
    for n in (l2.get("nodes") or []):
        nid = n.get("id")
        if nid in seen:
            errs.append(f"duplicate L2 id {nid}")
        seen.add(nid)
        # method-subset binding consistency
        for b in (n.get("l1_bindings") or []):
            k = b.get("l1_key")
            bm = set(b.get("methods") or [])
            if k in l1_methods and bm and not bm <= l1_methods[k]:
                errs.append(f"{nid}: binding methods {sorted(bm-l1_methods[k])} "
                            f"not in L1 {k} methods {sorted(l1_methods[k])}")
    return errs

def check_agentic(doc):
    errs = []
    agents = {a["id"] for a in (doc.get("agents") or [])}
    tools = {t["id"] for t in (doc.get("tool_bindings") or [])}
    ctx = {c["id"] for c in (doc.get("context_sources") or [])}
    mem = {m["id"] for m in (doc.get("memory_stores") or [])}
    sinks = {s["id"] for s in (doc.get("output_sinks") or [])}
    ctls = {c["id"] for c in (doc.get("controls") or [])}

    def sub(label, ids, universe):
        for i in (ids or []):
            if i is None:
                continue
            if isinstance(i, str) and i.startswith("("):
                continue  # placeholder like "(model-selected binding)"
            if i not in universe:
                errs.append(f"{label}: unknown ref {i}")

    # referential integrity + lineage closure
    for a in (doc.get("agents") or []):
        w = f"agent {a['id']}"
        sub(w + ".tool_binding_ids", a.get("tool_binding_ids"), tools)
        sub(w + ".context_source_ids", a.get("context_source_ids"), ctx)
        sub(w + ".memory_ids", a.get("memory_ids"), mem)
        sub(w + ".output_sink_ids", a.get("output_sink_ids"), sinks)
        sub(w + ".control_ids", a.get("control_ids"), ctls)
    for t in (doc.get("tool_bindings") or []):
        w = f"tool {t['id']}"
        if t.get("agent_id") not in agents:
            errs.append(f"{w}: unknown agent_id {t.get('agent_id')}")
        sub(w + ".control_ids", t.get("control_ids"), ctls)
        sub(w + ".output_ids", t.get("output_ids"), ctx | mem | sinks)
    for c in (doc.get("context_sources") or []):
        sub(f"ctx {c['id']}.destination_agent_ids", c.get("destination_agent_ids"), agents)
        for wr in (c.get("writers") or []):
            p = wr.get("principal")
            if isinstance(p, str) and p.startswith("agent.") and p not in agents:
                errs.append(f"ctx {c['id']}.writer: unknown agent principal {p}")
    for m in (doc.get("memory_stores") or []):
        sub(f"mem {m['id']}.readers", m.get("readers"), agents)
        for wr in (m.get("writers") or []):
            p = wr.get("principal")
            if isinstance(p, str) and p.startswith("agent.") and p not in agents:
                errs.append(f"mem {m['id']}.writer: unknown agent principal {p}")
    for s in (doc.get("output_sinks") or []):
        sub(f"sink {s['id']}.producer_ids", s.get("producer_ids"), agents | tools)
        sub(f"sink {s['id']}.becomes_context_source_ids", s.get("becomes_context_source_ids"), ctx)
    for e in (doc.get("execution_edges") or []):
        w = f"edge {e['id']}"
        src = (e.get("source") or {}).get("agent_id")
        if src is not None and src not in agents:
            errs.append(f"{w}.source.agent_id: unknown {src}")
        dst = e.get("destination") or {}
        if dst.get("agent_id") is not None and dst.get("agent_id") not in agents:
            errs.append(f"{w}.destination.agent_id: unknown {dst.get('agent_id')}")
        tb = dst.get("tool_binding_id")
        if tb and not str(tb).startswith("(") and tb not in tools:
            errs.append(f"{w}.destination.tool_binding_id: unknown {tb}")
        if dst.get("output_sink_id") and dst.get("output_sink_id") not in sinks:
            errs.append(f"{w}.destination.output_sink_id: unknown {dst.get('output_sink_id')}")
        sub(w + ".input_source_ids", e.get("input_source_ids"), ctx)
        sub(w + ".output_ids", e.get("output_ids"), ctx | mem | sinks)
        sub(w + ".control_ids", e.get("control_ids"), ctls)
    for c in (doc.get("controls") or []):
        sub(f"control {c['id']}.applies_to_agent_ids", c.get("applies_to_agent_ids"), agents)
        sub(f"control {c['id']}.applies_to_tool_binding_ids", c.get("applies_to_tool_binding_ids"), tools)

    # enum validity
    for t in (doc.get("tool_bindings") or []):
        if t.get("effect_class") not in EFFECT:
            errs.append(f"tool {t['id']}: invalid effect_class {t.get('effect_class')}")
    for c in (doc.get("context_sources") or []):
        if c.get("trust_class") not in TRUST:
            errs.append(f"ctx {c['id']}: invalid trust_class {c.get('trust_class')}")
    for c in (doc.get("controls") or []):
        if c.get("enforcement_mode") not in ENFORCE:
            errs.append(f"control {c['id']}: invalid enforcement_mode {c.get('enforcement_mode')}")

    # evidence-grading invariants over every top-level record
    rec_types = ["agents", "tool_bindings", "context_sources", "memory_stores",
                 "output_sinks", "execution_edges", "controls"]
    graded = observed = 0
    for rt in rec_types:
        for rec in (doc.get(rt) or []):
            es = rec.get("evidence_status")
            if es is None:
                continue
            graded += 1
            if es not in EVID:
                errs.append(f"{rt} {rec.get('id')}: invalid evidence_status {es}")
            blk = rec.get("runtime_blocker")
            if es == "observed":
                observed += 1
                if blk is not None:
                    errs.append(f"{rt} {rec.get('id')}: observed record carries blocker {blk}")
            else:
                if blk is None:
                    errs.append(f"{rt} {rec.get('id')}: unobserved record missing runtime_blocker")
                elif blk not in BLOCKERS:
                    errs.append(f"{rt} {rec.get('id')}: invalid runtime_blocker {blk}")
    return errs, graded, observed

def main():
    os.chdir(ROOT)
    rows = []
    any_fail = False
    tot_l1 = tot_l2 = tot_ag = tot_obs = 0
    for d in sorted(glob.glob("*_gt")):
        l1p, l2p = f"{d}/l1_gt.yaml", f"{d}/l2_gt.yaml"
        agp = f"{d}/agentic_gt.yaml"
        app = d.replace("_gt", "")
        core = extra = ag = None
        n1 = n2 = nag = obs = 0
        if os.path.exists(l1p) and os.path.exists(l2p):
            l1, l2 = load(l1p), load(l2p)
            n1 = len(l1.get("nodes") or []); n2 = len(l2.get("nodes") or [])
            kinds = {(n.get("kind")) for n in (l1.get("nodes") or [])}
            ext_vocab = bool(kinds - {"api", "page", "static"})
            if ext_vocab:
                # OpenClaw: extended invocation-surface vocabulary (channel/rpc/internal),
                # explicitly scoped and not part of the traditional-web corpus.
                core = "ext-vocab (invocation layer; excluded from standard core)"
                extra = "-"
            else:
                ok, _ = run_core(l1p, l2p)
                ee = check_l1l2_extra(l1, l2)
                core = "OK" if ok else "FAIL"
                extra = "OK" if not ee else "FAIL: " + "; ".join(ee[:3])
                if not ok or ee:
                    any_fail = True
        if os.path.exists(agp):
            errs, nag, obs = check_agentic(load(agp))
            ag = "OK" if not errs else "FAIL: " + "; ".join(errs[:3])
            if errs:
                any_fail = True
        if core or ag:
            rows.append((app, n1, n2, nag, obs, core, extra, ag))
            tot_l1 += n1; tot_l2 += n2; tot_ag += nag; tot_obs += obs

    out = []
    out.append("# GT validation summary\n")
    out.append("_Generated by `gt_validate_all.py`. Structural consistency only; "
               "semantic correctness is established separately (author spot-check)._\n")
    out.append("| app | L1 | L2 | agentic | ag.observed | L1/L2 core | L2-id+method | agentic checks |")
    out.append("|---|--:|--:|--:|--:|:--:|:--:|:--:|")
    for app, n1, n2, nag, obs, core, extra, ag in rows:
        out.append(f"| {app} | {n1 or ''} | {n2 or ''} | {nag or ''} | {obs or ''} "
                   f"| {core or '-'} | {extra or '-'} | {ag or '-'} |")
    out.append(f"| **TOTAL** | **{tot_l1}** | **{tot_l2}** | **{tot_ag}** | **{tot_obs}** | | | |")
    out.append("")
    out.append("**Checks performed per application**")
    out.append("- *L1/L2 core* (`validate_gt.py`): closed vocabularies (predicate, value_kind, "
               "location, crud, visibility); semantic IO consistency (semantic_inputs == "
               "mergeable input resources; every flow field lifts); cross-layer closure "
               "(every L2 binding resolves to a real L1 key); L1 key uniqueness; L2 coverage "
               "of candidate L1 api nodes.")
    out.append("- *L2-id + method*: L2 action id uniqueness within the app; each L2 binding's "
               "methods are a subset of the bound L1 node's methods.")
    out.append("- *agentic*: referential integrity (every id ref resolves); lineage closure "
               "(producers/outputs/becomes_context_source resolve); enum validity "
               "(effect_class, trust_class, enforcement_mode); evidence invariants "
               "(observed <=> no blocker; unobserved <=> exactly one blocker from the closed set).")
    report = "\n".join(out) + "\n"
    with open("validation_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print("RESULT:", "FAIL" if any_fail else "ALL CHECKS PASS")
    sys.exit(1 if any_fail else 0)

if __name__ == "__main__":
    main()
