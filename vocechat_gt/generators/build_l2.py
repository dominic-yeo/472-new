"""Assemble L2 (Action-L2 v3) nodes for VoceChat from the per-op cores + L1 nodes."""
import json, collections, copy
from l2lib import *
import l2_spec, l2_spec2, l2_spec3, l2_spec4  # populate SPEC
from l2_spec import SPEC, SUBJECTS
from common import SEM

SCRATCH = __import__("os").path.dirname(__import__("os").path.abspath(__file__)) + "/"
L1 = json.load(open(SCRATCH + "l1_build.json", encoding="utf-8"))
OP = L1["op_index"]
NODE = {n["key"]: n for n in L1["l1"]["nodes"]}
API = "http://localhost:3009/api"

SUFFIX_TARGET = {
    "": None, "recipient": "recipient", "member": "member", "msg": "message", "group": "group",
    "user": "user", "contact": "contact", "contactp": "contact_user", "invite": "invite",
    "challenge": "challenge", "archive": "archive", "fav": "favorite", "peer": "peer",
    "secret": "server", "refresh": "session", "callname": "call", "challenge": "challenge", "credtok": "session", "x": None,
}

def refs_in(fact):
    out = []
    for a in fact.get("arguments", []):
        if isinstance(a, dict):
            if a.get("kind") == "reference":
                out.append(("ref", a))
            elif a.get("kind") in ("entity", "principal", "subject"):
                out.append((a["kind"], a))
    return out

def find_req_know(reqs, target_id):
    cands = []
    for r in reqs:
        f = r["fact"]
        if f["predicate"] not in ("Know",):
            continue
        ref = next((a for a in f["arguments"] if isinstance(a, dict) and a.get("kind") == "reference"), None)
        if ref is None:
            continue
        tid = ref["target"]["id"]
        if target_id is None or tid == target_id:
            cands.append((r, fact_key(f)))
    return cands

def find_gen_know(gens, reftype):
    for e in gens:
        f = e["fact"]
        if f["predicate"] != "Know":
            continue
        ref = next((a for a in f["arguments"] if isinstance(a, dict) and a.get("kind") == "reference"), None)
        if ref and ref["type"] == reftype:
            return fact_key(f)
    return None

IGN = {
    "attr": "New business content/payload for this action; not a pre-existing object reference.",
    "attr_state": "New value written by this action; accounted as the object state it sets, not a Know precondition.",
    "attr_cred": "Credential/secret presented for this action; proof material, not a stable object reference.",
    "attr_cursor": "Pagination cursor over an existing collection; not a semantic object of this action.",
    "attr_ref_user": "References a user inside the payload but is not a precondition fact of this action.",
    "attr_ref_group": "References a group inside the payload but is not a precondition fact of this action.",
    "attr_ref_msg": "References a message inside the payload but is not a precondition fact of this action.",
}

def build_action(key, method, core, idx):
    op = OP.get(f"{key}|{method}")
    node = NODE[key]
    variant = next((v for v in node["io_variants"] if v["method"] == method), None)
    scls = core["subject"] or (l2_spec_subject(op) if op else "user")
    subject = {"id": "actor", **{k: SUBJECTS[scls][k] for k in ("identity", "role", "auth_context")}}

    reqs = [copy.deepcopy(r) for r in core["req_facts"]]
    gens = [copy.deepcopy(e) for e in core["gen"]]
    kills = [copy.deepcopy(e) for e in core["kill"]]
    req_keys = {fact_key(r["fact"]) for r in reqs}
    gen_keys = {fact_key(e["fact"]) for e in gens}

    # object
    o = core["obj"]
    _kind = "entity" if o["kind"] == "collection" else o["kind"]
    obj = {"kind": _kind, "id": o["id"], "type": o["type"], "name": o["name"], "entity": o["entity"],
           "role": o["role"], "attribute": o.get("attribute", ""), "state_field": o.get("state_field", ""),
           "binding": o["binding"], "participants": [], "constraints": list(core["constraints"])}

    # collect declared ids from all facts
    declared = {"actor", obj["id"]}
    participants = []
    def add_part(term):
        pid = term.get("id")
        if pid in declared or any(p["id"] == pid for p in participants):
            return
        if term["kind"] == "principal":
            participants.append({"id": pid, "type": term["type"], "role": term.get("role", "participant"),
                                 "relative_role": term.get("relative_role", "PEER"),
                                 "binding": {"source": "request", "field": "", "resource": ""}})
        else:
            participants.append({"id": pid, "type": term["type"], "role": term.get("role", "related"),
                                 "binding": {"source": "request", "field": "", "resource": ""}})
    # spec-declared participants first (nicer roles)
    for p in core["participants"]:
        if p["id"] in declared:
            continue
        if p["kind"] == "principal":
            participants.append({"id": p["id"], "type": p["type"], "role": p["role"], "relative_role": p["relative_role"],
                                 "binding": {"source": "request", "field": "", "resource": ""}})
        else:
            participants.append({"id": p["id"], "type": p["type"], "role": p["role"],
                                 "binding": {"source": "request", "field": "", "resource": ""}})
    for bid, btype, brole in core["extra_bindings"]:
        if bid not in declared and not any(p["id"] == bid for p in participants):
            participants.append({"id": bid, "type": btype, "role": brole, "binding": {"source": "request", "field": "", "resource": ""}})
    # auto from facts
    for fl in (reqs, gens, kills):
        for item in fl:
            for kind, term in refs_in(item["fact"]):
                if kind == "ref":
                    add_part(term["target"])
                elif kind in ("entity", "principal"):
                    add_part(term)
    obj["participants"] = participants

    # io_accounting
    io = []
    io_in = dict(core["io_in"])
    cred_fields = io_in.pop("__cred__", None)
    if cred_fields:
        for cf in cred_fields:
            io_in[cf] = "attr_cred"
    # flow inputs of the variant
    vin = {f["name"]: f for f in variant["request"]["fields"] if f["flow"]} if variant else {}
    vout_names = set(variant["outputs"]) if variant else set()
    for fname, token in io_in.items():
        label = f"{fname} / {SEM.get(fname, (fname,))[0]}"
        if token.startswith("req_know"):
            suf = token[len("req_know"):].lstrip("_")
            tid = SUFFIX_TARGET.get(suf, suf or None)
            cands = find_req_know(reqs, tid)
            if not cands:
                raise SystemExit(f"{key}|{method}: no Know requirement for io_in {fname} (target {tid})")
            io.append(ioacc("input", label, "req", [cands[0][1]]))
        else:
            io.append(ioacc("input", label, "object_attribute", [], IGN.get(token, IGN["attr"])))
    # flow inputs present in variant but not mapped -> object_attribute
    for fname in vin:
        if fname not in io_in and fname not in (cred_fields or []):
            io.append(ioacc("input", f"{fname} / {SEM.get(fname, (fname,))[0]}", "object_attribute", [],
                            "Flow input not tied to a precondition fact; carried as part of the action payload."))
    # outputs
    io_out = dict(core["io_out"])
    for fname, token in io_out.items():
        res = SEM.get(fname, (fname + "(x)",))[0]
        label = f"{fname} / {res}"
        if token == "know":
            reftype = res.split("(")[0]
            gk = find_gen_know(gens, reftype)
            if gk is None:
                raise SystemExit(f"{key}|{method}: no gen Know({reftype}) for io_out {fname}")
            io.append(ioacc("output", label, "gen", [gk]))
        else:
            io.append(ioacc("output", label, "observed_only", [],
                            "Observed in the response but not a generated semantic fact of this action."))
    for fname in vout_names:
        if fname not in io_out:
            io.append(ioacc("output", f"{fname} / {SEM.get(fname, (fname,))[0]}", "observed_only", [],
                            "Response field observed only; not a generated semantic fact."))

    # l1 binding
    sel = {"field": "", "values": []}
    if core["selector"]:
        sel = {"field": core["selector"][0], "values": list(core["selector"][1])}
    bindings = [{"l1_key": key, "methods": [method], "selector": sel}]

    gt = node["gt"]
    reach = core.get("reach") if core.get("reach") is not None else (op["reach"] if op else True)
    conds = list(core.get("reach_conds") or gt.get("reachability_conditions", []))
    vis = gt["visibility"]
    observable = [{"observer_l1_key": key, "expected": f"{method} {key} reflects the {core['business']} outcome described above."}]
    evid = []
    for e in gt.get("evidence", []):
        if e["type"] == "source" and method.lower() in e.get("supports", "").lower() or e["type"] == "runtime":
            evid.append(e)
    evid = evid[:4] or gt.get("evidence", [])[:2]

    node_out = {
        "id": f"gt-{core['akey']}" + (f"-{idx}" if idx else ""),
        "name": core["name"], "kind": "normal", "description": core.get("desc") or core["name"] + ".",
        "action_key": core["akey"], "subject": subject,
        "operation": {"business": core["business"], "crud": core["crud"]},
        "object": obj,
        "requirements": [{"type": r["type"], "fact": r["fact"], "reason": r["reason"]} for r in reqs],
        "effects": {"gen": [{"fact": e["fact"], "basis": e["basis"], "reason": e["reason"]} for e in gens],
                    "kill": [{"fact": e["fact"], "basis": e["basis"], "reason": e["reason"]} for e in kills]},
        "io_accounting": io,
        "l1_bindings": bindings,
        "confidence": core["conf"],
        "reasoning": core.get("reasoning") or "Subject/Operation/Object and Req/Eff derived from the handler semantics and payload contract.",
        "l1_keys": [key],
        "consumes": [fact_key(r["fact"]) for r in reqs],
        "produces": [fact_key(e["fact"]) for e in gens],
        "object_type": o["kind"], "lifecycle": "", "operations": [], "secondary_objects": [],
        "gt": {
            "visibility": vis,
            "black_box_reachable": reach,
            "reachability_conditions": conds,
            "observable_evidence": observable,
            "evidence": evid,
            "notes": (op.get("notes") if op else None),
        },
    }
    return node_out


def l2_spec_subject(op):
    from l2lib import subj_class
    return subj_class(op)


nodes = []
seen_keys = set()
for spec_key, cores in SPEC.items():
    key, method = spec_key.rsplit("|", 1)
    seen_keys.add((key, method))
    for i, core in enumerate(cores):
        nodes.append(build_action(key, method, core, i if len(cores) > 1 else 0))

# coverage check
cands = set()
for n in L1["l1"]["nodes"]:
    if n["kind"] == "api" and n["io_variants"]:
        for v in n["io_variants"]:
            cands.add((n["key"], v["method"]))
covered = {(b["l1_key"], m) for n in nodes for b in n["l1_bindings"] for m in b["methods"]}
missing = sorted(cands - covered)
extra = sorted(covered - cands)

# duplicate action_key check
akc = collections.Counter(n["action_key"] for n in nodes)

l2 = {"schema_version": "pengent-web-gt-v1", "environment_id": "vocechat-0.5.36-local", "nodes": nodes, "edges": [], "annotation_issues": []}
json.dump(l2, open(SCRATCH + "l2_build.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("L2 nodes:", len(nodes), "candidates:", len(cands), "covered:", len(covered & cands))
print("MISSING coverage:", missing)
print("EXTRA bindings (no such candidate):", extra)
print("dup action_keys:", [(k, c) for k, c in akc.items() if c > 1])

# gate the build on cross-action fact reconciliation
import subprocess, sys
print("--- fact reconciliation (lint_l2) ---")
rc = subprocess.run([sys.executable, SCRATCH + "lint_l2.py"]).returncode
if rc != 0:
    sys.exit("BUILD FAILED: unresolved producer/consumer fact drift (see lint_l2 output above)")
