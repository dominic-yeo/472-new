# -*- coding: utf-8 -*-
"""L2 action assembler: compact cores -> full Pengent L2 nodes (Discourse).

Keeps every action independently authored (Subject/Operation/Object/Req/Eff)
while filling the Pengent-required and compatibility fields and deriving
consumes/produces/l1_keys/object_type so the file is a superset of Pengent output.
"""
from common import fact_key

# Discourse subjects (SUBJECTS[k] = (identity, role, auth_context)).
# Auth is a session cookie `_t` + CSRF token, or an api_key/api_username pair.
# Authorization tiers (Guardian + route constraints):
#   Anonymous -- not signed in
#   User      -- signed-in member (current_user present)
#   Staff     -- moderator or admin (StaffConstraint / Guardian#is_staff?)
#   Admin     -- admin only (AdminConstraint / Guardian#is_admin?)
SUBJECTS = {
    "Anonymous": ("Anonymous", "Public", "None"),
    "User":      ("AuthenticatedUser", "Member", "Session"),
    "Staff":     ("StaffUser", "Moderator", "Session"),
    "Admin":     ("AdminUser", "Administrator", "Session"),
}

_nodes = []
_seen_keys = set()


def obj(kind, id, type, binding_source="request", binding_field="", binding_resource="",
        name=None, role="target", attribute="", state_field="", participants=None, constraints=None):
    return {"kind": kind, "id": id, "type": type, "name": name or type, "entity": type,
            "role": role, "attribute": attribute, "state_field": state_field,
            "binding": {"source": binding_source, "field": binding_field, "resource": binding_resource},
            "participants": participants or [], "constraints": constraints or []}


def principal_p(id, type, role, relative_role, binding=None):
    return {"id": id, "type": type, "role": role, "relative_role": relative_role,
            "binding": binding or {}}


def entity_p(id, type, role, binding=None):
    return {"id": id, "type": type, "role": role, "binding": binding or {}}


def _term_decls(fact):
    out = []
    for arg in fact.get("arguments", []):
        if not isinstance(arg, dict):
            continue
        k = arg.get("kind")
        if k == "reference":
            t = arg.get("target") or {}
            if isinstance(t, dict) and t.get("kind") in {"entity", "subject", "principal"}:
                out.append(t)
        elif k in {"subject", "principal", "entity"}:
            out.append(arg)
    return out


def _auto_declare(object, requirements, gen, kill):
    declared = {"actor", object["id"]}
    for p in object.get("participants", []):
        declared.add(p.get("id"))
    seen = set(declared)
    for e in ([r["fact"] for r in requirements] +
              [x["fact"] for x in gen] + [x["fact"] for x in kill]):
        for t in _term_decls(e):
            tid = t.get("id")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            if t.get("kind") == "principal":
                object["participants"].append(
                    principal_p(tid, t.get("type"), t.get("role") or tid,
                                t.get("relative_role") or "PEER"))
            else:
                object["participants"].append(
                    entity_p(tid, t.get("type"), t.get("role") or "related"))


def action(key, name, crud, business, subject, object, requirements, gen, kill,
           io_accounting, bindings, vis, vis_reason, reachable, reach_conds, evidence,
           confidence, reasoning, description, observable=None, notes=None):
    if key in _seen_keys:
        raise ValueError(f"duplicate action_key {key}")
    _seen_keys.add(key)
    idn = f"gt-action-{len(_nodes) + 1:03d}"
    sid, role, auth = SUBJECTS[subject]
    _auto_declare(object, requirements, gen, kill)

    consumes = [fact_key(r["fact"]) for r in requirements]
    produces = [fact_key(e["fact"]) for e in gen]

    node = {
        "id": idn, "name": name, "kind": "normal", "description": description,
        "action_key": key,
        "subject": {"id": "actor", "identity": sid, "role": role, "auth_context": auth},
        "operation": {"business": business, "crud": crud},
        "object": object,
        "requirements": requirements,
        "effects": {"gen": gen, "kill": kill},
        "io_accounting": io_accounting,
        "l1_bindings": bindings,
        "confidence": confidence,
        "reasoning": reasoning,
        "l1_keys": [b["l1_key"] for b in bindings],
        "consumes": consumes,
        "produces": produces,
        "object_type": object["kind"],
        "lifecycle": "", "operations": [], "secondary_objects": [],
        "gt": {
            "visibility": {"minimum": vis, "reason": vis_reason},
            "black_box_reachable": reachable,
            "reachability_conditions": reach_conds,
            "observable_evidence": observable or [],
            "evidence": evidence,
            "notes": notes,
        },
    }
    _nodes.append(node)
    return node


def bind(l1_key, methods, sel_field="", sel_values=None):
    return {"l1_key": l1_key, "methods": methods,
            "selector": {"field": sel_field, "values": sel_values or []}}


# ---------------------------------------------------------------------------
# qa(): compact quick-action for scaling across many modules. Auto-fills the
# standard auth requirement for the subject tier and derives default gen/kill
# from the crud verb (Read->Know, Create->Exists, Update->State, Delete->kill
# Exists). io_accounting is left empty (the validator allows it). Pass gen/kill
# explicitly to override for security-relevant effects.
# ---------------------------------------------------------------------------
from common import (subj as _subj, reference as _ref, entity as _ent, f_auth as _fauth,
                    f_know as _fknow, f_exists as _fexists, f_state as _fstate,
                    f_can as _fcan, req as _req, eff as _eff, ev as _ev)

_ACTOR = _subj()
_INSTANCE = _ent("instance", "Instance", "authority")


def _auth_reqs(subject):
    if subject == "Anonymous":
        return []
    reqs = [_req("authentication", _fauth(_ACTOR, "Session"),
                 "Signed-in session cookie / API key required (current_user present).")]
    if subject == "Admin":
        reqs.append(_req("authorization", _fcan(_ACTOR, "Administer", _INSTANCE),
                         "Admin only (AdminConstraint / Guardian#is_admin?)."))
    elif subject == "Staff":
        reqs.append(_req("authorization", _fcan(_ACTOR, "Moderate", _INSTANCE),
                         "Staff only (StaffConstraint / Guardian#is_staff?)."))
    return reqs


def qa(key, name, crud, business, subject, l1key, methods, entity_type,
       entity_id=None, extra_req=None, gen=None, kill=None, vis="black_box",
       vis_reason="", reach_conds=None, src="", evidence=None, description="",
       notes=None, reachable=True, confidence=0.9, obj_kind="entity",
       sel_field="", sel_values=None):
    entity_id = entity_id or entity_type.lower().replace(" ", "_")
    ENT = _ent(entity_id, entity_type, "target")
    reqs = _auth_reqs(subject) + (extra_req or [])
    if gen is None and kill is None:
        if crud == "Read":
            gen, kill = [_eff(_fknow(_ACTOR, _ref(entity_type, ENT)), "io_reference",
                              f"Response discloses {entity_type}.")], []
        elif crud == "Create":
            gen, kill = [_eff(_fexists(ENT), "action_semantics", f"A {entity_type} is created.")], []
        elif crud == "Update":
            gen, kill = [_eff(_fstate(ENT, "state", "updated"), "state_transition",
                              f"{entity_type} state is modified.")], []
        elif crud == "Delete":
            gen, kill = [], [_eff(_fexists(ENT), "state_transition", f"The {entity_type} is removed.")]
        else:
            gen, kill = [], []
    gen = gen or []
    kill = kill or []
    evd = evidence or ([_ev("source", src, business)] if src else [])
    return action(
        key, name, crud, business, subject,
        obj(obj_kind, entity_id, entity_type, "implicit", "", "", role="target"),
        requirements=reqs, gen=gen, kill=kill, io_accounting=[],
        bindings=[bind(l1key, methods, sel_field, sel_values)],
        vis=vis, vis_reason=vis_reason, reachable=reachable, reach_conds=reach_conds or [],
        evidence=evd, confidence=confidence, reasoning=description or name,
        description=description or name, notes=notes)


def reset():
    _nodes.clear()
    _seen_keys.clear()


def nodes():
    return _nodes
