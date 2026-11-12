# -*- coding: utf-8 -*-
"""L2 action assembler: compact cores -> full Pengent L2 nodes (WriteFreely).

Identical design to the MediaCMS assembler; only the Subject presets differ.
WriteFreely has two auth transports: a web-session cookie (handler.User/Web/Admin)
and an Authorization-header access token (handler.UserAPI / apiAuth inside All).
"""
from common import fact_key

# semantic Subject presets (identity, role, auth_context). Validator does not
# constrain these strings; chosen to read as security roles + the real transport.
SUBJECTS = {
    # (identity, role, auth_context) -- Rocket.Chat REST auth = X-Auth-Token + X-User-Id
    # (or Authorization: Bearer <personal-access-token>); per-route authRequired + permission checks.
    "Anonymous":     ("Anonymous",   "Guest",  "Anonymous"),   # no auth (login, users.register, public settings)
    "User":          ("CurrentUser", "User",   "AuthToken"),   # authenticated workspace user
    "RoomMember":    ("CurrentUser", "Member", "AuthToken"),   # user with access to a room
    "RoomOwner":     ("CurrentUser", "Owner",  "AuthToken"),   # room owner/moderator (room-scoped authz)
    "Administrator": ("AdminUser",   "Admin",  "AuthToken"),   # holds admin permission(s)
    "Bot":           ("BotUser",     "Bot",    "PersonalAccessToken"), # PAT / bot
}

_nodes = []
_seen_keys = set()


def obj(kind, id, type, binding_source="request", binding_field="", binding_resource="",
        name=None, role="target", attribute="", state_field="", participants=None, constraints=None):
    return {
        "kind": kind, "id": id, "type": type, "name": name or type, "entity": type,
        "role": role, "attribute": attribute, "state_field": state_field,
        "binding": {"source": binding_source, "field": binding_field, "resource": binding_resource},
        "participants": participants or [], "constraints": constraints or [],
    }


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
        "confidence": confidence, "reasoning": reasoning,
        "l1_keys": [b["l1_key"] for b in bindings],
        "consumes": consumes, "produces": produces,
        "object_type": object["kind"],
        "lifecycle": "", "operations": [], "secondary_objects": [],
        "gt": {
            "visibility": {"minimum": vis, "reason": vis_reason},
            "black_box_reachable": reachable,
            "reachability_conditions": reach_conds,
            "observable_evidence": observable or [],
            "evidence": evidence, "notes": notes,
        },
    }
    _nodes.append(node)
    return node


def bind(l1_key, methods, sel_field="", sel_values=None):
    return {"l1_key": l1_key, "methods": methods,
            "selector": {"field": sel_field, "values": sel_values or []}}


def reset():
    _nodes.clear()
    _seen_keys.clear()


def nodes():
    return _nodes
