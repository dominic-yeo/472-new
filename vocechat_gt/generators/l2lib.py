"""Fact-language helpers and the generic L2 action builder for VoceChat."""
import re

# ---- typed terms -------------------------------------------------------------
def SUBJ(id="actor", type="User", rr="SELF"):
    return {"kind": "subject", "id": id, "type": type, "relative_role": rr}

def PRIN(id, type, role, rr):
    return {"kind": "principal", "id": id, "type": type, "role": role, "relative_role": rr}

def ENT(id, type, role):
    return {"kind": "entity", "id": id, "type": type, "role": role}

def REF(reftype, target):
    return {"kind": "reference", "type": reftype, "target": target}

def tk(x):
    if not isinstance(x, dict):
        return str(x)
    k = x.get("kind")
    if k == "reference":
        return f"{x.get('type')}({tk(x.get('target'))})"
    base = f"{x.get('id')}:{x.get('type')}"
    if k in ("subject", "principal"):
        return f"{base}[{x.get('relative_role')}]"
    return f"{base}{{{x.get('role')}}}"

def fact_key(f):
    return f"{f['predicate']}({','.join(tk(a) for a in f.get('arguments', []))})"

def FACT(pred, *args):
    return {"predicate": pred, "arguments": list(args)}

def req(type, fact, reason):
    return {"type": type, "fact": fact, "reason": reason}

def eff(fact, basis, reason):
    return {"fact": fact, "basis": basis, "reason": reason}

def ioacc(direction, field, disposition, facts, ignored=""):
    return {"direction": direction, "field": field, "disposition": disposition,
            "facts": list(facts), "ignored_reason": ignored}

# ---- subject presets ---------------------------------------------------------
SUBJECTS = {
    "anon":   {"id": "actor", "identity": "Anonymous", "role": "Guest", "auth_context": "Anonymous"},
    "user":   {"id": "actor", "identity": "CurrentUser", "role": "User", "auth_context": "Session"},
    "userng": {"id": "actor", "identity": "CurrentUser", "role": "User", "auth_context": "Session"},
    "admin":  {"id": "actor", "identity": "Administrator", "role": "Admin", "auth_context": "Session"},
    "bot":    {"id": "actor", "identity": "ServiceAccount", "role": "Service", "auth_context": "APIToken"},
    "secret": {"id": "actor", "identity": "ServiceAccount", "role": "Service", "auth_context": "ServiceCredential"},
}

def subj_class(op):
    a = op["auth"]
    if a in SUBJECTS:
        return a
    if a == "unknown":
        return "user" if any(f["name"] in ("X-API-Key",) for f in op["req"]) else "anon"
    if a in ("token", "token_q"):
        return "user"
    if a == "token_ng":
        return "userng"
    return "anon"

def subject_dict(cls):
    s = SUBJECTS[cls]
    return {"id": s["id"], "identity": s["identity"], "role": s["role"], "auth_context": s["auth_context"]}
