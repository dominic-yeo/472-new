# -*- coding: utf-8 -*-
"""Extra GT-quality lint beyond validate_gt.py:
 (A) every fact variable (subject/principal/entity + reference targets) is declared
     in the action's Subject/Object/participants;
 (B) dependency graph can form: every consumed fact matches a produced fact
     (canonical key) or an approved ROOT.
Run with PYTHONIOENCODING=utf-8. Exit 1 on any violation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2_data  # noqa: F401
from l2lib import nodes

# Approved roots: facts a caller legitimately brings or that are environment axioms,
# so they need not be produced by another action's Eff.
ROOT_PREDICATES = {"Can", "Authenticated"}  # authorization axioms + base session
ROOT_SUBSTRINGS = [
    "Know(actor:User[SELF],Password(",     # caller brings their own password at login
]


def canon(fkey):
    """Drop per-action bookkeeping: entity local-id and {role}, keep load-bearing parts."""
    import re
    s = re.sub(r"\{[^}]*\}", "", fkey)       # drop {role}
    s = re.sub(r"\b[a-z_]+:", ":", s)         # drop entity/subject local id, keep :Type
    return s


def declared_ids(a):
    ids = {"actor", a["object"]["id"]}
    for p in a["object"].get("participants", []):
        ids.add(p.get("id"))
    return ids


def fact_ids(fact):
    out = []
    for arg in fact.get("arguments", []):
        if not isinstance(arg, dict):
            continue
        k = arg.get("kind")
        if k == "reference":
            t = arg.get("target") or {}
            if isinstance(t, dict) and t.get("id"):
                out.append(t["id"])
        elif k in {"subject", "principal", "entity"}:
            out.append(arg.get("id"))
    return out


def main():
    acts = nodes()
    undeclared = []
    for a in acts:
        d = declared_ids(a)
        allfacts = ([r["fact"] for r in a["requirements"]] +
                    [e["fact"] for e in a["effects"]["gen"]] +
                    [e["fact"] for e in a["effects"]["kill"]])
        for f in allfacts:
            for fid in fact_ids(f):
                if fid not in d:
                    undeclared.append((a["action_key"], f.get("predicate"), fid))

    produced = set()
    for a in acts:
        for e in a["effects"]["gen"]:
            produced.add(canon(__import__("common").fact_key(e["fact"])))

    drift = []
    for a in acts:
        for r in a["requirements"]:
            f = r["fact"]
            if f.get("predicate") in ROOT_PREDICATES:
                continue
            fk = __import__("common").fact_key(f)
            if any(sub in fk for sub in ROOT_SUBSTRINGS):
                continue
            if canon(fk) not in produced:
                drift.append((a["action_key"], fk))

    print(f"declared-variable violations: {len(undeclared)}")
    for v in undeclared[:60]:
        print("   UNDECLARED", v)
    print(f"dependency drift (consumed-but-not-produced, non-root): {len(drift)}")
    for v in drift[:60]:
        print("   DRIFT", v)

    if undeclared or drift:
        sys.exit(1)
    print("lint OK: all fact variables declared; dependency graph closes (roots + produced).")


if __name__ == "__main__":
    main()
