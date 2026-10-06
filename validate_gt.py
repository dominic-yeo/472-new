#!/usr/bin/env python3
import argparse, re, sys, yaml

PREDICATES = {"Exists", "Know", "State", "Relation", "Can", "Authenticated"}
CRUD = {"Create", "Read", "Update", "Delete"}
OBJECT_KINDS = {"entity", "state", "relation"}
REQ_TYPES = {"existence", "knowledge", "state", "relation", "authorization", "authentication"}
EFFECT_BASES = {
    "io_reference", "action_semantics", "auth_transition", "implicit_context",
    "state_transition", "relation_transition", "unspecified",
}
RELATIVE_ROLES = {"SELF", "SUPERIOR", "SUBORDINATE", "PEER", "UNRELATED"}
VALUE_KINDS = {"identifier","locator","credential","content","state","attribute","collection","summary","opaque"}
VIS = {"black_box","grey_box","white_box"}

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def fact_key(f):
    def tk(x):
        if not isinstance(x, dict):
            return str(x)
        k = x.get("kind")
        if k == "reference":
            return f"{x.get('type')}({tk(x.get('target'))})"
        base = f"{x.get('id')}:{x.get('type')}"
        if k in {"subject","principal"}:
            return f"{base}[{x.get('relative_role')}]"
        return f"{base}{{{x.get('role')}}}"
    return f"{f.get('predicate')}({','.join(tk(x) for x in (f.get('arguments') or []))})"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--l1",required=True)
    ap.add_argument("--l2",required=True)
    a=ap.parse_args()
    l1,l2=load(a.l1),load(a.l2)
    errors=[]

    nodes=l1.get("nodes") or []
    l1_by_key={}
    candidates=set()
    for i,n in enumerate(nodes):
        w=f"L1[{i}]"
        key=n.get("key")
        if not key: errors.append(f"{w}: missing key"); continue
        if key in l1_by_key: errors.append(f"{w}: duplicate key {key}")
        l1_by_key[key]=n
        if n.get("kind") not in {"api","page","static"}:
            errors.append(f"{w}: invalid kind")
        if n.get("kind")=="api" and n.get("io_variants"):
            candidates.add(key)

        # semantic decisions
        for fld in ("semantic_input_decisions","semantic_output_decisions"):
            for j,d in enumerate(n.get(fld) or []):
                for req in ("raw_field","resource","mergeable","value_kind","reference_capable","reference_fields","reason"):
                    if req not in d:
                        errors.append(f"{w}.{fld}[{j}]: missing {req}")
                if d.get("value_kind") not in VALUE_KINDS:
                    errors.append(f"{w}.{fld}[{j}]: invalid value_kind")
                if d.get("reference_capable") and d.get("value_kind") not in {"identifier","locator"}:
                    errors.append(f"{w}.{fld}[{j}]: reference_capable only valid for identifier/locator")
                if d.get("reference_capable") and not d.get("reference_fields"):
                    errors.append(f"{w}.{fld}[{j}]: reference_capable requires reference_fields")

        exp_in={d.get("resource") for d in n.get("semantic_input_decisions") or [] if d.get("mergeable")}
        exp_out={d.get("resource") for d in n.get("semantic_output_decisions") or [] if d.get("mergeable")}
        if set(n.get("semantic_inputs") or []) != exp_in:
            errors.append(f"{w}: semantic_inputs != mergeable=true input resources")
        if set(n.get("semantic_outputs") or []) != exp_out:
            errors.append(f"{w}: semantic_outputs != mergeable=true output resources")

        v=((n.get("gt") or {}).get("visibility") or {}).get("minimum")
        if v not in VIS: errors.append(f"{w}: invalid gt.visibility.minimum")

    covered=set()
    for i,n in enumerate(l2.get("nodes") or []):
        w=f"L2[{i}]"
        if n.get("operation",{}).get("crud") not in CRUD:
            errors.append(f"{w}: invalid CRUD")
        if not n.get("operation",{}).get("business"):
            errors.append(f"{w}: missing operation.business")
        if n.get("object",{}).get("kind") not in OBJECT_KINDS:
            errors.append(f"{w}: invalid object.kind")

        declared={"actor", str(n.get("object",{}).get("id") or "")}
        declared |= {str(p.get("id") or "") for p in n.get("object",{}).get("participants") or []}

        req_keys=set()
        gen_keys=set()
        for j,r in enumerate(n.get("requirements") or []):
            if r.get("type") not in REQ_TYPES:
                errors.append(f"{w}.requirements[{j}]: invalid type")
            f=r.get("fact") or {}
            if f.get("predicate") not in PREDICATES:
                errors.append(f"{w}.requirements[{j}]: invalid predicate")
            req_keys.add(fact_key(f))
        for side in ("gen","kill"):
            for j,e in enumerate((n.get("effects") or {}).get(side) or []):
                if e.get("basis") not in EFFECT_BASES:
                    errors.append(f"{w}.effects.{side}[{j}]: invalid basis")
                f=e.get("fact") or {}
                if f.get("predicate") not in PREDICATES:
                    errors.append(f"{w}.effects.{side}[{j}]: invalid predicate")
                if side=="gen": gen_keys.add(fact_key(f))
                if n.get("operation",{}).get("crud")=="Read" and side=="gen" and f.get("predicate")!="Know":
                    errors.append(f"{w}: Read GEN may contain only Know")
                if n.get("operation",{}).get("crud")=="Read" and side=="kill":
                    errors.append(f"{w}: Read KILL must be empty")

        for j,b in enumerate(n.get("l1_bindings") or []):
            k=b.get("l1_key")
            if k not in l1_by_key:
                errors.append(f"{w}.l1_bindings[{j}]: unknown L1 key {k}")
            else:
                covered.add(k)

        for j,x in enumerate(n.get("io_accounting") or []):
            d=x.get("direction")
            disp=x.get("disposition")
            if d=="input" and disp not in {"req","object_attribute"}:
                errors.append(f"{w}.io_accounting[{j}]: invalid input disposition")
            if d=="output" and disp not in {"gen","observed_only"}:
                errors.append(f"{w}.io_accounting[{j}]: invalid output disposition")
            fs=set(x.get("facts") or [])
            if disp=="req" and not fs <= req_keys:
                errors.append(f"{w}.io_accounting[{j}]: req facts do not match requirements")
            if disp=="gen" and not fs <= gen_keys:
                errors.append(f"{w}.io_accounting[{j}]: gen facts do not match effects.gen")
            if disp in {"req","gen"} and not fs:
                errors.append(f"{w}.io_accounting[{j}]: {disp} requires facts")
            if disp in {"object_attribute","observed_only"} and not x.get("ignored_reason"):
                errors.append(f"{w}.io_accounting[{j}]: ignored_reason required")

        v=((n.get("gt") or {}).get("visibility") or {}).get("minimum")
        if v not in VIS: errors.append(f"{w}: invalid gt.visibility.minimum")

    missing=sorted(candidates-covered)
    if missing:
        errors.append("L2 coverage missing for: " + ", ".join(missing))

    if errors:
        for e in errors: print("ERROR:",e)
        sys.exit(1)
    print(f"OK: {len(nodes)} L1 nodes; {len(l2.get('nodes') or [])} L2 nodes; all {len(candidates)} candidate L1 nodes covered.")

if __name__=="__main__":
    main()
