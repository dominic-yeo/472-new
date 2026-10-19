# -*- coding: utf-8 -*-
"""Shared helpers + semantic vocabulary for the MediaCMS Pengent Web GT.

Everything that keeps the generated YAML internally consistent lives here:
 - ORIGIN / key helpers
 - the SEM resource vocabulary (raw_field -> resource, value_kind, reference_capable)
 - L1 node / io_variant / request-field / response builders that fill every
   Pengent-required field and DERIVE inputs/outputs/semantic_inputs/semantic_outputs
 - L2 typed-term + fact builders, and fact_key() -- a byte-for-byte copy of the
   validator's canonical fact key, so io_accounting strings always match Req/Eff.
"""

ORIGIN = "http://localhost"


def key(path):
    """Normalized L1 key = origin + normalized path template."""
    return ORIGIN + path


# --------------------------------------------------------------------------
# SEM: the single source of resource-type consistency.
# raw_field -> (resource, value_kind, reference_capable, mergeable)
# reference_capable only ever True for identifier/locator (validator enforces).
# --------------------------------------------------------------------------
SEM = {
    # media
    "friendly_token":      ("MediaToken(media)",        "identifier", True,  True),
    "media_token":         ("MediaToken(media)",        "identifier", True,  True),
    "media_friendly_token":("MediaToken(media)",        "identifier", True,  True),
    "media_ids":           ("MediaToken(media)",        "identifier", True,  True),
    "tokens":              ("MediaToken(media)",        "identifier", True,  True),
    "title":               ("MediaTitle(media)",        "content",    False, True),
    "description":         ("MediaDescription(media)",  "content",    False, True),
    "media_file":          ("MediaFile(media)",         "content",    False, True),
    "state":               ("MediaState(media)",        "state",      False, True),
    "media_type":          ("MediaType(media)",         "attribute",  False, True),
    "enable_comments":     ("MediaCommentsFlag(media)", "state",      False, True),
    "allow_download":      ("MediaDownloadFlag(media)", "state",      False, True),
    "is_reviewed":         ("MediaReviewed(media)",     "state",      False, True),
    "featured":            ("MediaFeatured(media)",     "state",      False, True),
    "reported_times":      ("MediaReports(media)",      "summary",    False, False),
    "views":               ("MediaViews(media)",        "summary",    False, False),
    "likes":               ("MediaLikes(media)",        "summary",    False, False),
    "dislikes":            ("MediaDislikes(media)",     "summary",    False, False),
    "chapter_data":        ("MediaChapters(media)",     "content",    False, True),
    "chapters":            ("MediaChapters(media)",     "content",    False, True),
    # categories / tags
    "category_uid":        ("CategoryUID(category)",    "identifier", True,  True),
    "category_uids":       ("CategoryUID(category)",    "identifier", True,  True),
    "uid_category":        ("CategoryUID(category)",    "identifier", True,  True),
    "category_title":      ("CategoryTitle(category)",  "attribute",  False, True),
    "tag_titles":          ("TagTitle(tag)",            "identifier", True,  True),
    "tag_title":           ("TagTitle(tag)",            "identifier", True,  True),
    "t":                   ("TagTitle(tag)",            "identifier", True,  True),
    "c":                   ("CategoryUID(category)",    "identifier", True,  True),
    # comments
    "comment_uid":         ("CommentUID(comment)",      "identifier", True,  True),
    "comment_ids":         ("CommentUID(comment)",      "identifier", True,  True),
    "text":                ("CommentText(comment)",     "content",    False, True),
    "parent":              ("CommentParent(comment)",   "identifier", True,  True),
    # playlists
    "playlist_token":      ("PlaylistToken(playlist)",  "identifier", True,  True),
    "playlist_ids":        ("PlaylistID(playlist)",     "identifier", True,  True),
    "ordering":            ("PlaylistOrdering(playlist)","attribute", False, False),
    # users
    "username":            ("Username(user)",           "identifier", True,  True),
    "users":               ("Username(user)",           "identifier", True,  True),
    "owner":               ("Username(user)",           "identifier", True,  True),
    "author":              ("Username(user)",           "identifier", True,  True),
    "user":                ("Username(user)",           "identifier", True,  True),
    "name":                ("UserName(user)",           "attribute",  False, True),
    "email":               ("UserEmail(user)",          "identifier", True,  True),
    "password":            ("Password(user)",           "credential", False, True),
    "token":               ("AuthToken(session)",       "credential", False, True),
    "logo":                ("UserLogo(user)",           "content",    False, True),
    "body":                ("ContactBody(message)",     "content",    False, False),
    "is_approved":         ("UserApproved(user)",       "state",      False, True),
    "ownership_type":      ("OwnershipType(permission)","attribute",  False, True),
    # migrations
    "pk":                  ("MigrationID(migration)",   "identifier", True,  True),
    "provider":            ("MigrationProvider(migration)","attribute",False,True),
    # actions / encode
    "extra_info":          ("ReportReason(media)",      "content",    False, False),
    "encoding_profiles":   ("EncodeProfileID(profile)", "identifier", True,  True),
    "result":             ("ReviewResult(media)",       "state",      False, False),
}


def dec_for(raw_field, override_resource=None, reason=None):
    """Build a semantic decision row from the SEM vocabulary."""
    resource, vk, refcap, mergeable = SEM[raw_field]
    if override_resource:
        resource = override_resource
    return {
        "raw_field": raw_field,
        "resource": resource,
        "mergeable": mergeable,
        "value_kind": vk,
        "reference_capable": refcap,
        "reference_fields": [raw_field] if refcap else [],
        "reason": reason or f"{raw_field} denotes {resource}.",
    }


def dec(raw_field, resource, value_kind, mergeable=True, reference_capable=False,
        reference_fields=None, reason=""):
    """Explicit semantic decision row (when SEM default is not wanted)."""
    return {
        "raw_field": raw_field,
        "resource": resource,
        "mergeable": mergeable,
        "value_kind": value_kind,
        "reference_capable": reference_capable,
        "reference_fields": reference_fields or ([raw_field] if reference_capable else []),
        "reason": reason,
    }


# --------------------------------------------------------------------------
# L1 request-field / response / io_variant builders
# --------------------------------------------------------------------------
def rf(name, location, typ="string", required=False, flow=True, description="", path=""):
    return {"name": name, "location": location, "path": path, "type": typ,
            "required": required, "flow": flow, "description": description}


def resp_json(fields):
    return {"format": "json", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "fields": fields}


def resp_empty():
    return {"format": "empty", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False, "value_description": None,
            "fields": []}


def resp_scalar(value_name, value_type, value_description, value_flow=True):
    return {"format": "scalar", "scalar_type": value_type, "value_name": value_name,
            "value_type": value_type, "value_flow": value_flow,
            "value_description": value_description, "fields": []}


def resp_raw(value_description):
    return {"format": "raw", "scalar_type": None, "value_name": None,
            "value_type": None, "value_flow": False,
            "value_description": value_description, "fields": []}


def of(name, typ="string", flow=True, description="", path=None):
    """Response field."""
    return {"name": name, "path": path if path is not None else name, "type": typ,
            "flow": flow, "description": description}


def variant(method, request_fields=None, response=None, body_format="none",
            body_example=None, reason="", evidence="", content_types=None):
    request_fields = request_fields or []
    response = response if response is not None else resp_empty()
    inputs = [f["name"] for f in request_fields if f.get("flow")]
    outputs = [f["name"] for f in (response.get("fields") or []) if f.get("flow")]
    if response.get("value_flow") and response.get("value_name"):
        outputs.append(response["value_name"])
    return {
        "method": method,
        "content_types": content_types or (["application/json"]),
        "inputs": inputs,
        "outputs": outputs,
        "input": {},
        "request": {"body_format": body_format, "body_example": body_example or {},
                    "fields": request_fields},
        "response": response,
        "reason": reason,
        "evidence": evidence,
    }


def _uniq(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def ev(type_, ref, supports):
    return {"type": type_, "ref": ref, "supports": supports}


def node(key_, kind, methods, variants=None, operation_semantic="",
         params=None, sem_in_decisions=None, sem_out_decisions=None,
         statuses=None, content_types=None, identity_statuses=None,
         sources=None, referrers=None, resource_types=None, js_sources=None,
         route_confirmed=False, visibility="black_box", vis_reason="",
         reachable=True, reach_conds=None, evidence=None, samples=None, notes=None):
    variants = variants or []
    sem_in_decisions = sem_in_decisions or []
    sem_out_decisions = sem_out_decisions or []
    inputs = _uniq([n for v in variants for n in v["inputs"]])
    outputs = _uniq([n for v in variants for n in v["outputs"]])
    body_json = any(v["request"]["body_format"] == "json" for v in variants)
    body_form = any(v["request"]["body_format"] == "form" for v in variants)
    input_spec = {"format": "json" if body_json else ("plain" if (inputs and body_form) else ("plain" if inputs else "")),
                  "fields": inputs}
    semantic_inputs = _uniq([d["resource"] for d in sem_in_decisions if d["mergeable"]])
    semantic_outputs = _uniq([d["resource"] for d in sem_out_decisions if d["mergeable"]])
    return {
        "key": key_,
        "kind": kind,
        "methods": methods,
        "statuses": statuses or [],
        "content_types": content_types or (["application/json"] if kind == "api" else ["text/html"]),
        "params": params or [],
        "inputs": inputs,
        "outputs": outputs,
        "input_spec": input_spec,
        "io_variants": variants,
        "operation_semantic": operation_semantic,
        "semantic_inputs": semantic_inputs,
        "semantic_outputs": semantic_outputs,
        "semantic_input_decisions": sem_in_decisions,
        "semantic_output_decisions": sem_out_decisions,
        "samples": samples or [],
        "sources": sources or ["source", "runtime"],
        "referrers": referrers or [],
        "resource_types": resource_types or (["fetch", "xhr"] if kind == "api" else ["document"]),
        "js_sources": js_sources or [],
        "identity_statuses": identity_statuses or {},
        "route_confirmed": route_confirmed,
        "runtime_api_prefixes": [ORIGIN + "/api/v1"] if kind == "api" else [],
        "gt": {
            "visibility": {"minimum": visibility, "reason": vis_reason},
            "black_box_reachable": reachable,
            "reachability_conditions": reach_conds or [],
            "evidence": evidence or [],
            "notes": notes,
        },
    }


# --------------------------------------------------------------------------
# L2 typed terms + facts
# --------------------------------------------------------------------------
def subj(id="actor", type="User", rel="SELF"):
    return {"kind": "subject", "id": id, "type": type, "relative_role": rel}


def principal(id, type, role, rel):
    return {"kind": "principal", "id": id, "type": type, "role": role, "relative_role": rel}


def entity(id, type, role="target"):
    return {"kind": "entity", "id": id, "type": type, "role": role}


def reference(ref_type, target_entity):
    return {"kind": "reference", "type": ref_type, "target": target_entity}


def f_auth(s=None, context="Session"):
    s = s or subj()
    args = [s]
    if context:
        args.append(context)
    return {"predicate": "Authenticated", "arguments": args}


def f_know(s, ref):
    return {"predicate": "Know", "arguments": [s, ref]}


def f_exists(ent):
    return {"predicate": "Exists", "arguments": [ent]}


def f_state(ent, field, value):
    return {"predicate": "State", "arguments": [ent, field, value]}


def f_relation(t1, t2, name):
    return {"predicate": "Relation", "arguments": [t1, t2, name]}


def f_can(s, crud, ent):
    return {"predicate": "Can", "arguments": [s, crud, ent]}


def req(rtype, fact, reason):
    return {"type": rtype, "fact": fact, "reason": reason}


def eff(fact, basis, reason):
    return {"fact": fact, "basis": basis, "reason": reason}


# fact_key: byte-for-byte identical to validate_gt.py so io_accounting matches.
def fact_key(f):
    def tk(x):
        if not isinstance(x, dict):
            return str(x)
        k = x.get("kind")
        if k == "reference":
            return f"{x.get('type')}({tk(x.get('target'))})"
        base = f"{x.get('id')}:{x.get('type')}"
        if k in {"subject", "principal"}:
            return f"{base}[{x.get('relative_role')}]"
        return f"{base}{{{x.get('role')}}}"
    return f"{f.get('predicate')}({','.join(tk(x) for x in (f.get('arguments') or []))})"


def io(direction, field, disposition, facts=None, ignored_reason=""):
    return {"direction": direction, "field": field, "disposition": disposition,
            "facts": facts or [], "ignored_reason": ignored_reason}
