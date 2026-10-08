"""Cross-action fact reconciliation linter for the VoceChat L2 GT.

Independent authoring risks producer/consumer label drift: an action that CONSUMES a fact (Req) must either
(a) have another action that PRODUCES it (Eff.gen), or (b) be a declared ROOT precondition (an external
input the attacker brings, an authorization axiom, or a known constant). This linter proves that, and FAILS
on any consumed fact that is neither matched nor an approved root.

Matching is done on a CANONICAL key that drops the per-action bookkeeping that is not meant to be globally
identical, while keeping what is semantically load-bearing:
  * top-level subject/principal  -> Type[relative_role]   (SELF vs PEER matters for *who* acts/knows)
  * a reference target (the object a Know/ref points at) -> Type only  (its downstream role/id is local)
  * a top-level entity (Exists/State/Relation/Can arg)   -> Type (+ kept field/value for State)
So Know(actor:User[SELF],RefreshToken(session:Session{created}))  ==  ...RefreshToken(session:Session{target}),
and a uid learned from the directory (UserID(user:User{target})) == a uid used as a peer (UserID(recipient:User[PEER])).
"""
import json, re, sys, collections, os

SCRATCH = os.path.dirname(os.path.abspath(__file__)) + "/"
L2 = json.load(open(SCRATCH + "l2_build.json", encoding="utf-8"))["nodes"]

def canon(k):
    # reference target: RefType(id:Type{role})  or RefType(id:Type[rr])  -> RefType(Type)
    k = re.sub(r'([A-Za-z]+)\((\w+):(\w+)(?:\{[^}]*\}|\[[^\]]*\])\)', r'\1(\2:\3)', k)  # mark, next pass strips
    # now strip nested "id:Type" inside (...) to Type, drop entity {role}, keep [rr] only at top level
    # 1) reference targets: inside (...) -> Type only
    def strip_ref(m):
        inner = m.group(1)
        inner = re.sub(r'\w+:(\w+)(?:\{[^}]*\}|\[[^\]]*\])?', r'\1', inner)
        return "(" + inner + ")"
    k = re.sub(r'\(([^()]*)\)', strip_ref, k)
    # 2) top-level entity args id:Type{role} -> Type ; principal/subject id:Type[rr] -> Type[rr]
    k = re.sub(r'\b\w+:(\w+)\{[^}]*\}', r'\1', k)
    k = re.sub(r'\b\w+:(\w+)\[([^\]]*)\]', r'\1[\2]', k)
    return k

produced = collections.defaultdict(list)
consumed = collections.defaultdict(list)
for n in L2:
    for key in n["produces"]:
        produced[canon(key)].append(n["action_key"])
    for key in n["consumes"]:
        consumed[canon(key)].append((n["action_key"], key))

# ---- ROOT preconditions that legitimately have no producing action ----------
# external inputs the attacker/user brings, authorization axioms, or server-known constants.
EXTERNAL_REF_ROOTS = {
    "ExternalIdToken", "OAuthCode", "OAuthState", "WalletSignature", "WalletNonce",
    "MagicToken", "MagicLinkURL", "ThirdPartySecret", "ThirdPartyLoginKey", "LicenseBlob",
    "CustomPageName", "AgoraChannelName", "BotSecret", "ExternalURL", "FilePath", "ArchivePath",
    "ArchiveAttachmentID", "PasskeyCredentialID", "NotificationChannelType", "PageAPIKey",
}
def is_root(ck):
    pred = ck.split("(", 1)[0]
    if pred == "Can":
        return "authorization axiom (role/ownership, not produced by an action)"
    if pred == "Authenticated" and "APIToken" in ck:
        return "bot API-key auth (admin mints the key out of band)"
    if pred == "Know":
        m = re.search(r',\s*([A-Za-z]+)\(', ck)
        if m and m.group(1) in EXTERNAL_REF_ROOTS:
            return f"external/root input: {m.group(1)} (brought by the caller or a server-known constant)"
    if ck.startswith("State(Device") or ck == "Exists(Device)":
        return "device row is created by any login (do_login inserts it); implied by Authenticated(Session)"
    return None

matched = [ck for ck in consumed if ck in produced]
unmatched = [ck for ck in consumed if ck not in produced]
roots, drift = [], []
for ck in unmatched:
    why = is_root(ck)
    (roots if why else drift).append((ck, why))

print(f"consumed canonical facts: {len(consumed)} | matched by a producer: {len(matched)} | "
      f"roots: {len(roots)} | UNRESOLVED DRIFT: {len(drift)}")
print("\n== roots (approved, no producer needed) ==")
for ck, why in sorted(roots):
    print(f"  {ck}\n      -> {why}")
if drift:
    print("\n== UNRESOLVED DRIFT (a consumer whose fact no action produces and is not an approved root) ==")
    for ck, _ in sorted(drift):
        for ak, raw in consumed[ck][:3]:
            print(f"  [{ak}] {raw}")
    sys.exit(1)
print("\nLINT OK: every consumed fact is produced by some action or is an approved root precondition.")
