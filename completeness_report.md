# GT Completeness Check (Oracle A / B)

_Addresses limitation #9 (no completeness bound) by diffing each authored L1
against the running app's own route list. Re-run 2026-11-21 after applying the
fixes it surfaced._

**Method.** Obtain the live route list from an oracle, canonicalize both sides
(strip host/query, drop Rails `(.:format)` and optional-segment parens, rewrite
every path parameter — `{id}`, `:id`, `*glob` — to `{}`), then diff:

- **validity** = `|L1 ∩ live| / |L1|` — are the authored endpoints real routes? (catches stale / mis-templated entries)
- **coverage** = `|L1 ∩ live| / |live|` — how much of the live surface is captured? (meaningful only when the GT's scope is the whole API)

**Oracles.** `A` = app's served OpenAPI; `B` = route list dumped from inside the
running container (the framework's real router — stronger than hand-maintained docs).

## Summary (post-fix)

| app | oracle | live | L1 | ∩ | validity | coverage | note |
|---|---|--:|--:|--:|--:|--:|---|
| directus | A served OpenAPI | 65 | 115 | 62 | 53.9% | **95.4%** | whole-API; OAS itself incomplete |
| anything-llm | B in-container spec | 67 | 67 | 67 | **100%** | **100%** | exact match |
| open-webui | B FastAPI router | 587 | 17 | 17 | **100%** | 2.9% | GT scoped to `auths` module |
| discourse | B `rails routes` | 1732 | 231 | 230 | **99.6%** | 13.3% | GT scoped to 16 core modules |

## Fixes applied this round (from the first run)
- **directus +5 endpoints** added and grounded (were in the served OAS, confirmed
  live): `/utils/hash/generate` (POST→200, observed), `/utils/hash/verify`
  (POST→400), `/flows/:pk`, `/operations/:pk`, `/assets/:pk` (all 403 = route
  exists). Coverage 87.7% → **95.4%**.
- **discourse 3 paths corrected**: `/admin/watched_words{,/{id},/upload}` →
  `/admin/customize/watched_words…` (the live routes live under `/admin/customize/`).
- **canonicalizer fixed** to strip Rails optional-segment parens `(/:id)`, which
  had made `/admin/email/templates/:id` a false gap. Discourse validity
  97.8% → **99.6%**.

## Per-app reading

### directus — coverage 95.4%, validity 53.9%
Captures 62 of the 65 endpoints the served OpenAPI declares. The 3 still missing
are **declared in the OAS but not active in this deployment** (return 404):
`/auth/oauth`, `/auth/oauth/{}` (no OAuth provider configured) and
`/extensions/{}/{}` (not a live route in this build). Honestly left out rather
than recorded as grounded. Validity looks low (62/115) only because directus's
**own OAS is incomplete** — the GT has 53 real paths the OAS never lists
(`/access`, `/dashboards`, `/comments`, `/shares`, `/policies`, …), all confirmed
live. The GT is *more* complete than the vendor's documented API.

### anything-llm — 100% / 100%
The authored L1 exactly mirrors the app's generated OpenAPI (67/67). Built from
the Developer API spec; confirmed with zero drift.

### open-webui — validity 100%, module coverage 53%
All 17 authored paths are real live routes. The GT was deliberately scoped to the
`/api/v1/auths` module, so whole-app coverage (17/587) is not the right metric.
Within that module the live app has **32 routes vs 17 in the GT (53%)**; the 15
missing are newer MFA/session features (`auths/mfa/*`, `auths/sessions/*`) — part
version drift (container is v0.13.4), part genuine under-enumeration. Left as a
documented scope decision.

### discourse — validity 99.6%, scoped coverage 13%
Discourse's full router has 1732 routes; the GT intentionally scopes to 16 core
modules (231 paths), so 13% whole-API coverage is by design. **Validity is
230/231 (99.6%)**. The single remaining unmatched path, `/uploads/{}/{}`, is the
upload-serving route handled by a Rack/CDN layer rather than the Rails router, so
it does not appear in `rails routes` — not a GT error.

## Caveats (what this does and doesn't prove)
1. **The oracle is a reference, not absolute truth.** A served OpenAPI can be
   incomplete (directus) and can declare config-gated routes that aren't live; a
   router dump is authoritative for *that build* but misses Rack/CDN-served paths
   (discourse uploads). This bounds completeness; it does not prove exhaustiveness.
2. **Scope vs gap.** The check cannot tell a deliberate scoping decision
   (open-webui = auths, discourse = 16 modules) from an accidental omission — a
   human triages that. Validity is scope-independent and the more robust signal.
3. **Version drift.** Live containers may be newer than when the GT was authored
   (open-webui MFA/sessions), so a "missing" route can be a new feature.
4. **Applicability.** Oracle B needs a reachable in-container router; it covers
   directus (A), anything-llm, open-webui, discourse here. Apps with no running
   container (mediacms) or no introspectable router (ghost, vocechat, rocketchat,
   writefreely) would need source-route parsing (weaker, Oracle C).
