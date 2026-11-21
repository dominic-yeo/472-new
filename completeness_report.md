# GT Completeness Check (Oracle A / B)

_Generated 2026-11-21. Addresses limitation #9 (no completeness bound) by diffing
each authored L1 against the running app's own route list._

**Method.** Obtain the live route list from an oracle, canonicalize both sides
(strip host/query, drop Rails `(.:format)`, rewrite every path parameter —
`{id}`, `:id`, `*glob` — to `{}`), then diff:

- **validity** = `|L1 ∩ live| / |L1|` — are the authored endpoints real routes? (catches stale / mis-templated / hallucinated entries)
- **coverage** = `|L1 ∩ live| / |live|` — how much of the live surface is captured? (meaningful only when the GT's scope is the whole API)

**Oracles.** `A` = app's served OpenAPI; `B` = route list dumped from inside the
running container (the framework's real router — a stronger oracle than
hand-maintained docs).

## Summary

| app | oracle | live routes | L1 paths | ∩ | validity | coverage | note |
|---|---|--:|--:|--:|--:|--:|---|
| directus | A served OpenAPI | 65 | 110 | 57 | 51.8% | **87.7%** | whole-API; OAS itself incomplete |
| anything-llm | B in-container spec | 67 | 67 | 67 | **100%** | **100%** | exact match |
| open-webui | B FastAPI router | 587 | 17 | 17 | **100%** | 2.9% | GT scoped to `auths` module |
| discourse | B `rails routes` | 1733 | 231 | 226 | **97.8%** | 13.0% | GT scoped to 16 core modules |

## Per-app reading

### directus — coverage 87.7%, validity 51.8%
Of the 65 endpoints the served OpenAPI declares, the GT captures 57 (**87.7%**).
Validity looks low (57/110) only because directus's **own OAS is incomplete** —
the GT has 53 real paths the OAS never lists (`/access`, `/dashboards`,
`/comments`, `/shares`, `/policies`, `/panels`, …), all confirmed live during
effect-driving. So here the GT is *more* complete than the vendor's documented
API. 8 endpoints the OAS declares but the GT omits (genuine candidates to add):
`/auth/oauth`, `/auth/oauth/{}`, `/flows/{}`, `/operations/{}`,
`/extensions/{}/{}`, `/utils/hash/generate`, `/utils/hash/verify`, `/assets/{}`.

### anything-llm — 100% / 100%
The authored L1 exactly mirrors the app's generated OpenAPI (67/67). The GT was
built from the Developer API spec, and this confirms it with zero drift: every
authored endpoint is real and every documented endpoint is captured.

### open-webui — validity 100%, module coverage 53%
All 17 authored paths are real live routes. The GT was deliberately scoped to the
`/api/v1/auths` module, so whole-app coverage (17/587) is not the right metric.
Within that module the live app has **32 routes vs 17 in the GT (53%)**. The 15
missing are all newer MFA/session features:
`auths/mfa/{challenge,enroll/start,enroll/confirm,verify,status,recover,recovery/codes,replace}`
and `auths/sessions{,/refresh,/exchange,/requests,/{id},/{id}/authorize,/{id}/request}`.
These are partly **version drift** (the container is v0.13.4; MFA/sessions are
recent) and partly genuine under-enumeration — worth adding if the module is
meant to be exhaustive.

### discourse — validity 97.8%, scoped coverage 13%
Discourse's full router has **1733 routes**; the GT intentionally scopes to 16
core modules (231 paths), so 13% whole-API coverage is by design. The useful
number is **validity: 226/231 (97.8%)** of authored paths resolve to a real live
route. The **5 that don't** are mis-templated / moved and should be fixed:
`/admin/watched_words`, `/admin/watched_words/{}`, `/admin/watched_words/upload`
(live under `/admin/customize/watched_words…`), `/admin/email/templates/{}`
(live under `/admin/customize/email_templates/{}`), and `/uploads/{}/{}` (param
shape differs).

## Caveats (what this does and doesn't prove)
1. **The oracle is a reference, not absolute truth.** A served OpenAPI can be
   incomplete (directus); a router dump is authoritative for *that build*. This
   bounds completeness against the app's real surface; it does not prove the GT
   enumerates every conceivable route.
2. **Scope vs gap.** The check cannot tell a deliberate scoping decision
   (open-webui = auths, discourse = 16 modules) from an accidental omission — a
   human triages that. Validity is scope-independent and the more robust signal.
3. **Version drift.** Live containers may be newer than when the GT was authored
   (open-webui MFA/sessions), so a "missing" route can be a new feature rather
   than an oversight.
4. **Applicability.** Oracle B needs a reachable in-container router; it covers
   directus (A), anything-llm, open-webui, discourse here. Apps with no running
   container (mediacms) or no introspectable router (ghost, vocechat, rocketchat,
   writefreely) would need source-route parsing (weaker, Oracle C).
