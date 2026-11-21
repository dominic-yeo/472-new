# GT Completeness Check (Oracle A/B)
_Generated 2026-11-22_

`validity` = share of checkable authored L1 paths that are real live routes (are the entries real?).  
`coverage` = share of the live surface the GT captures (how much is inventoried?).  
Oracle A = the app's own served OpenAPI; Oracle B = an in-container router/route dump.  
Surface a static oracle structurally cannot see (dynamic/packaged routers, static assets) is held out of the validity denominator and listed per app.

## Summary

| app | oracle | live routes | authored L1 | validity | coverage |
|---|:--:|--:|--:|--:|--:|
| directus | A | 65 | 115 | 92.5% | 95.4% |
| anything-llm | B | 67 | 67 | 100.0% | 100.0% |
| open-webui | B | 587 | 17 | 100.0% | 2.9% ⃰ |
| discourse | B | 1732 | 231 | 99.6% | 13.3% ⃰ |
| vocechat | A | 159 | 189 | 98.7% | 98.7% |
| outline | B | 213 | 206 | 100.0% | 93.9% |
| ghost | B | 203 | 112 | 100.0% | 43.8% ⃰ |

⃰ GT is deliberately scoped (not whole-API), so low coverage is by design, not a gap — except where noted per app.

## directus  (A served OpenAPI)
- live routes (canonical paths): **65**
- authored L1 paths: **115**  (48 out of this oracle's scope)
- intersection: **62**
- **validity** (checkable L1 that are real live routes): **92.5%**  (5 of 67 checkable not matched)
- **coverage** (live surface captured): **95.4%**
- out-of-oracle-scope (48): real Directus endpoints absent from Directus's OWN served OAS (verified live: /graphql POST 200, /dashboards 200, /access 200, /items/* 403=exists, /flows/trigger 403; plus the documented notifications/panels/policies/shares/translations/users/server resource families) — the OAS enumerates only ~65 of the ~115 real paths
- missing from GT (3): /auth/oauth, /auth/oauth/{}, /extensions/{}/{}
- checked-but-unmatched (5): /metrics, /utils/import, /utils/resolve-redirect, /utils/revert/{}, /utils/translations/generate

## anything-llm  (B in-container spec)
- live routes (canonical paths): **67**
- authored L1 paths: **67**
- intersection: **67**
- **validity** (checkable L1 that are real live routes): **100.0%**  (0 of 67 checkable not matched)
- **coverage** (live surface captured): **100.0%**

- missing from GT (0): none
- checked-but-unmatched (0): none

## open-webui  (B FastAPI router)
- live routes (canonical paths): **587**
- authored L1 paths: **17**
- intersection: **17**
- **validity** (checkable L1 that are real live routes): **100.0%**  (0 of 17 checkable not matched)
- **coverage** (live surface captured): **2.9%**  _(GT is scoped, not whole-API — coverage is expected low)_

- missing from GT (570): /api/changelog, /api/chat/actions/{}, /api/chat/completed, /api/chat/completions, /api/config, /api/embeddings, /api/events, /api/events/webhooks, /api/events/webhooks/{}, /api/message, /api/message/count_tokens, /api/models, /api/models/base, /api/models/unload, /api/tasks, /api/tasks/chat/{}, /api/tasks/chat/{}/resume, /api/tasks/chat/{}/stop, /api/tasks/stop/{}, /api/usage, /api/v1/analytics/daily, /api/v1/analytics/messages, /api/v1/analytics/models, /api/v1/analytics/models/{}/chats, /api/v1/analytics/models/{}/overview …
- checked-but-unmatched (0): none

## discourse  (B rails routes)
- live routes (canonical paths): **1732**
- authored L1 paths: **231**
- intersection: **230**
- **validity** (checkable L1 that are real live routes): **99.6%**  (1 of 231 checkable not matched)
- **coverage** (live surface captured): **13.3%**  _(GT is scoped, not whole-API — coverage is expected low)_

- missing from GT (1502): /, /.json, /.well-known/apple-app-site-association, /.well-known/assetlinks.json, /.well-known/change-password, /.well-known/discourse-id-challenge, /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp, /.well-known/openid-configuration, /404, /404-body, /about/live_post_counts, /accept, /accepted, /access-control/evaluate, /access-control/grantees/search, /ad_plugin/ad_impressions, /ad_plugin/ad_impressions/{}, /admin, /admin/admin_notices/{}, /admin/api, /admin/api/keys/scopes, /admin/api/keys/{}/revoke, /admin/api/keys/{}/undo-revoke, /admin/api/web_hook_events/{} …
- checked-but-unmatched (1): /uploads/{}/{}

## vocechat  (A served OpenAPI (/api/spec))
- live routes (canonical paths): **159**
- authored L1 paths: **189**  (30 out of this oracle's scope)
- intersection: **157**
- **validity** (checkable L1 that are real live routes): **98.7%**  (2 of 159 checkable not matched)
- **coverage** (live surface captured): **98.7%**
- out-of-oracle-scope (30): static assets, ops (/health,/metrics), SPA pages and self-referential swagger — real surface the OAS does not list
- missing from GT (2): /api/page/after_signin, /api/page/landing
- checked-but-unmatched (2): /api/group/{}/agora_token, /api/page/{}

## outline  (B in-container route dump)
- live routes (canonical paths): **213**
- authored L1 paths: **206**  (6 out of this oracle's scope)
- intersection: **200**
- **validity** (checkable L1 that are real live routes): **100.0%**  (0 of 200 checkable not matched)
- **coverage** (live surface captured): **93.9%**
- out-of-oracle-scope (6): dynamic passport-provider auth routes, share-link render routes and internal cron — real routes not statically reconstructed
- missing from GT (13): /doc/{}, /embeds/dropbox, /embeds/github, /embeds/gitlab, /embeds/pinterest, /locales/{}.json, /s/{}, /s/{}.{}, /s/{}/doc/{}, /s/{}/doc/{}.{}, /s/{}/{}, /sitemap.xml, /static/{}
- checked-but-unmatched (0): none

## ghost  (B in-container route dump)
- live routes (canonical paths): **203**
- authored L1 paths: **112**  (23 out of this oracle's scope)
- intersection: **89**
- **validity** (checkable L1 that are real live routes): **100.0%**  (0 of 89 checkable not matched)
- **coverage** (live surface captured): **43.8%**  _(GT is scoped, not whole-API — coverage is expected low)_
- out-of-oracle-scope (23): Members API served by the dynamic @tryghost/members-api package, plus front-end routes — not in the static admin/content route oracle
- missing from GT (114): /ghost/api/admin/apps, /ghost/api/admin/apps/*, /ghost/api/admin/authentication/reset, /ghost/api/admin/automated_emails, /ghost/api/admin/automated_emails/design, /ghost/api/admin/automated_emails/senders, /ghost/api/admin/automated_emails/verifications, /ghost/api/admin/automated_emails/{}, /ghost/api/admin/automated_emails/{}/preview, /ghost/api/admin/automated_emails/{}/test, /ghost/api/admin/automations, /ghost/api/admin/automations/poll, /ghost/api/admin/automations/{}, /ghost/api/admin/automations/{}/actions/{}/links, /ghost/api/admin/automations/{}/email_preview, /ghost/api/admin/automations/{}/email_test, /ghost/api/admin/automations/{}/performance-stats, /ghost/api/admin/automations/{}/runs, /ghost/api/admin/automations/{}/runs/{}, /ghost/api/admin/comments/post/{}, /ghost/api/admin/comments/{}/dislikes, /ghost/api/admin/comments/{}/likes, /ghost/api/admin/comments/{}/replies, /ghost/api/admin/comments/{}/reports, /ghost/api/admin/emails …
- checked-but-unmatched (0): none
