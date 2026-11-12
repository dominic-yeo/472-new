# -*- coding: utf-8 -*-
"""WriteFreely L1 attack surface as data.

Authoritative source: writefreely/routes.go (route table) + writefreely/handle.go
(wrapper -> required identity). ORIGIN assumes a multi-user deployment at
http://localhost. Statuses / identity_statuses are intentionally left for runtime
confirmation (see ../annotation_issues.yaml and the runtime-artifact list).

API_NODES with non-empty io_variants are the L2 coverage candidates.
Everything else (web pages, federation, oauth, admin HTML, static) is enumerated so
the surface is complete; their full IO contracts are deferred pending runtime capture.
"""
import common as c
from common import key as K, rf, of, variant, resp_json, resp_scalar, resp_empty, dec

SRC = "writefreely/routes.go"


def ev_src(ref, supports):
    return c.ev("source", ref, supports)


# ===========================================================================
# API CANDIDATES (JSON contracts -> require L2 coverage)
# ===========================================================================
API_NODES = []


def api(key, methods, variants, op, sin=None, sout=None, params=None,
        vis="black_box", vis_reason="", reach=None, evref="", notes=None):
    API_NODES.append(c.node(
        K(key), "api", methods, variants=variants, operation_semantic=op,
        sem_in_decisions=sin or [], sem_out_decisions=sout or [], params=params or [],
        visibility=vis, vis_reason=vis_reason, reachable=True, reach_conds=reach or [],
        evidence=[ev_src(SRC + ":" + evref, "route + handler wrapper")] if evref else [],
        notes=notes))


# ---- auth ----
api("/api/auth/signup", ["POST"],
    [variant("POST",
             [rf("alias", "body", required=True, description="desired username"),
              rf("pass", "body", required=True, description="password"),
              rf("email", "body", required=False, description="optional email")],
             resp_json([of("access_token", description="API token for the new user"),
                        of("username", description="created username")]),
             body_format="json", reason="apiSignup creates a user and returns a token",
             evidence="account.go:89 apiSignup")],
    "signup_user",
    sin=[dec("alias", "Username(user)", "identifier", reference_capable=True,
             reason="Chosen username/handle."),
         dec("pass", "Password(user)", "credential", reason="New account password."),
         dec("email", "UserEmail(user)", "identifier", reference_capable=True,
             reason="Optional account email.")],
    sout=[dec("access_token", "AuthToken(session)", "credential",
              reason="Bearer token minted for the new account."),
          dec("username", "Username(user)", "identifier", reference_capable=True,
              reason="Created account username.")],
    vis_reason="Public signup endpoint.", reach=["Open registration enabled."],
    evref="88")

api("/api/auth/login", ["POST"],
    [variant("POST",
             [rf("alias", "body", required=True, description="username or email"),
              rf("pass", "body", required=True, description="password")],
             resp_json([of("access_token", description="API token"),
                        of("username", description="authenticated username")]),
             body_format="json", reason="login authenticates and returns a token",
             evidence="account.go:405 login")],
    "login_user",
    sin=[dec("alias", "Username(user)", "identifier", reference_capable=True,
             reason="Login identifier."),
         dec("pass", "Password(user)", "credential", reason="Account password.")],
    sout=[dec("access_token", "AuthToken(session)", "credential",
              reason="Bearer token for the session."),
          dec("username", "Username(user)", "identifier", reference_capable=True,
              reason="Authenticated username.")],
    vis_reason="Public login endpoint.", reach=["Valid credentials."], evref="89")

api("/api/auth/me", ["DELETE"],
    [variant("DELETE", [], resp_empty(), reason="invalidate the caller's access token",
             evidence="account.go:299 handleAPILogout")],
    "logout_user",
    vis_reason="Token invalidation.", reach=["Authenticated via Authorization header."],
    evref="91")

# ---- me ----
api("/api/me", ["GET"],
    [variant("GET", [], resp_json([of("username"), of("email", flow=False),
                                   of("created", flow=False)]),
             reason="viewMeAPI returns the authenticated user",
             evidence="account.go:702 viewMeAPI")],
    "read_me",
    sout=[dec("username", "Username(user)", "identifier", reference_capable=True,
              reason="Caller's own username.")],
    vis_reason="Authenticated self lookup.", reach=["Authenticated."], evref="114")

api("/api/me/posts", ["GET"],
    [variant("GET", [], resp_json([of("id", description="post id"),
                                   of("slug", flow=False), of("body", flow=False)]),
             reason="viewMyPostsAPI lists the caller's posts",
             evidence="account.go viewMyPostsAPI")],
    "list_my_posts",
    sout=[dec("id", "PostID(post)", "identifier", reference_capable=True,
              reason="Ids of the caller's own posts.")],
    vis_reason="Authenticated post list.", reach=["Authenticated (cookie or token)."],
    evref="117")

api("/api/me/collections", ["GET"],
    [variant("GET", [], resp_json([of("alias", description="collection alias"),
                                   of("title", flow=False)]),
             reason="viewMyCollectionsAPI lists the caller's blogs",
             evidence="collections.go viewMyCollectionsAPI")],
    "list_my_collections",
    sout=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
              reason="Aliases of the caller's own collections.")],
    vis_reason="Authenticated collection list.", reach=["Authenticated (token)."],
    evref="118")

api("/api/me/password", ["POST"],
    [variant("POST",
             [rf("current", "body", required=True, description="current password (FORM field 'current')"),
              rf("new", "body", required=True, description="new password (FORM field 'new')")],
             resp_empty(), body_format="form",
             reason="updatePassphrase changes the caller's password (reads r.FormValue current/new)",
             evidence="account.go:1011 updatePassphrase r.FormValue")],
    "change_password",
    sin=[dec("current", "Password(user)", "credential",
             reason="Current password proves control of the account."),
         dec("new", "NewPassword(user)", "credential", mergeable=False,
             reason="Replacement password (new content, not a reference).")],
    vis_reason="Password change.", reach=["Authenticated."], evref="119")

api("/api/alias", ["POST"],
    [variant("POST", [rf("alias", "body", required=True, description="candidate username")],
             resp_json([of("available", "bool")]), body_format="json",
             reason="handleUsernameCheck reports availability",
             evidence="routes.go:126 handleUsernameCheck")],
    "check_alias",
    sin=[dec("alias", "Username(user)", "identifier", reference_capable=True,
             reason="Candidate username being probed.")],
    vis_reason="Username availability (enumeration surface).",
    reach=["Open."], evref="126",
    notes="AllowAny-style enumeration oracle; confirm anon reachability at runtime.")

api("/api/markdown", ["POST"],
    [variant("POST", [rf("raw_body", "body", required=True, description="markdown source")],
             resp_json([of("body", description="rendered HTML")]), body_format="json",
             reason="handleRenderMarkdown renders markdown to HTML",
             evidence="routes.go:128 handleRenderMarkdown")],
    "render_markdown",
    sin=[dec("raw_body", "MarkdownSource(doc)", "content", mergeable=False,
             reason="Transient markdown input, not a stored object.")],
    vis_reason="Stateless markdown preview.", reach=["Open."], evref="128")

# ---- collections ----
api("/api/collections", ["POST"],
    [variant("POST",
             [rf("alias", "body", required=True, description="collection alias"),
              rf("title", "body", required=False, description="collection title")],
             resp_json([of("alias"), of("title", flow=False)]), body_format="json",
             reason="newCollection creates a blog owned by the caller",
             evidence="collections.go:446 newCollection")],
    "create_collection",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Chosen blog alias."),
         dec("title", "CollectionTitle(collection)", "content", mergeable=False,
             reason="New blog title (content attribute).")],
    sout=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
              reason="Alias of the created collection.")],
    vis_reason="Blog creation.", reach=["Authenticated; under max-blogs quota."],
    evref="134")

api("/api/collections/{alias}", ["GET", "POST", "DELETE"],
    [variant("GET", [rf("alias", "path", required=True, description="collection alias")],
             resp_json([of("alias"), of("title", flow=False),
                        of("description", flow=False)]),
             reason="fetchCollection returns public blog metadata",
             evidence="collections.go:554 fetchCollection"),
     variant("POST",
             [rf("alias", "path", required=True, description="collection alias"),
              rf("title", "body", required=False, description="new title"),
              rf("description", "body", required=False, description="new description")],
             resp_json([of("alias")]), body_format="json",
             reason="existingCollection updates the blog",
             evidence="collections.go:1264 existingCollection"),
     variant("DELETE", [rf("alias", "path", required=True, description="collection alias")],
             resp_empty(), reason="existingCollection deletes the blog",
             evidence="collections.go:1264 existingCollection")],
    "collection_crud",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Target blog alias."),
         dec("title", "CollectionTitle(collection)", "content", mergeable=False,
             reason="Updated title (content)."),
         dec("description", "CollectionDescription(collection)", "content", mergeable=False,
             reason="Updated description (content).")],
    sout=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
              reason="Blog alias.")],
    vis_reason="Blog read is public; write requires ownership.",
    reach=["GET public (unless instance Private); POST/DELETE owner only."], evref="138-139")

api("/api/collections/{alias}/posts", ["GET", "POST"],
    [variant("GET", [rf("alias", "path", required=True, description="collection alias")],
             resp_json([of("id"), of("slug"), of("body", flow=False)]),
             reason="fetchCollectionPosts lists a blog's posts",
             evidence="collections.go:604 fetchCollectionPosts"),
     variant("POST",
             [rf("alias", "path", required=True, description="collection alias"),
              rf("body", "body", required=True, description="post markdown body"),
              rf("title", "body", required=False, description="post title")],
             resp_json([of("id"), of("slug")]), body_format="json",
             reason="newPost creates a post in the collection",
             evidence="posts.go:565 newPost")],
    "collection_posts",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Target blog alias."),
         dec("body", "PostBody(post)", "content", mergeable=False,
             reason="New post content."),
         dec("title", "PostTitle(post)", "content", mergeable=False,
             reason="New post title.")],
    sout=[dec("id", "PostID(post)", "identifier", reference_capable=True,
              reason="Created / listed post ids."),
          dec("slug", "PostSlug(post)", "identifier", reference_capable=True,
              reason="Post slug within the collection.")],
    vis_reason="Public post list; create requires ownership.",
    reach=["GET public; POST owner."], evref="140-141")

api("/api/collections/{alias}/posts/{post}", ["GET", "POST"],
    [variant("GET",
             [rf("alias", "path", required=True), rf("post", "path", required=True)],
             resp_json([of("id"), of("slug"), of("body", flow=False)]),
             reason="fetchPost returns one collection post",
             evidence="posts.go:1142 fetchPost"),
     variant("POST",
             [rf("alias", "path", required=True), rf("post", "path", required=True),
              rf("body", "body", required=False, description="updated body")],
             resp_json([of("id")]), body_format="json",
             reason="existingPost updates the post",
             evidence="posts.go:713 existingPost")],
    "collection_post_crud",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Owning blog alias."),
         dec("post", "PostID(post)", "identifier", reference_capable=True,
             reason="Target post id."),
         dec("body", "PostBody(post)", "content", mergeable=False,
             reason="Updated post content.")],
    sout=[dec("id", "PostID(post)", "identifier", reference_capable=True,
              reason="Post id.")],
    vis_reason="Public read; update owner-only.",
    reach=["GET public; POST owner."], evref="142-143")

api("/api/collections/{alias}/collect", ["POST"],
    [variant("POST",
             [rf("alias", "path", required=True, description="destination collection"),
              rf("id", "body", required=True, description="post id to move"),
              rf("token", "body", required=False, description="post edit token")],
             resp_empty(), body_format="json",
             reason="addPost moves posts into the collection",
             evidence="posts.go:963 addPost")],
    "collect_posts",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Destination blog."),
         dec("id", "PostID(post)", "identifier", reference_capable=True,
             reason="Post being collected."),
         dec("token", "PostEditToken(post)", "credential",
             reason="Edit token authorizing the move of an anonymous post.")],
    vis_reason="Claim/move posts into a blog.", reach=["Authenticated owner."], evref="146")

api("/api/collections/{alias}/pin", ["POST"],
    [variant("POST",
             [rf("alias", "path", required=True), rf("id", "body", required=True, description="post id")],
             resp_empty(), body_format="json",
             reason="pinPost pins a post to the blog nav",
             evidence="posts.go:1072 pinPost")],
    "pin_post",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Blog whose nav is changed."),
         dec("id", "PostID(post)", "identifier", reference_capable=True,
             reason="Post to pin.")],
    vis_reason="Pin a post.", reach=["Blog owner."], evref="147")

api("/api/collections/{alias}/unpin", ["POST"],
    [variant("POST",
             [rf("alias", "path", required=True), rf("id", "body", required=True, description="post id")],
             resp_empty(), body_format="json",
             reason="pinPost (unpin) removes a pinned post",
             evidence="posts.go:1072 pinPost")],
    "unpin_post",
    sin=[dec("alias", "CollectionAlias(collection)", "identifier", reference_capable=True,
             reason="Blog whose nav is changed."),
         dec("id", "PostID(post)", "identifier", reference_capable=True,
             reason="Post to unpin.")],
    vis_reason="Unpin a post.", reach=["Blog owner."], evref="148")

# ---- posts (draft / anonymous) ----
api("/api/posts", ["POST"],
    [variant("POST",
             [rf("body", "body", required=True, description="post markdown body"),
              rf("title", "body", required=False, description="post title")],
             resp_json([of("id"), of("token", description="edit token")]),
             body_format="json",
             reason="newPost creates an anonymous/draft post",
             evidence="posts.go:565 newPost")],
    "create_draft_post",
    sin=[dec("body", "PostBody(post)", "content", mergeable=False,
             reason="Post content."),
         dec("title", "PostTitle(post)", "content", mergeable=False,
             reason="Post title.")],
    sout=[dec("id", "PostID(post)", "identifier", reference_capable=True,
              reason="Created post id."),
          dec("token", "PostEditToken(post)", "credential",
              reason="Edit token returned to the anonymous author.")],
    vis_reason="Anonymous posting surface.",
    reach=["Open (anonymous posting enabled by default)."], evref="159",
    notes="Anonymous posts return an edit token that later authorizes edit/delete/claim.")

api("/api/posts/claim", ["POST"],
    [variant("POST",
             [rf("id", "body", required=True, description="anonymous post id"),
              rf("token", "body", required=True, description="post edit token")],
             resp_empty(), body_format="json",
             reason="addPost claims anonymous posts to the caller",
             evidence="posts.go:963 addPost")],
    "claim_posts",
    sin=[dec("id", "PostID(post)", "identifier", reference_capable=True,
             reason="Post to claim."),
         dec("token", "PostEditToken(post)", "credential",
             reason="Edit token proving control of the anonymous post.")],
    vis_reason="Associate anonymous posts with an account.",
    reach=["Authenticated; holds the post edit token."], evref="161")

api("/api/posts/disperse", ["POST"],
    [variant("POST", [rf("id", "body", required=True, description="post id to unclaim")],
             resp_empty(), body_format="json",
             reason="dispersePost removes posts from the caller's account",
             evidence="posts.go:1028 dispersePost")],
    "disperse_posts",
    sin=[dec("id", "PostID(post)", "identifier", reference_capable=True,
             reason="Owned post to disperse.")],
    vis_reason="Unclaim posts.", reach=["Authenticated owner."], evref="162")

api("/api/posts/{post}", ["GET", "POST", "PUT", "DELETE"],
    [variant("GET", [rf("post", "path", required=True)],
             resp_json([of("id"), of("body", flow=False)]),
             reason="fetchPost returns a single post",
             evidence="posts.go:1142 fetchPost"),
     variant("POST",
             [rf("post", "path", required=True),
              rf("body", "body", required=False, description="updated body"),
              rf("token", "body", required=False, description="edit token (anon)")],
             resp_json([of("id")]), body_format="json",
             reason="existingPost updates the post",
             evidence="posts.go:713 existingPost"),
     variant("DELETE",
             [rf("post", "path", required=True),
              rf("token", "query", required=False, description="edit token (anon)")],
             resp_empty(), reason="deletePost deletes the post",
             evidence="posts.go:846 deletePost")],
    "post_crud",
    sin=[dec("post", "PostID(post)", "identifier", reference_capable=True,
             reason="Target post id."),
         dec("body", "PostBody(post)", "content", mergeable=False,
             reason="Updated content."),
         dec("token", "PostEditToken(post)", "credential",
             reason="Edit token authorizing anonymous edit/delete.")],
    sout=[dec("id", "PostID(post)", "identifier", reference_capable=True,
              reason="Post id.")],
    vis_reason="Public read; write via ownership or edit token.",
    reach=["GET public; POST/PUT/DELETE owner or edit-token holder."], evref="163-165")

api("/api/posts/{post}/{property}", ["GET"],
    [variant("GET",
             [rf("post", "path", required=True), rf("property", "path", required=True,
              description="e.g. body, title")],
             resp_scalar("value", "string", "the requested post property"),
             reason="fetchPostProperty returns one post field",
             evidence="posts.go:1201 fetchPostProperty")],
    "read_post_property",
    sin=[dec("post", "PostID(post)", "identifier", reference_capable=True,
             reason="Target post id.")],
    vis_reason="Public single-property read.", reach=["Public."], evref="166")


# ===========================================================================
# PAGE / FEDERATION / OAUTH / ADMIN / STATIC (enumerated; IO deferred to runtime)
# ===========================================================================
PAGE_NODES = []


def page(key, methods, op="", kind="page", vis="black_box", vis_reason="",
         reach=None, evref="", notes=None):
    PAGE_NODES.append(c.node(
        K(key), kind, methods, variants=[], operation_semantic=op, params=[],
        visibility=vis, vis_reason=vis_reason, reachable=True, reach_conds=reach or [],
        evidence=[ev_src(SRC + ":" + evref, "route + handler wrapper")] if evref else [],
        notes=notes))


# auth / session web pages
page("/login", ["GET"], "view_login", evref="187")
page("/signup", ["GET"], "view_landing", evref="188")
page("/auth/login", ["POST"], "web_login", evref="169")
page("/auth/signup", ["POST"], "web_signup", evref="168")
page("/reset", ["GET", "POST"], "reset_password", evref="186")
page("/invite/{code}", ["GET"], "view_invite", evref="189")
page("/api/auth/read", ["POST"], "unlock_private_collection", evref="90",
     notes="Blog password unlock; form POST via WebErrors handler.")

# logged-in user web area (session cookie required)
page("/me/", ["GET"], "me_redirect", evref="95")
page("/me/c/", ["GET"], "view_collections", evref="97")
page("/me/c/{collection}", ["GET"], "edit_collection", evref="98")
page("/me/c/{collection}/stats", ["GET"], "view_collection_stats", evref="99")
page("/me/c/{collection}/subscribers", ["GET"], "view_subscribers", evref="100")
page("/me/delete", ["POST"], "delete_account", evref="101",
     notes="CSRF-protected account self-deletion.")
page("/me/posts/", ["GET"], "view_articles", evref="103")
page("/me/posts/export.csv", ["GET"], "export_posts_csv", kind="api", evref="104")
page("/me/posts/export.zip", ["GET"], "export_posts_zip", kind="api", evref="105")
page("/me/posts/export.json", ["GET"], "export_posts_json", kind="api", evref="106")
page("/me/export", ["GET"], "view_export_options", evref="107")
page("/me/export.json", ["GET"], "export_full_json", kind="api", evref="108")
page("/me/import", ["GET"], "view_import", evref="109")
page("/me/settings", ["GET"], "view_settings", evref="110")
page("/me/invites", ["GET"], "view_invites", evref="111")
page("/me/logout", ["GET"], "web_logout", evref="112")
page("/me/new", ["GET"], "view_pad_singleuser", evref="197")
page("/new", ["GET"], "view_pad", evref="199")

# me API form actions (cookie/CSRF; JSON contract deferred)
page("/api/me/self", ["POST"], "update_settings", kind="api", evref="120",
     notes="updateSettings; CSRF-exempt for JSON (csrfProtectForm).")
page("/api/me/invites", ["POST"], "create_invite", kind="api", evref="121")
page("/api/me/import", ["POST"], "import_posts", kind="api", evref="122",
     notes="Multipart upload import; contract deferred to runtime.")
page("/api/me/oauth/remove", ["POST"], "remove_oauth", kind="api", evref="123")

# collection read web surface
page("/{prefix}{collection}", ["GET"], "view_collection", evref="209")
page("/{collection}/", ["GET"], "view_collection", evref="210")
page("/{collection}/{slug}", ["GET"], "view_collection_post", evref="248")
page("/{collection}/{slug}/edit", ["GET"], "edit_post", evref="249")
page("/{collection}/feed/", ["GET"], "collection_feed", kind="api", evref="245")
page("/{collection}/tag:{tag}", ["GET"], "view_collection_tag", evref="241")
page("/{collection}/page/{page}", ["GET"], "view_collection_page", evref="236")
page("/{collection}/lang:{lang}", ["GET"], "view_collection_lang", evref="239")
page("/{collection}/sitemap.xml", ["GET"], "collection_sitemap", kind="api", evref="244")
page("/{collection}/logout", ["GET"], "collection_logout", evref="235")
page("/{post}", ["GET"], "view_post", evref="214")

# email subscription (collection newsletters)
page("/api/collections/{alias}/email/subscribe", ["POST", "DELETE"], "email_subscribe",
     kind="api", evref="150-151")
page("/api/collections/{alias}/email/subscribers/export.csv", ["GET"], "export_subscribers",
     kind="api", evref="149")
page("/{collection}/email/confirm/{subscriber}", ["GET"], "confirm_subscription", evref="246")
page("/{collection}/email/unsubscribe/{subscriber}", ["GET"], "unsubscribe", evref="247")

# federation / ActivityPub / discovery
page("/.well-known/webfinger", ["GET"], "webfinger", kind="api", evref="69")
page("/.well-known/host-meta", ["GET"], "host_meta", kind="api", evref="67")
page("/.well-known/nodeinfo", ["GET"], "nodeinfo_discover", kind="api", evref="73")
page("/api/nodeinfo", ["GET"], "nodeinfo", kind="api", evref="74")
page("/@/{handle}", ["GET"], "view_mention", evref="77")
page("/api/collections/{alias}/inbox", ["POST"], "ap_inbox", kind="api", evref="153",
     notes="ActivityPub inbox; HTTP-signature verified. Federation attack surface.")
page("/api/collections/{alias}/outbox", ["GET"], "ap_outbox", kind="api", evref="154")
page("/api/collections/{alias}/following", ["GET"], "ap_following", kind="api", evref="155")
page("/api/collections/{alias}/followers", ["GET"], "ap_followers", kind="api", evref="156")
page("/api/collections/{alias}/posts/{post}/splitcontent", ["GET", "POST"], "split_content",
     kind="api", evref="144")
page("/api/collections/{alias}/posts/{post}/{property}", ["GET"], "read_collection_post_property",
     kind="api", evref="145")
page("/api/collections/{host}", ["GET"], "fetch_collection_by_host", kind="api", evref="137")
page("/api/collections/monetization-pointer", ["GET"], "monetization_pointer",
     kind="api", evref="136")

# reader timeline (/read)
page("/read", ["GET"], "local_timeline", evref="191")
page("/read/api/posts", ["GET"], "local_timeline_api", kind="api", evref="255")
page("/read/p/{page}", ["GET"], "local_timeline_page", evref="256")
page("/read/feed/", ["GET"], "local_timeline_feed", kind="api", evref="257")
page("/read/t/{tag}", ["GET"], "local_timeline_tag", evref="259")
page("/read/a/{post}", ["GET"], "post_id_redirect", evref="260")

# oauth (client-initiated; external IdP dependency)
page("/oauth/signup", ["GET", "POST"], "oauth_signup", evref="80",
     notes="OAuth login/signup via Slack/WriteAs/GitLab/Gitea/generic; needs external IdP.")

# admin (HTML; session + IsAdmin())
page("/admin", ["GET"], "admin_dashboard", vis_reason="Admin dashboard.",
     reach=["Admin session."], evref="171")
page("/admin/monitor", ["GET"], "admin_monitor", reach=["Admin."], evref="172")
page("/admin/settings", ["GET"], "admin_settings", reach=["Admin."], evref="173")
page("/admin/users", ["GET"], "admin_users", reach=["Admin."], evref="174")
page("/admin/user/{username}", ["GET"], "admin_view_user", reach=["Admin."], evref="175")
page("/admin/user/{username}/delete", ["POST"], "admin_delete_user", reach=["Admin."], evref="176")
page("/admin/user/{username}/status", ["POST"], "admin_toggle_user_status",
     reach=["Admin."], evref="177")
page("/admin/user/{username}/passphrase", ["POST"], "admin_reset_user_pass",
     reach=["Admin."], evref="178")
page("/admin/pages", ["GET"], "admin_pages", reach=["Admin."], evref="179")
page("/admin/page/{slug}", ["GET"], "admin_view_page", reach=["Admin."], evref="180")
page("/admin/update/config", ["POST"], "admin_update_config", reach=["Admin."], evref="181")
page("/admin/update/{page}", ["POST"], "admin_update_site", reach=["Admin."], evref="182")
page("/admin/updates", ["GET"], "admin_updates", reach=["Admin."], evref="183")

# root + static
page("/", ["GET"], "home", evref="215")
page("/robots.txt", ["GET"], "robots", kind="static", evref="471")
page("/manifest.json", ["GET"], "manifest", kind="static", evref="471")


# ===========================================================================
# EDGES (real navigations / request triggers; minimal source-confirmed set)
# ===========================================================================
EDGES = [
    {"src": K("/login"), "dst": K("/api/auth/login"), "methods": ["POST"],
     "triggers": ["form"]},
    {"src": K("/new"), "dst": K("/api/posts"), "methods": ["POST"], "triggers": ["xhr"]},
    {"src": K("/me/c/"), "dst": K("/api/collections"), "methods": ["POST"],
     "triggers": ["xhr"]},
]


# ===========================================================================
# RUNTIME OVERLAY -- probe-grounded statuses (runtime/probe.ps1 -> probe_results/)
# Frozen instance: WriteFreely 0.17.2-73-gd248591, multi-user, open_registration,
# federation=false, private=false, single_user=false. Token transport header:
# "Authorization: Token <access_token>". Identities: anonymous, usera/userb
# (regular users), wfadmin (admin). Labels: owner/non_owner express the
# ownership gate; admin_cookie/nonadmin_cookie/api_token express the /admin/*
# transport split. Source of truth: runtime/probe_results/matrix.json.
# ===========================================================================
_RUNTIME_API = {
    "/api/auth/signup":                      {"s": [201, 409], "id": {"anonymous": [201, 409]}},
    "/api/auth/login":                       {"s": [200, 404, 429], "id": {"anonymous": [200, 404, 429]}},
    "/api/me":                               {"s": [200, 400], "id": {"authenticated": [200], "anonymous": [400]}},
    "/api/me/posts":                         {"s": [200, 400], "id": {"authenticated": [200], "anonymous": [400]}},
    "/api/me/collections":                   {"s": [200, 400], "id": {"authenticated": [200], "anonymous": [400]}},
    "/api/alias":                            {"s": [200, 409], "id": {"anonymous": [200, 409], "authenticated": [200, 409]}},
    "/api/collections":                      {"s": [201], "id": {"authenticated": [201]}},
    "/api/collections/{alias}":              {"s": [200, 401], "id": {"anonymous": [200, 401], "owner": [200], "non_owner": [401]}},
    "/api/collections/{alias}/posts":        {"s": [200, 201], "id": {"anonymous": [200], "authenticated": [200], "owner": [201]}},
    "/api/collections/{alias}/posts/{post}": {"s": [200], "id": {"anonymous": [200], "authenticated": [200]}},
    "/api/posts":                            {"s": [201, 401], "id": {"authenticated": [201], "anonymous": [401]}},
    "/api/posts/disperse":                   {"s": [200], "id": {"owner": [200]}},
    "/api/posts/{post}":                     {"s": [200, 204, 400, 401, 403],
                                              "id": {"owner": [200, 204], "non_owner": [401, 403], "anonymous": [400]}},
    # --- Phase 6 (remaining endpoints) ---
    "/api/markdown":                         {"s": [200], "id": {"anonymous": [200], "authenticated": [200]}},
    "/api/posts/{post}/{property}":          {"s": [200, 400], "id": {"anonymous": [200], "authenticated": [200]}},
    "/api/collections/{alias}/pin":          {"s": [200, 403], "id": {"owner": [200], "non_owner": [403]}},
    "/api/collections/{alias}/unpin":        {"s": [200], "id": {"owner": [200]}},
    "/api/collections/{alias}/collect":      {"s": [200], "id": {"authenticated": [200]}},
    "/api/posts/claim":                      {"s": [200], "id": {"authenticated": [200]}},
    "/api/me/password":                      {"s": [200, 400], "id": {"authenticated": [200], "anonymous": [400]}},
    "/api/auth/me":                          {"s": [204, 400], "id": {"authenticated": [204], "anonymous": [400]}},
}
_RUNTIME_PAGE = {
    "/admin/users": {"s": [200, 404],
                     "id": {"admin_cookie": [200], "nonadmin_cookie": [404],
                            "anonymous": [404], "api_token": [404]}},
}


def _apply_runtime():
    base = len(c.ORIGIN)
    for n in API_NODES:
        r = _RUNTIME_API.get(n["key"][base:])
        if r:
            n["statuses"] = r["s"]
            n["identity_statuses"] = r["id"]
            n["route_confirmed"] = True
    for n in PAGE_NODES:
        r = _RUNTIME_PAGE.get(n["key"][base:])
        if r:
            n["statuses"] = r["s"]
            n["identity_statuses"] = r["id"]
            n["route_confirmed"] = True


_apply_runtime()
