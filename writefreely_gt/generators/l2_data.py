# -*- coding: utf-8 -*-
"""WriteFreely L2 action cores.

One business action per <Subject,Operation,Object,Req,Eff>. Facts use only the six
Pengent predicates. io_accounting fact strings are produced with common.fact_key so
they always match Req/Eff. Evidence refs point at writefreely/ source (routes.go +
the named handler). Statuses/identity scoping are confidence-flagged pending runtime.
"""
import common as c
from common import (key as K, subj, reference, entity, f_auth, f_know, f_exists,
                    f_state, f_relation, f_can, req, eff, io, fact_key)
from l2lib import action, obj, bind, entity_p

ACTOR = subj()


def kf(fact):
    return fact_key(fact)


def src(ref, supports="route + handler"):
    return c.ev("source", "writefreely/" + ref, supports)


# ===========================================================================
# AUTH / SESSION
# ===========================================================================
_pw = f_know(ACTOR, reference("Password", entity("user", "User", "self")))
_tok = f_know(ACTOR, reference("AuthToken", entity("session", "Session", "created")))
action(
    "anon_signup", "Sign up", "Create", "signup_user", "Anonymous",
    obj("entity", "user", "User", "response", "username", "Username(user)", role="created"),
    requirements=[req("knowledge", _pw, "Caller supplies the new account password (brought credential).")],
    gen=[eff(f_exists(entity("user", "User", "created")), "action_semantics", "A new user row is created."),
         eff(_tok, "io_reference", "Response returns an API access token.")],
    kill=[],
    io_accounting=[io("input", "alias / Username(user)", "object_attribute", [], "Chosen username (new content)."),
                   io("input", "pass / Password(user)", "req", [kf(_pw)]),
                   io("input", "email / UserEmail(user)", "object_attribute", [], "Optional new email."),
                   io("output", "access_token / AuthToken(session)", "gen", [kf(_tok)]),
                   io("output", "username / Username(user)", "observed_only", [], "Echo of the created name.")],
    bindings=[bind(K("/api/auth/signup"), ["POST"])],
    vis="black_box", vis_reason="Public signup.", reachable=True,
    reach_conds=["Open registration enabled."],
    evidence=[src("account.go:89 apiSignup", "create user + token")],
    confidence=0.85, reasoning="apiSignup creates a User and returns an access token.",
    description="A visitor registers and receives an API token.")

_pw2 = f_know(ACTOR, reference("Password", entity("user", "User", "self")))
_tok2 = f_know(ACTOR, reference("AuthToken", entity("session", "Session", "created")))
action(
    "anon_login", "Log in", "Create", "login_user", "Anonymous",
    obj("state", "session", "Session", "response", "access_token", "AuthToken(session)",
        role="created", state_field="authenticated"),
    requirements=[req("knowledge", _pw2, "Caller supplies the account password.")],
    gen=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The caller becomes authenticated."),
         eff(_tok2, "io_reference", "Response returns an API access token.")],
    kill=[],
    io_accounting=[io("input", "alias / Username(user)", "object_attribute", [], "Login identifier."),
                   io("input", "pass / Password(user)", "req", [kf(_pw2)]),
                   io("output", "access_token / AuthToken(session)", "gen", [kf(_tok2)]),
                   io("output", "username / Username(user)", "observed_only", [], "Echoed identity.")],
    bindings=[bind(K("/api/auth/login"), ["POST"])],
    vis="black_box", vis_reason="Public login.", reachable=True,
    reach_conds=["Valid credentials."],
    evidence=[src("account.go:405 login", "authenticate + token")],
    confidence=0.9, reasoning="login authenticates and returns a token.",
    description="A visitor logs in and receives an API token.")

_auth = f_auth(ACTOR, "Session")
action(
    "user_logout", "Log out (API)", "Delete", "logout_user", "APIUser",
    obj("state", "session", "Session", "subject", "", "AuthToken(session)",
        role="self", state_field="authenticated"),
    requirements=[req("authentication", _auth, "A valid access token identifies the caller.")],
    gen=[], kill=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The access token is invalidated.")],
    io_accounting=[],
    bindings=[bind(K("/api/auth/me"), ["DELETE"])],
    vis="black_box", vis_reason="Token invalidation.", reachable=True,
    reach_conds=["Authenticated via Authorization header."],
    evidence=[src("account.go:299 handleAPILogout", "invalidate token")],
    confidence=0.85, reasoning="handleAPILogout deletes the caller's token.",
    description="A user invalidates their API access token.")

# ===========================================================================
# ME (self)
# ===========================================================================
_u_self = f_know(ACTOR, reference("Username", entity("user", "User", "self")))
action(
    "user_read_me", "Read own account", "Read", "read_me", "APIUser",
    obj("entity", "user", "User", "subject", "", "Username(user)", role="self"),
    requirements=[req("authentication", _auth, "IsAuthenticated (token or cookie).")],
    gen=[eff(_u_self, "io_reference", "Returns the caller's own username.")],
    kill=[],
    io_accounting=[io("output", "username / Username(user)", "gen", [kf(_u_self)])],
    bindings=[bind(K("/api/me"), ["GET"])],
    vis="black_box", vis_reason="Authenticated self lookup.", reachable=True,
    reach_conds=["Authenticated."],
    evidence=[src("account.go:702 viewMeAPI", "self info")],
    confidence=0.9, reasoning="viewMeAPI returns the authenticated user.",
    description="A user reads their own account info.")

_mp = f_know(ACTOR, reference("PostID", entity("post", "Post", "collection")))
action(
    "user_list_my_posts", "List own posts", "Read", "list_my_posts", "APIUser",
    obj("entity", "post", "Post", "implicit", "", "PostID(post)", role="collection"),
    requirements=[req("authentication", _auth, "Authenticated (cookie or token).")],
    gen=[eff(_mp, "io_reference", "Returns ids of the caller's posts.")],
    kill=[],
    io_accounting=[io("output", "id / PostID(post)", "gen", [kf(_mp)])],
    bindings=[bind(K("/api/me/posts"), ["GET"])],
    vis="black_box", vis_reason="Authenticated post list.", reachable=True,
    reach_conds=["Authenticated."],
    evidence=[src("account.go viewMyPostsAPI", "own posts")],
    confidence=0.85, reasoning="viewMyPostsAPI lists the caller's posts.",
    description="A user lists their own posts.")

_mc = f_know(ACTOR, reference("CollectionAlias", entity("collection", "Collection", "collection")))
action(
    "user_list_my_collections", "List own blogs", "Read", "list_my_collections", "APIUser",
    obj("entity", "collection", "Collection", "implicit", "", "CollectionAlias(collection)", role="collection"),
    requirements=[req("authentication", _auth, "Authenticated via token.")],
    gen=[eff(_mc, "io_reference", "Returns aliases of the caller's blogs.")],
    kill=[],
    io_accounting=[io("output", "alias / CollectionAlias(collection)", "gen", [kf(_mc)])],
    bindings=[bind(K("/api/me/collections"), ["GET"])],
    vis="black_box", vis_reason="Authenticated blog list.", reachable=True,
    reach_conds=["Authenticated."],
    evidence=[src("collections.go viewMyCollectionsAPI", "own blogs")],
    confidence=0.85, reasoning="viewMyCollectionsAPI lists the caller's collections.",
    description="A user lists their own blogs.")

_cur_pw = f_know(ACTOR, reference("Password", entity("user", "User", "self")))
action(
    "user_change_password", "Change password", "Update", "change_password", "APIUser",
    obj("state", "user", "User", "subject", "", "Username(user)", role="self", state_field="password"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _cur_pw, "Current password proves control of the account.")],
    gen=[eff(f_state(entity("user", "User", "self"), "password", "updated"), "state_transition",
             "Password hash replaced.")],
    kill=[eff(f_state(entity("user", "User", "self"), "password", "previous"), "state_transition",
              "Old password no longer valid.")],
    io_accounting=[io("input", "current_pass / Password(user)", "req", [kf(_cur_pw)]),
                   io("input", "new_pass / NewPassword(user)", "object_attribute", [], "Replacement secret.")],
    bindings=[bind(K("/api/me/password"), ["POST"])],
    vis="black_box", vis_reason="Password change.", reachable=True,
    reach_conds=["Authenticated; knows current password."],
    evidence=[src("account.go:1005 updatePassphrase", "password change")],
    confidence=0.8, reasoning="updatePassphrase replaces the caller's password.",
    description="A user changes their own password.")

action(
    "user_check_alias", "Check username availability", "Read", "check_alias", "Anonymous",
    obj("entity", "user", "User", "request", "alias", "Username(user)", role="target"),
    requirements=[],
    gen=[], kill=[],
    io_accounting=[io("input", "alias / Username(user)", "object_attribute", [], "Probed candidate name."),
                   io("output", "available / Availability(user)", "observed_only", [], "Boolean availability.")],
    bindings=[bind(K("/api/alias"), ["POST"])],
    vis="black_box", vis_reason="Availability oracle (enumeration surface).", reachable=True,
    reach_conds=["Open; confirm anon reachability at runtime."],
    evidence=[src("routes.go:126 handleUsernameCheck", "availability check")],
    confidence=0.7, reasoning="handleUsernameCheck reports whether a username is taken.",
    description="A visitor probes whether a username is available.",
    notes="Username-enumeration oracle; pair with runtime identity_statuses.")

action(
    "user_render_markdown", "Render markdown", "Read", "render_markdown", "Anonymous",
    obj("entity", "doc", "Document", "request", "raw_body", "MarkdownSource(doc)", role="target"),
    requirements=[],
    gen=[], kill=[],
    io_accounting=[io("input", "raw_body / MarkdownSource(doc)", "object_attribute", [], "Transient markdown."),
                   io("output", "body / RenderedHTML(doc)", "observed_only", [], "Rendered HTML (no state).")],
    bindings=[bind(K("/api/markdown"), ["POST"])],
    vis="black_box", vis_reason="Stateless preview.", reachable=True,
    reach_conds=["Open."],
    evidence=[src("routes.go:128 handleRenderMarkdown", "markdown preview")],
    confidence=0.75, reasoning="handleRenderMarkdown renders markdown without persisting.",
    description="A visitor previews markdown rendered to HTML.")

# ===========================================================================
# COLLECTIONS (blogs)
# ===========================================================================
_coll_c = entity("collection", "Collection", "created")
_know_coll_c = f_know(ACTOR, reference("CollectionAlias", _coll_c))
action(
    "user_create_collection", "Create blog", "Create", "create_collection", "APIUser",
    obj("entity", "collection", "Collection", "response", "alias", "CollectionAlias(collection)", role="created"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Create", _coll_c), "Under the max-blogs quota.")],
    gen=[eff(f_exists(_coll_c), "action_semantics", "A new Collection is created."),
         eff(_know_coll_c, "io_reference", "Response returns the created alias.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "object_attribute", [], "Chosen alias."),
                   io("input", "title / CollectionTitle(collection)", "object_attribute", [], "Blog title (content)."),
                   io("output", "alias / CollectionAlias(collection)", "gen", [kf(_know_coll_c)])],
    bindings=[bind(K("/api/collections"), ["POST"])],
    vis="black_box", vis_reason="Blog creation.", reachable=True,
    reach_conds=["Authenticated; quota not exceeded."],
    evidence=[src("collections.go:446 newCollection", "create blog")],
    confidence=0.85, reasoning="newCollection creates a Collection owned by the caller.",
    description="A user creates a new blog (collection).")

_coll_t = entity("collection", "Collection", "target")
_know_coll_t = f_know(ACTOR, reference("CollectionAlias", _coll_t))
action(
    "reader_read_collection", "Read blog", "Read", "read_collection", "Reader",
    obj("entity", "collection", "Collection", "request", "alias", "CollectionAlias(collection)"),
    requirements=[req("knowledge", _know_coll_t, "Request carries the blog alias."),
                  req("existence", f_exists(_coll_t), "Unknown aliases 404 (confirm at runtime).")],
    gen=[eff(_know_coll_t, "io_reference", "Returns blog metadata and alias.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_t)]),
                   io("output", "alias / CollectionAlias(collection)", "gen", [kf(_know_coll_t)]),
                   io("output", "title / CollectionTitle(collection)", "observed_only", [], "Display attribute."),
                   io("output", "description / CollectionDescription(collection)", "observed_only", [], "Display.")],
    bindings=[bind(K("/api/collections/{alias}"), ["GET"])],
    vis="black_box", vis_reason="Public blog read.", reachable=True,
    reach_conds=["Public unless instance is Private."],
    evidence=[src("collections.go:554 fetchCollection", "read blog")],
    confidence=0.85, reasoning="fetchCollection returns public blog metadata.",
    description="A reader reads a blog's public metadata.")

action(
    "owner_update_collection", "Update blog", "Update", "update_collection", "Owner",
    obj("entity", "collection", "Collection", "request", "alias", "CollectionAlias(collection)"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_t, "Target blog alias."),
                  req("existence", f_exists(_coll_t), "Blog must exist."),
                  req("authorization", f_can(ACTOR, "Update", _coll_t), "Blog owner only.")],
    gen=[eff(f_state(_coll_t, "title", "updated"), "state_transition", "Title replaced.")],
    kill=[eff(f_state(_coll_t, "title", "previous"), "state_transition", "Old title dropped.")],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_t)]),
                   io("input", "title / CollectionTitle(collection)", "object_attribute", [], "Updated title."),
                   io("input", "description / CollectionDescription(collection)", "object_attribute", [], "Updated desc.")],
    bindings=[bind(K("/api/collections/{alias}"), ["POST"])],
    vis="black_box", vis_reason="Owner edit.", reachable=True,
    reach_conds=["Blog owner."],
    evidence=[src("collections.go:1264 existingCollection", "update blog")],
    confidence=0.8, reasoning="existingCollection (POST) updates blog fields.",
    description="A blog owner updates their blog settings.")

action(
    "owner_delete_collection", "Delete blog", "Delete", "delete_collection", "Owner",
    obj("entity", "collection", "Collection", "request", "alias", "CollectionAlias(collection)"),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_t, "Target blog alias."),
                  req("existence", f_exists(_coll_t), "Blog must exist."),
                  req("authorization", f_can(ACTOR, "Delete", _coll_t), "Blog owner only.")],
    gen=[], kill=[eff(f_exists(_coll_t), "state_transition", "Blog removed.")],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_t)])],
    bindings=[bind(K("/api/collections/{alias}"), ["DELETE"])],
    vis="black_box", vis_reason="Owner delete.", reachable=True,
    reach_conds=["Blog owner."],
    evidence=[src("collections.go:1264 existingCollection", "delete blog")],
    confidence=0.8, reasoning="existingCollection (DELETE) removes the blog.",
    description="A blog owner deletes their blog.")

# ----- collection posts -----
_coll_ctx = entity("collection", "Collection", "context")
_know_coll_ctx = f_know(ACTOR, reference("CollectionAlias", _coll_ctx))
_cpost_col = entity("post", "Post", "collection")
_know_cpost_col = f_know(ACTOR, reference("PostID", _cpost_col))
action(
    "reader_list_collection_posts", "List blog posts", "Read", "list_collection_posts", "Reader",
    obj("entity", "post", "Post", "implicit", "", "PostID(post)", role="collection",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("knowledge", _know_coll_ctx, "Blog alias in path."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist.")],
    gen=[eff(_know_cpost_col, "io_reference", "Returns post ids of the blog.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("output", "id / PostID(post)", "gen", [kf(_know_cpost_col)]),
                   io("output", "slug / PostSlug(post)", "observed_only", [], "Per-blog slug; display.")],
    bindings=[bind(K("/api/collections/{alias}/posts"), ["GET"])],
    vis="black_box", vis_reason="Public post list.", reachable=True,
    reach_conds=["Public unless Private."],
    evidence=[src("collections.go:604 fetchCollectionPosts", "list posts")],
    confidence=0.85, reasoning="fetchCollectionPosts paginates a blog's posts.",
    description="A reader lists the posts of a blog.")

_post_c = entity("post", "Post", "created")
_know_post_c = f_know(ACTOR, reference("PostID", _post_c))
action(
    "user_create_collection_post", "Publish post", "Create", "create_collection_post", "Owner",
    obj("entity", "post", "Post", "response", "id", "PostID(post)", role="created",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_ctx, "Target blog alias."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist."),
                  req("authorization", f_can(ACTOR, "Create", _post_c), "Blog owner may publish.")],
    gen=[eff(f_exists(_post_c), "action_semantics", "A new post is created."),
         eff(f_relation(_post_c, _coll_ctx, "InCollection"), "relation_transition", "Post attached to blog."),
         eff(_know_post_c, "io_reference", "Response returns the post id.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("input", "body / PostBody(post)", "object_attribute", [], "New post content."),
                   io("input", "title / PostTitle(post)", "object_attribute", [], "New post title."),
                   io("output", "id / PostID(post)", "gen", [kf(_know_post_c)]),
                   io("output", "slug / PostSlug(post)", "observed_only", [], "Assigned slug.")],
    bindings=[bind(K("/api/collections/{alias}/posts"), ["POST"])],
    vis="black_box", vis_reason="Publish to a blog.", reachable=True,
    reach_conds=["Blog owner."],
    evidence=[src("posts.go:565 newPost", "create post in collection")],
    confidence=0.8, reasoning="newPost with a collection creates a published post.",
    description="A blog owner publishes a post to their blog.")

_post_t = entity("post", "Post", "target")
_know_post_t = f_know(ACTOR, reference("PostID", _post_t))
action(
    "reader_read_collection_post", "Read blog post", "Read", "read_collection_post", "Reader",
    obj("entity", "post", "Post", "request", "post", "PostID(post)",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("knowledge", _know_coll_ctx, "Blog alias in path."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist."),
                  req("knowledge", _know_post_t, "Post slug/id in path."),
                  req("existence", f_exists(_post_t), "Post must exist.")],
    gen=[eff(_know_post_t, "io_reference", "Returns the post and its id.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("output", "id / PostID(post)", "gen", [kf(_know_post_t)]),
                   io("output", "body / PostBody(post)", "observed_only", [], "Post content; display.")],
    bindings=[bind(K("/api/collections/{alias}/posts/{post}"), ["GET"])],
    vis="black_box", vis_reason="Public post read.", reachable=True,
    reach_conds=["Public unless Private."],
    evidence=[src("posts.go:1142 fetchPost", "read one post")],
    confidence=0.85, reasoning="fetchPost returns a single collection post.",
    description="A reader reads one post of a blog.")

action(
    "owner_update_collection_post", "Edit blog post", "Update", "update_collection_post", "Owner",
    obj("entity", "post", "Post", "request", "post", "PostID(post)",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_ctx, "Owning blog alias."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist."),
                  req("knowledge", _know_post_t, "Target post id."),
                  req("existence", f_exists(_post_t), "Post must exist."),
                  req("authorization", f_can(ACTOR, "Update", _post_t), "Post author / blog owner.")],
    gen=[eff(f_state(_post_t, "body", "updated"), "state_transition", "Body replaced.")],
    kill=[eff(f_state(_post_t, "body", "previous"), "state_transition", "Old body dropped.")],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("input", "body / PostBody(post)", "object_attribute", [], "Updated content.")],
    bindings=[bind(K("/api/collections/{alias}/posts/{post}"), ["POST"])],
    vis="black_box", vis_reason="Owner edit of a published post.", reachable=True,
    reach_conds=["Post author / blog owner."],
    evidence=[src("posts.go:713 existingPost", "update post")],
    confidence=0.8, reasoning="existingPost updates a collection post.",
    description="A blog owner edits one of their published posts.")

# ----- collect / pin -----
_cpost_m = entity("post", "Post", "member")
_know_cpost_m = f_know(ACTOR, reference("PostID", _cpost_m))
_tok_cpost_m = f_know(ACTOR, reference("PostEditToken", _cpost_m))
_coll_dst = entity("collection", "Collection", "destination")
_know_coll_dst = f_know(ACTOR, reference("CollectionAlias", _coll_dst))
action(
    "user_collect_posts_to_collection", "Move posts into blog", "Create", "collect_posts", "Owner",
    obj("relation", "membership", "CollectionMembership", "request", "alias", "CollectionAlias(collection)",
        role="created",
        participants=[entity_p("collection", "Collection", "destination",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"}),
                      entity_p("post", "Post", "member",
                               {"source": "request", "field": "id", "resource": "PostID(post)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_dst, "Destination blog alias."),
                  req("existence", f_exists(_coll_dst), "Destination blog must exist."),
                  req("knowledge", _know_cpost_m, "Post id to move."),
                  req("existence", f_exists(_cpost_m), "Post must exist."),
                  req("knowledge", _tok_cpost_m, "Edit token authorizing the move of an anon post.")],
    gen=[eff(f_relation(_cpost_m, _coll_dst, "InCollection"), "relation_transition",
             "Post is placed in the destination blog.")],
    kill=[],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_dst)]),
                   io("input", "id / PostID(post)", "req", [kf(_know_cpost_m)]),
                   io("input", "token / PostEditToken(post)", "req", [kf(_tok_cpost_m)])],
    bindings=[bind(K("/api/collections/{alias}/collect"), ["POST"])],
    vis="black_box", vis_reason="Collect posts into a blog.", reachable=True,
    reach_conds=["Authenticated; holds the post edit token."],
    evidence=[src("posts.go:963 addPost", "collect/move posts")],
    confidence=0.75, reasoning="addPost moves posts into the target collection.",
    description="A user moves posts into one of their blogs.")

_pin_post = entity("post", "Post", "target")
_know_pin = f_know(ACTOR, reference("PostID", _pin_post))
action(
    "owner_pin_post", "Pin post", "Update", "pin_post", "Owner",
    obj("state", "post", "Post", "request", "id", "PostID(post)", role="target", state_field="pinned",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_ctx, "Blog alias whose nav changes."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist."),
                  req("knowledge", _know_pin, "Post id to pin."),
                  req("existence", f_exists(_pin_post), "Post must exist."),
                  req("authorization", f_can(ACTOR, "Update", _coll_ctx), "Blog owner.")],
    gen=[eff(f_state(_pin_post, "pinned", "true"), "state_transition", "Post pinned to nav.")],
    kill=[eff(f_state(_pin_post, "pinned", "false"), "state_transition", "Was unpinned.")],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("input", "id / PostID(post)", "req", [kf(_know_pin)])],
    bindings=[bind(K("/api/collections/{alias}/pin"), ["POST"])],
    vis="black_box", vis_reason="Pin to blog nav.", reachable=True,
    reach_conds=["Blog owner."],
    evidence=[src("posts.go:1072 pinPost", "pin")],
    confidence=0.75, reasoning="pinPost pins a post.",
    description="A blog owner pins a post to the blog navigation.")

action(
    "owner_unpin_post", "Unpin post", "Update", "unpin_post", "Owner",
    obj("state", "post", "Post", "request", "id", "PostID(post)", role="target", state_field="pinned",
        participants=[entity_p("collection", "Collection", "context",
                               {"source": "request", "field": "alias", "resource": "CollectionAlias(collection)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_coll_ctx, "Blog alias whose nav changes."),
                  req("existence", f_exists(_coll_ctx), "Blog must exist."),
                  req("knowledge", _know_pin, "Post id to unpin."),
                  req("existence", f_exists(_pin_post), "Post must exist."),
                  req("authorization", f_can(ACTOR, "Update", _coll_ctx), "Blog owner.")],
    gen=[eff(f_state(_pin_post, "pinned", "false"), "state_transition", "Post removed from nav.")],
    kill=[eff(f_state(_pin_post, "pinned", "true"), "state_transition", "Was pinned.")],
    io_accounting=[io("input", "alias / CollectionAlias(collection)", "req", [kf(_know_coll_ctx)]),
                   io("input", "id / PostID(post)", "req", [kf(_know_pin)])],
    bindings=[bind(K("/api/collections/{alias}/unpin"), ["POST"])],
    vis="black_box", vis_reason="Unpin from blog nav.", reachable=True,
    reach_conds=["Blog owner."],
    evidence=[src("posts.go:1072 pinPost", "unpin")],
    confidence=0.75, reasoning="pinPost (unpin) removes a pinned post.",
    description="A blog owner unpins a post from the blog navigation.")

# ===========================================================================
# POSTS (draft / anonymous)
# ===========================================================================
_dpost = entity("post", "Post", "created")
_know_dpost = f_know(ACTOR, reference("PostID", _dpost))
_tok_dpost = f_know(ACTOR, reference("PostEditToken", _dpost))
action(
    "anon_create_draft_post", "Create anonymous post", "Create", "create_draft_post", "Anonymous",
    obj("entity", "post", "Post", "response", "id", "PostID(post)", role="created"),
    requirements=[],
    gen=[eff(f_exists(_dpost), "action_semantics", "A new anonymous/draft post is created."),
         eff(_know_dpost, "io_reference", "Response returns the post id."),
         eff(_tok_dpost, "io_reference", "Response returns an edit token for the author.")],
    kill=[],
    io_accounting=[io("input", "body / PostBody(post)", "object_attribute", [], "Post content."),
                   io("input", "title / PostTitle(post)", "object_attribute", [], "Post title."),
                   io("output", "id / PostID(post)", "gen", [kf(_know_dpost)]),
                   io("output", "token / PostEditToken(post)", "gen", [kf(_tok_dpost)])],
    bindings=[bind(K("/api/posts"), ["POST"])],
    vis="black_box", vis_reason="Anonymous posting surface.", reachable=True,
    reach_conds=["Open (anonymous posting enabled by default)."],
    evidence=[src("posts.go:565 newPost", "create anonymous post")],
    confidence=0.8, reasoning="newPost without a collection creates an anonymous post + edit token.",
    description="A visitor creates an anonymous post and receives an edit token.",
    notes="The returned edit token is the capability that later authorizes edit/delete/claim.")

action(
    "user_claim_posts", "Claim anonymous posts", "Create", "claim_posts", "APIUser",
    obj("relation", "ownership", "PostOwnership", "request", "id", "PostID(post)", role="created",
        participants=[entity_p("post", "Post", "member",
                               {"source": "request", "field": "id", "resource": "PostID(post)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_cpost_m, "Post id to claim."),
                  req("existence", f_exists(_cpost_m), "Post must exist."),
                  req("knowledge", _tok_cpost_m, "Edit token proving control of the anonymous post.")],
    gen=[eff(f_relation(_cpost_m, ACTOR, "OwnedBy"), "relation_transition",
             "Post becomes owned by the caller.")],
    kill=[],
    io_accounting=[io("input", "id / PostID(post)", "req", [kf(_know_cpost_m)]),
                   io("input", "token / PostEditToken(post)", "req", [kf(_tok_cpost_m)])],
    bindings=[bind(K("/api/posts/claim"), ["POST"])],
    vis="black_box", vis_reason="Associate anonymous posts with an account.", reachable=True,
    reach_conds=["Authenticated; holds the post edit token."],
    evidence=[src("posts.go:963 addPost", "claim posts")],
    confidence=0.75, reasoning="addPost (claim) ties anonymous posts to the account.",
    description="A user claims anonymous posts into their account using edit tokens.")

_opost = entity("post", "Post", "member")
action(
    "user_disperse_posts", "Unclaim posts", "Delete", "disperse_posts", "APIUser",
    obj("relation", "ownership", "PostOwnership", "request", "id", "PostID(post)", role="target",
        participants=[entity_p("post", "Post", "member",
                               {"source": "request", "field": "id", "resource": "PostID(post)"})]),
    requirements=[req("authentication", _auth, "Authenticated."),
                  req("knowledge", _know_cpost_m, "Owned post id."),
                  req("existence", f_exists(_cpost_m), "Post must exist."),
                  req("authorization", f_can(ACTOR, "Update", _opost), "Post owner.")],
    gen=[], kill=[eff(f_relation(_cpost_m, ACTOR, "OwnedBy"), "relation_transition",
                      "Ownership link removed.")],
    io_accounting=[io("input", "id / PostID(post)", "req", [kf(_know_cpost_m)])],
    bindings=[bind(K("/api/posts/disperse"), ["POST"])],
    vis="black_box", vis_reason="Unclaim posts from the account.", reachable=True,
    reach_conds=["Authenticated owner."],
    evidence=[src("posts.go:1028 dispersePost", "unclaim posts")],
    confidence=0.75, reasoning="dispersePost removes posts from the caller's account.",
    description="A user removes (unclaims) posts from their account.")

action(
    "reader_read_post", "Read post", "Read", "read_post", "Reader",
    obj("entity", "post", "Post", "request", "post", "PostID(post)"),
    requirements=[req("knowledge", _know_post_t, "Post id in path."),
                  req("existence", f_exists(_post_t), "Post must exist.")],
    gen=[eff(_know_post_t, "io_reference", "Returns the post and its id.")],
    kill=[],
    io_accounting=[io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("output", "id / PostID(post)", "gen", [kf(_know_post_t)]),
                   io("output", "body / PostBody(post)", "observed_only", [], "Post content; display.")],
    bindings=[bind(K("/api/posts/{post}"), ["GET"])],
    vis="black_box", vis_reason="Public post read by id.", reachable=True,
    reach_conds=["Public unless Private."],
    evidence=[src("posts.go:1142 fetchPost", "read post by id")],
    confidence=0.85, reasoning="fetchPost returns a post by id.",
    description="A reader reads a post directly by its id.")

_tok_post_t = f_know(ACTOR, reference("PostEditToken", _post_t))
action(
    "author_update_post", "Edit post", "Update", "update_post", "Author",
    obj("entity", "post", "Post", "request", "post", "PostID(post)"),
    requirements=[req("knowledge", _know_post_t, "Post id in path."),
                  req("existence", f_exists(_post_t), "Post must exist."),
                  req("knowledge", _tok_post_t, "Edit token (for an anonymous post)."),
                  req("authorization", f_can(ACTOR, "Update", _post_t), "Post owner or edit-token holder.")],
    gen=[eff(f_state(_post_t, "body", "updated"), "state_transition", "Body replaced.")],
    kill=[eff(f_state(_post_t, "body", "previous"), "state_transition", "Old body dropped.")],
    io_accounting=[io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("input", "token / PostEditToken(post)", "req", [kf(_tok_post_t)]),
                   io("input", "body / PostBody(post)", "object_attribute", [], "Updated content.")],
    bindings=[bind(K("/api/posts/{post}"), ["POST", "PUT"])],
    vis="black_box", vis_reason="Edit via ownership or edit token.", reachable=True,
    reach_conds=["Post owner (session/token) or anon edit-token holder."],
    evidence=[src("posts.go:713 existingPost", "update post")],
    confidence=0.8, reasoning="existingPost updates a post, authorized by owner or edit token.",
    description="An author edits a post via account ownership or the post edit token.")

action(
    "author_delete_post", "Delete post", "Delete", "delete_post", "Author",
    obj("entity", "post", "Post", "request", "post", "PostID(post)"),
    requirements=[req("knowledge", _know_post_t, "Post id in path."),
                  req("existence", f_exists(_post_t), "Post must exist."),
                  req("knowledge", _tok_post_t, "Edit token (for an anonymous post)."),
                  req("authorization", f_can(ACTOR, "Delete", _post_t), "Post owner or edit-token holder.")],
    gen=[], kill=[eff(f_exists(_post_t), "state_transition", "Post removed.")],
    io_accounting=[io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("input", "token / PostEditToken(post)", "req", [kf(_tok_post_t)])],
    bindings=[bind(K("/api/posts/{post}"), ["DELETE"])],
    vis="black_box", vis_reason="Delete via ownership or edit token.", reachable=True,
    reach_conds=["Post owner or anon edit-token holder."],
    evidence=[src("posts.go:846 deletePost", "delete post")],
    confidence=0.8, reasoning="deletePost removes a post, authorized by owner or edit token.",
    description="An author deletes a post via account ownership or the post edit token.")

action(
    "reader_read_post_property", "Read post property", "Read", "read_post_property", "Reader",
    obj("entity", "post", "Post", "request", "post", "PostID(post)"),
    requirements=[req("knowledge", _know_post_t, "Post id in path."),
                  req("existence", f_exists(_post_t), "Post must exist.")],
    gen=[eff(_know_post_t, "io_reference", "Returns the requested property of a known post.")],
    kill=[],
    io_accounting=[io("input", "post / PostID(post)", "req", [kf(_know_post_t)]),
                   io("input", "property / PostProperty(post)", "object_attribute", [], "Which field is requested."),
                   io("output", "value / PostProperty(post)", "observed_only", [], "Single field value; display.")],
    bindings=[bind(K("/api/posts/{post}/{property}"), ["GET"])],
    vis="black_box", vis_reason="Public single-property read.", reachable=True,
    reach_conds=["Public unless Private."],
    evidence=[src("posts.go:1201 fetchPostProperty", "read one property")],
    confidence=0.8, reasoning="fetchPostProperty returns one field of a post.",
    description="A reader reads a single property of a post.")

# ===========================================================================
# ADMIN (bound to admin HTML form routes; privileged surface)
# ===========================================================================
_adm_user = entity("user", "User", "target")
_know_adm_user = f_know(ACTOR, reference("Username", _adm_user))
action(
    "admin_delete_user", "Delete user (admin)", "Delete", "admin_delete_user", "Administrator",
    obj("entity", "user", "User", "request", "username", "Username(user)", role="target"),
    requirements=[req("authentication", _auth, "Admin session."),
                  req("knowledge", _know_adm_user, "Target username in path."),
                  req("existence", f_exists(_adm_user), "User must exist."),
                  req("authorization", f_can(ACTOR, "Delete", _adm_user), "IsAdmin() required.")],
    gen=[], kill=[eff(f_exists(_adm_user), "state_transition", "User account removed.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(_know_adm_user)])],
    bindings=[bind(K("/admin/user/{username}/delete"), ["POST"])],
    vis="black_box", vis_reason="Admin user management (browser form).", reachable=True,
    reach_conds=["Admin session."],
    evidence=[src("routes.go:176 handleAdminDeleteUser", "admin delete user")],
    confidence=0.8, reasoning="handleAdminDeleteUser removes a user account.",
    description="An administrator deletes a user account.")

action(
    "admin_toggle_user_status", "Toggle user status (admin)", "Update", "admin_toggle_user_status",
    "Administrator",
    obj("state", "user", "User", "request", "username", "Username(user)", role="target", state_field="status"),
    requirements=[req("authentication", _auth, "Admin session."),
                  req("knowledge", _know_adm_user, "Target username."),
                  req("existence", f_exists(_adm_user), "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", _adm_user), "IsAdmin() required.")],
    gen=[eff(f_state(_adm_user, "status", "toggled"), "state_transition", "Suspended/active flipped.")],
    kill=[eff(f_state(_adm_user, "status", "previous"), "state_transition", "Prior status dropped.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(_know_adm_user)])],
    bindings=[bind(K("/admin/user/{username}/status"), ["POST"])],
    vis="black_box", vis_reason="Admin suspends/activates a user.", reachable=True,
    reach_conds=["Admin session."],
    evidence=[src("routes.go:177 handleAdminToggleUserStatus", "admin status toggle")],
    confidence=0.8, reasoning="handleAdminToggleUserStatus flips a user's suspended flag.",
    description="An administrator suspends or re-activates a user.")

action(
    "admin_reset_user_pass", "Reset user password (admin)", "Update", "admin_reset_user_pass",
    "Administrator",
    obj("state", "user", "User", "request", "username", "Username(user)", role="target", state_field="password"),
    requirements=[req("authentication", _auth, "Admin session."),
                  req("knowledge", _know_adm_user, "Target username."),
                  req("existence", f_exists(_adm_user), "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", _adm_user), "IsAdmin() required.")],
    gen=[eff(f_state(_adm_user, "password", "reset"), "state_transition", "Password reset by admin.")],
    kill=[eff(f_state(_adm_user, "password", "previous"), "state_transition", "Old password dropped.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(_know_adm_user)]),
                   io("input", "new_pass / NewPassword(user)", "object_attribute", [], "Admin-set password.")],
    bindings=[bind(K("/admin/user/{username}/passphrase"), ["POST"])],
    vis="black_box", vis_reason="Admin account takeover primitive.", reachable=True,
    reach_conds=["Admin session."],
    evidence=[src("routes.go:178 handleAdminResetUserPass", "admin password reset")],
    confidence=0.8, reasoning="handleAdminResetUserPass sets a user's password.",
    description="An administrator resets another user's password.")
