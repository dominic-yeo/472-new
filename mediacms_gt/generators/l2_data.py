# -*- coding: utf-8 -*-
"""MediaCMS 9.2.1 L2 action cores.

One business action per <Subject,Operation,Object,Req,Eff>. Endpoints are split by
permission context and by request discriminators (action= / type= / url_path).
Facts use only the six Pengent predicates. io_accounting fact strings are produced
with common.fact_key so they always match Req/Eff.
"""
import common as c
from common import key as K, subj, reference, entity, f_auth, f_know, f_exists, f_state, \
    f_relation, f_can, req, eff, io, fact_key
from l2lib import action, obj, bind, principal_p, entity_p

# ---- shared terms -----------------------------------------------------------
ACTOR = subj()
MEDIA = entity("media", "Media", "target")
AUTH = f_auth(ACTOR, "Session")
KNOW_MEDIA = f_know(ACTOR, reference("MediaToken", MEDIA))
EXISTS_MEDIA = f_exists(MEDIA)


def kf(fact):
    return fact_key(fact)


# ============================================================================
# MEDIA
# ============================================================================
action(
    "user_list_media", "List media", "Read", "list_media", "CurrentUser",
    obj("entity", "media", "Media", "implicit", "", "MediaToken(media)", role="collection"),
    requirements=[],
    gen=[eff(KNOW_MEDIA, "io_reference", "Response returns friendly_token references for listed media.")],
    kill=[],
    io_accounting=[
        io("output", "friendly_token / MediaToken(media)", "gen", [kf(KNOW_MEDIA)]),
        io("output", "title / MediaTitle(media)", "observed_only", [], "Display attribute; not a reference."),
        io("input", "author / Username(user)", "object_attribute", [], "Filter only; not a precondition fact."),
    ],
    bindings=[bind(K("/api/v1/media"), ["GET"])],
    vis="black_box", vis_reason="Home/listing pages fetch this.", reachable=True,
    reach_conds=["Public read; scope widens with session."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200 all identities")],
    confidence=0.95, reasoning="List endpoint; read semantics confirmed by source + runtime.",
    description="A visitor lists media the identity is allowed to see.",
)

action(
    "user_create_media", "Upload media", "Create", "upload_media", "CurrentUser",
    obj("entity", "media", "Media", "response", "friendly_token", "MediaToken(media)", role="created"),
    requirements=[req("authentication", AUTH, "IsAuthorizedToAdd requires an authenticated uploader."),
                  req("authorization", f_can(ACTOR, "Create", MEDIA), "Upload permission (CAN_ADD_MEDIA / quota).")],
    gen=[eff(f_exists(entity("media", "Media", "created")), "action_semantics", "A new Media row is created."),
         eff(f_know(ACTOR, reference("MediaToken", entity("media", "Media", "created"))), "io_reference",
             "Response returns the created media's friendly_token.")],
    kill=[],
    io_accounting=[
        io("input", "media_file / MediaFile(media)", "object_attribute", [], "New uploaded content, not a precondition."),
        io("input", "title / MediaTitle(media)", "object_attribute", [], "New content attribute."),
        io("input", "description / MediaDescription(media)", "object_attribute", [], "New content attribute."),
        io("output", "friendly_token / MediaToken(media)", "gen",
           [kf(f_know(ACTOR, reference("MediaToken", entity("media", "Media", "created"))))]),
    ],
    bindings=[bind(K("/api/v1/media"), ["POST"])],
    vis="black_box", vis_reason="Upload form posts a media file.", reachable=True,
    reach_conds=["Authenticated with upload permission (CAN_ADD_MEDIA=all)."],
    evidence=[c.ev("runtime", "upload token=Yt7r1RFGP -> 201", "Create confirmed")],
    confidence=0.95, reasoning="MediaList.post creates Media owned by the user.",
    description="An authenticated user uploads a new media item.",
)

action(
    "user_read_media", "View media", "Read", "read_media", "CurrentUser",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("knowledge", KNOW_MEDIA, "Request carries the media friendly_token."),
                  req("existence", EXISTS_MEDIA, "Missing media returns 400 (observed).")],
    gen=[eff(KNOW_MEDIA, "io_reference", "Response returns the media detail and its token.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("output", "title / MediaTitle(media)", "observed_only", [], "Display attribute."),
                   io("output", "state / MediaState(media)", "observed_only", [], "Observed state, Read makes no state.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}"), ["GET"])],
    vis="black_box", vis_reason="Watch page fetches media detail.", reachable=True,
    reach_conds=["Public media: anyone; private: owner/member/editor."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "pub=200; private anon=400 user=200; missing=400")],
    confidence=0.95, reasoning="MediaDetail.get; 400 on missing confirms Exists precondition.",
    description="A viewer reads a single media item by token.",
    observable=[{"observer_l1_key": K("/api/v1/media/{friendly_token}"),
                 "expected": "200 with media detail for accessible media; 400 for missing/forbidden."}],
)

action(
    "owner_update_media", "Edit media", "Update", "update_media", "CurrentUser",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("authentication", AUTH, "Authenticated session/token."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Target must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA),
                      "Owner, media contributor, or editor only.")],
    gen=[eff(f_state(MEDIA, "title", "updated"), "state_transition", "Title/description replaced."),
         eff(f_state(MEDIA, "description", "updated"), "state_transition", "Description replaced.")],
    kill=[eff(f_state(MEDIA, "title", "previous"), "state_transition", "Previous title no longer holds.")],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "title / MediaTitle(media)", "object_attribute", [], "Updated value, not a precondition."),
                   io("input", "description / MediaDescription(media)", "object_attribute", [], "Updated value.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}"), ["PUT"])],
    vis="black_box", vis_reason="Owner edit form.", reachable=True,
    reach_conds=["Media owner, contributor, or editor."],
    evidence=[c.ev("source", "files/views/media.py:965-985", "PUT contributor/editor gate")],
    confidence=0.9, reasoning="MediaDetail.put updates title/description.",
    description="The media owner (or contributor/editor) edits a media's title and description.",
)

action(
    "owner_delete_media", "Delete media", "Delete", "delete_media", "CurrentUser",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Target must exist."),
                  req("authorization", f_can(ACTOR, "Delete", MEDIA), "Owner, contributor, or editor.")],
    gen=[], kill=[eff(EXISTS_MEDIA, "state_transition", "Media row and its files are removed.")],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)])],
    bindings=[bind(K("/api/v1/media/{friendly_token}"), ["DELETE"])],
    vis="black_box", vis_reason="Owner delete control.", reachable=True,
    reach_conds=["Media owner, contributor, or editor."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "DELETE missing user=400 (anon=403)")],
    confidence=0.9, reasoning="MediaDetail.delete removes the media.",
    description="The media owner (or contributor/editor) deletes a media item.",
)

action(
    "editor_encode_media", "Run encoding", "Update", "encode_media", "MediaEditor",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Target must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Editor/manager only.")],
    gen=[eff(f_state(MEDIA, "encoding_status", "pending"), "state_transition", "Encoding tasks queued.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "encoding_profiles / EncodeProfileID(profile)", "object_attribute", [], "Which profiles to encode."),
                   io("input", "type / encode", "object_attribute", [], "Discriminator value, not a fact.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}"), ["POST"], "type", ["encode"])],
    vis="black_box", vis_reason="Manager action menu on the media.", reachable=True,
    reach_conds=["Editor or manager."],
    evidence=[c.ev("source", "files/views/media.py:922-941", "encode branch")],
    confidence=0.85, reasoning="POST type=encode queues encoding.",
    description="An editor triggers (re)encoding of a media for selected profiles.",
)

action(
    "editor_review_media", "Review media", "Update", "review_media", "MediaEditor",
    obj("state", "media", "Media", "request", "friendly_token", "MediaToken(media)",
        state_field="is_reviewed"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Target must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Editor/manager only.")],
    gen=[eff(f_state(MEDIA, "is_reviewed", "true"), "state_transition", "Media marked reviewed.")],
    kill=[eff(f_state(MEDIA, "is_reviewed", "false"), "state_transition", "Prior unreviewed state cleared.")],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "result / ReviewResult(media)", "object_attribute", [], "Reviewed true/false value."),
                   io("input", "type / review", "object_attribute", [], "Discriminator value.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}"), ["POST"], "type", ["review"])],
    vis="black_box", vis_reason="Manager review toggle.", reachable=True,
    reach_conds=["Editor or manager."],
    evidence=[c.ev("source", "files/views/media.py:942-948", "review branch")],
    confidence=0.85, reasoning="POST type=review flips is_reviewed.",
    description="An editor marks a media reviewed or not reviewed.",
)

# ---- media actions endpoint (like/dislike/report/watch, reports, reset) ----
def media_action_post(akey, name, verb, desc, anon_ok):
    rc = ["Authenticated user."]
    if anon_ok:
        rc = ["Anonymous allowed (ALLOW_ANONYMOUS_ACTIONS) or authenticated user."]
    gen_fact = f_state(MEDIA, f"action_{verb}", "recorded")
    action(
        akey, name, "Create", verb + "_media", "CurrentUser",
        obj("state", "media", "Media", "request", "friendly_token", "MediaToken(media)",
            state_field=f"action_{verb}"),
        requirements=[req("knowledge", KNOW_MEDIA, "Target media token."),
                      req("existence", EXISTS_MEDIA, "Target must exist.")],
        gen=[eff(gen_fact, "action_semantics", f"A {verb} MediaAction is recorded for the media.")],
        kill=[],
        io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                       io("input", "type / " + verb, "object_attribute", [], "Action discriminator value."),
                       io("input", "extra_info / ReportReason(media)", "object_attribute", [],
                          "Report reason text (report only).")],
        bindings=[bind(K("/api/v1/media/{friendly_token}/actions"), ["POST"], "type", [verb])],
        vis="black_box", vis_reason="Media page action buttons.", reachable=True,
        reach_conds=rc,
        evidence=[c.ev("source", "files/views/media.py:1059-1086", "action dispatch"),
                  c.ev("runtime", "mediacms_gt/runtime_probe.txt", "POST no-type=400")],
        confidence=0.85, reasoning="MediaActions.post with type=" + verb,
        description=desc,
    )


media_action_post("user_like_media", "Like media", "like", "A user likes a media.", True)
media_action_post("user_dislike_media", "Dislike media", "dislike", "A user dislikes a media.", True)
media_action_post("user_report_media", "Report media", "report", "A user reports a media with a reason.", True)
media_action_post("user_watch_media", "Watch media", "watch", "A view/watch is recorded for a media.", True)

action(
    "owner_read_media_reports", "List media reports", "Read", "read_media_reports", "CurrentUser",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("authorization", f_can(ACTOR, "Read", MEDIA), "Owner or editor only.")],
    gen=[eff(f_know(ACTOR, reference("ReportReason", MEDIA)), "io_reference", "Returns report dates/reasons.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("output", "reported", "gen", [kf(f_know(ACTOR, reference("ReportReason", MEDIA)))])],
    bindings=[bind(K("/api/v1/media/{friendly_token}/actions"), ["GET"])],
    vis="black_box", vis_reason="Owner/editor report view.", reachable=True,
    reach_conds=["Media owner or editor."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET anon=400 owner=200")],
    confidence=0.85, reasoning="MediaActions.get lists reports.",
    description="The media owner or an editor reads who reported a media and why.",
)

action(
    "admin_reset_media_reports", "Reset media reports", "Update", "reset_media_reports", "Administrator",
    obj("state", "media", "Media", "request", "friendly_token", "MediaToken(media)", state_field="reported_times"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Superuser only.")],
    gen=[eff(f_state(MEDIA, "reported_times", "0"), "state_transition", "Report counter reset and reports removed.")],
    kill=[eff(f_state(MEDIA, "reported_times", "nonzero"), "state_transition", "Prior report count cleared.")],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "type / report", "object_attribute", [], "Only 'report' is accepted.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/actions"), ["DELETE"], "type", ["report"])],
    vis="black_box", vis_reason="Admin moderation.", reachable=True,
    reach_conds=["Superuser."],
    evidence=[c.ev("source", "files/views/media.py:1094-1113", "superuser reset")],
    confidence=0.85, reasoning="MediaActions.delete resets reports.",
    description="An administrator clears all reports of a media and resets its counter.",
)

# ---- comments ---------------------------------------------------------------
action(
    "user_read_media_comments", "List media comments", "Read", "read_media_comments", "CurrentUser",
    obj("entity", "comment", "Comment", "implicit", "", "CommentUID(comment)", role="collection",
        participants=[entity_p("media", "Media", "context",
                               {"source": "request", "field": "friendly_token", "resource": "MediaToken(media)"})]),
    requirements=[req("knowledge", KNOW_MEDIA, "Media token in path."),
                  req("existence", EXISTS_MEDIA, "Media must exist / be accessible.")],
    gen=[eff(f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "collection"))),
             "io_reference", "Returns comment uids/text.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("output", "uid / CommentUID(comment)", "gen",
                      [kf(f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "collection"))))]),
                   io("output", "text / CommentText(comment)", "observed_only", [], "Comment content; not a reference.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/comments"), ["GET"]),
              bind(K("/api/v1/media/{friendly_token}/comments/{uid}"), ["GET"])],
    vis="black_box", vis_reason="Comments widget on media page.", reachable=True,
    reach_conds=["Same access as viewing the media."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
    confidence=0.9, reasoning="CommentDetail.get paginates a media's comments.",
    description="A viewer lists the comments of a media.",
)

action(
    "user_create_comment", "Add comment", "Create", "create_comment", "CurrentUser",
    obj("entity", "comment", "Comment", "response", "uid", "CommentUID(comment)", role="created",
        participants=[entity_p("media", "Media", "context",
                               {"source": "request", "field": "friendly_token", "resource": "MediaToken(media)"})]),
    requirements=[req("authentication", AUTH, "Authenticated and allowed to comment."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Media must exist and have comments enabled.")],
    gen=[eff(f_exists(entity("comment", "Comment", "created")), "action_semantics", "A new Comment is created."),
         eff(f_relation(entity("comment", "Comment", "created"), MEDIA, "OnMedia"), "relation_transition",
             "Comment attached to the media.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "text / CommentText(comment)", "object_attribute", [], "New comment content."),
                   io("input", "parent / CommentParent(comment)", "object_attribute", [], "Optional parent for threading.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/comments"), ["POST"])],
    vis="black_box", vis_reason="Comment box submit.", reachable=True,
    reach_conds=["Authenticated; CAN_COMMENT=all; comments enabled on the media."],
    evidence=[c.ev("source", "files/views/comments.py:141-162", "POST create")],
    confidence=0.9, reasoning="CommentDetail.post creates a comment.",
    description="An authenticated user posts a comment on a media.",
)

action(
    "author_delete_own_comment", "Delete own comment", "Delete", "delete_comment", "CurrentUser",
    obj("entity", "comment", "Comment", "request", "uid", "CommentUID(comment)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))),
                      "Comment uid in path."),
                  req("existence", f_exists(entity("comment", "Comment", "target")), "Comment must exist."),
                  req("authorization", f_can(ACTOR, "Delete", entity("comment", "Comment", "target")),
                      "Comment author.")],
    gen=[], kill=[eff(f_exists(entity("comment", "Comment", "target")), "state_transition", "Comment removed.")],
    io_accounting=[io("input", "uid / CommentUID(comment)", "req",
                      [kf(f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))))])],
    bindings=[bind(K("/api/v1/media/{friendly_token}/comments/{uid}"), ["DELETE"])],
    vis="black_box", vis_reason="Delete control on a user's own comment.", reachable=True,
    reach_conds=["Comment author."],
    evidence=[c.ev("source", "files/views/comments.py:116-133", "author branch")],
    confidence=0.85, reasoning="CommentDetail.delete allows the author.",
    description="A user deletes their own comment.",
)

action(
    "moderator_delete_comment", "Moderate comment", "Delete", "delete_comment", "MediaEditor",
    obj("entity", "comment", "Comment", "request", "uid", "CommentUID(comment)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))),
                      "Comment uid in path."),
                  req("existence", f_exists(entity("comment", "Comment", "target")), "Comment must exist."),
                  req("authorization", f_can(ACTOR, "Delete", entity("comment", "Comment", "target")),
                      "Media owner or MediaCMS editor/manager/admin.")],
    gen=[], kill=[eff(f_exists(entity("comment", "Comment", "target")), "state_transition", "Comment removed.")],
    io_accounting=[io("input", "uid / CommentUID(comment)", "req",
                      [kf(f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))))])],
    bindings=[bind(K("/api/v1/media/{friendly_token}/comments/{uid}"), ["DELETE"])],
    vis="black_box", vis_reason="Moderation delete by media owner/editor.", reachable=True,
    reach_conds=["Media owner, or MediaCMS editor/manager/admin."],
    evidence=[c.ev("source", "files/views/comments.py:116-133", "owner/editor branch")],
    confidence=0.85, reasoning="Same handler, distinct permission context (moderation).",
    description="A media owner or editor deletes someone else's comment (moderation).",
)

# ---- share / chapters / trim / pdf -----------------------------------------
action(
    "owner_share_media", "Share media to course", "Create", "share_media", "CurrentUser",
    obj("relation", "mediapermission", "MediaPermission", "subject", "", "MediaToken(media)", role="created",
        participants=[entity_p("media", "Media", "target",
                               {"source": "request", "field": "friendly_token", "resource": "MediaToken(media)"}),
                      principal_p("actor", "User", "owner", "SELF")]),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Media must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Media owner only.")],
    gen=[eff(f_relation(ACTOR, MEDIA, "Owner"), "relation_transition", "Owner MediaPermission created (marks shared).")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "courseid", "object_attribute", [], "Optional LTI context id.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/share"), ["POST"])],
    vis="black_box", vis_reason="LTI plugin embed/share.", reachable=True,
    reach_conds=["Authenticated media owner."],
    evidence=[c.ev("source", "files/views/media.py:1251-1274", "owner-only share")],
    confidence=0.8, reasoning="media_share creates owner permission.",
    description="A media owner marks a media shared (for the LTI embed plugin).",
)

action(
    "contributor_set_media_chapters", "Set chapters", "Update", "set_media_chapters", "CurrentUser",
    obj("state", "media", "Media", "request", "friendly_token", "MediaToken(media)", state_field="chapter_data"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Media must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Editor or media contributor.")],
    gen=[eff(f_state(MEDIA, "chapter_data", "replaced"), "state_transition", "Chapter set replaced.")],
    kill=[eff(f_state(MEDIA, "chapter_data", "previous"), "state_transition", "Previous chapters cleared.")],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("input", "chapters / MediaChapters(media)", "object_attribute", [], "New chapter markers.")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/chapters"), ["POST"])],
    vis="black_box", vis_reason="Chapter editor.", reachable=True,
    reach_conds=["Editor or media contributor."],
    evidence=[c.ev("source", "files/views/pages.py:301-358", "chapters handler")],
    confidence=0.8, reasoning="video_chapters replaces chapters.",
    description="An editor/contributor sets a video's chapter markers.",
)

action(
    "contributor_trim_video", "Trim video", "Create", "trim_video", "CurrentUser",
    obj("entity", "trimrequest", "VideoTrimRequest", "response", "request_id", "TrimRequestID(trimrequest)",
        role="created",
        participants=[entity_p("media", "Media", "target",
                               {"source": "request", "field": "friendly_token", "resource": "MediaToken(media)"})]),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", KNOW_MEDIA, "Target media token."),
                  req("existence", EXISTS_MEDIA, "Media must exist."),
                  req("authorization", f_can(ACTOR, "Update", MEDIA), "Editor or media contributor.")],
    gen=[eff(f_exists(entity("trimrequest", "VideoTrimRequest", "created")), "action_semantics",
             "A VideoTrimRequest is queued.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("output", "request_id", "observed_only", [], "Queued trim-request id (not reused as a GT reference).")],
    bindings=[bind(K("/api/v1/media/{friendly_token}/trim_video"), ["POST"])],
    vis="black_box", vis_reason="Video trimmer tool.", reachable=True,
    reach_conds=["Editor or media contributor.", "ALLOW_VIDEO_TRIMMER enabled."],
    evidence=[c.ev("source", "files/views/pages.py:542-570", "trim handler")],
    confidence=0.8, reasoning="trim_video queues a trim request.",
    description="An editor/contributor queues a video trim job.",
)

action(
    "user_read_media_pdf", "Download media PDF", "Read", "read_media_pdf", "CurrentUser",
    obj("entity", "media", "Media", "request", "friendly_token", "MediaToken(media)"),
    requirements=[req("knowledge", KNOW_MEDIA, "Target media token (pdf)."),
                  req("existence", EXISTS_MEDIA, "PDF media must exist."),
                  req("authorization", f_can(ACTOR, "Read", MEDIA), "Public, or owner/member/editor for private.")],
    gen=[eff(f_know(ACTOR, reference("MediaFile", MEDIA)), "io_reference", "Streams the pdf file.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
                   io("output", "pdf", "gen", [kf(f_know(ACTOR, reference("MediaFile", MEDIA)))])],
    bindings=[bind(K("/api/v1/media/{friendly_token}/pdf"), ["GET"])],
    vis="black_box", vis_reason="PDF viewer embeds this.", reachable=True,
    reach_conds=["media_type=pdf; public: any; private: owner/member/editor."],
    evidence=[c.ev("source", "files/views/media_auth.py:215-233", "access check")],
    confidence=0.8, reasoning="view_pdf streams the original.",
    description="A viewer downloads/streams a PDF media file.",
)

# ---- bulk user actions (discriminator-split) -------------------------------
def bulk(akey, value, name, crud, business, gen, kill, desc, extra_in=None):
    ios = [io("input", "media_ids / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
           io("input", "action / " + value, "object_attribute", [], "Bulk action discriminator value.")]
    for fld, reason in (extra_in or []):
        ios.append(io("input", fld, "object_attribute", [], reason))
    action(
        akey, name, crud, business, "CurrentUser",
        obj("entity", "media", "Media", "request", "media_ids", "MediaToken(media)", role="collection"),
        requirements=[req("authentication", AUTH, "IsAuthenticated; acts only on the caller's own media."),
                      req("knowledge", KNOW_MEDIA, "media_ids select the caller's media."),
                      req("existence", EXISTS_MEDIA, "Selected media must exist and be owned by caller.")],
        gen=gen, kill=kill, io_accounting=ios,
        bindings=[bind(K("/api/v1/media/user/bulk_actions"), ["POST"], "action", [value])],
        vis="black_box", vis_reason="'My media' bulk toolbar.", reachable=True,
        reach_conds=["Authenticated; media owned by the caller."],
        evidence=[c.ev("source", "files/views/media.py:413-754", "bulk dispatch value=" + value),
                  c.ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403 user no-ids=400")],
        confidence=0.8, reasoning="MediaBulkUserActions action=" + value, description=desc,
    )


PLAYLIST = entity("playlist", "Playlist", "target")
CATEGORY = entity("category", "Category", "target")
TAG = entity("tag", "Tag", "target")
NEWOWNER = principal_p("new_owner", "User", "new_owner", "PEER")

bulk("user_bulk_enable_comments", "enable_comments", "Bulk enable comments", "Update", "enable_comments",
     [eff(f_state(MEDIA, "comments_enabled", "true"), "state_transition", "Comments enabled.")],
     [eff(f_state(MEDIA, "comments_enabled", "false"), "state_transition", "Prior disabled state cleared.")],
     "Owner enables comments on several of their media.")
bulk("user_bulk_disable_comments", "disable_comments", "Bulk disable comments", "Update", "disable_comments",
     [eff(f_state(MEDIA, "comments_enabled", "false"), "state_transition", "Comments disabled.")],
     [eff(f_state(MEDIA, "comments_enabled", "true"), "state_transition", "Prior enabled state cleared.")],
     "Owner disables comments on several of their media.")
bulk("user_bulk_delete_comments", "delete_comments", "Bulk delete comments", "Delete", "delete_media_comments",
     [], [eff(f_relation(entity("comment", "Comment", "target"), MEDIA, "OnMedia"), "relation_transition",
             "All comments of the selected media are removed.")],
     "Owner deletes all comments on several of their media.")
bulk("user_bulk_delete_media", "delete_media", "Bulk delete media", "Delete", "delete_media",
     [], [eff(EXISTS_MEDIA, "state_transition", "Selected media deleted.")],
     "Owner deletes several of their media.")
bulk("user_bulk_enable_download", "enable_download", "Bulk enable download", "Update", "enable_download",
     [eff(f_state(MEDIA, "download_allowed", "true"), "state_transition", "Download enabled.")],
     [eff(f_state(MEDIA, "download_allowed", "false"), "state_transition", "Prior state cleared.")],
     "Owner enables download on several of their media.")
bulk("user_bulk_disable_download", "disable_download", "Bulk disable download", "Update", "disable_download",
     [eff(f_state(MEDIA, "download_allowed", "false"), "state_transition", "Download disabled.")],
     [eff(f_state(MEDIA, "download_allowed", "true"), "state_transition", "Prior state cleared.")],
     "Owner disables download on several of their media.")
bulk("user_bulk_set_state", "set_state", "Bulk set media state", "Update", "set_media_state",
     [eff(f_state(MEDIA, "visibility", "new"), "state_transition", "State set to the requested value.")],
     [eff(f_state(MEDIA, "visibility", "previous"), "state_transition", "Prior state cleared.")],
     "Owner changes the visibility state of several media.",
     extra_in=[("state / MediaState(media)", "New visibility value."),
               ("remove_sharing", "Optionally strips sharing.")])
bulk("user_bulk_change_owner", "change_owner", "Bulk change owner", "Update", "change_media_owner",
     [eff(f_relation(MEDIA, NEWOWNER, "Owner"), "relation_transition", "Ownership transferred to new owner.")],
     [eff(f_relation(MEDIA, ACTOR, "Owner"), "relation_transition", "Previous ownership relation removed.")],
     "Owner transfers ownership of several media to another user.",
     extra_in=[("owner / Username(user)", "New owner username.")])
bulk("user_bulk_copy_media", "copy_media", "Bulk copy media", "Create", "copy_media",
     [eff(f_exists(entity("media_copy", "Media", "created")), "action_semantics", "Copies created.")],
     [], "Owner duplicates several media.")
bulk("user_bulk_add_to_playlist", "add_to_playlist", "Bulk add to playlist", "Create", "add_media_to_playlist",
     [eff(f_relation(MEDIA, PLAYLIST, "InPlaylist"), "relation_transition", "Media added to playlists.")],
     [], "Owner adds several media to playlists.",
     extra_in=[("playlist_ids / PlaylistID(playlist)", "Target playlist ids.")])
bulk("user_bulk_remove_from_playlist", "remove_from_playlist", "Bulk remove from playlist", "Delete",
     "remove_media_from_playlist", [],
     [eff(f_relation(MEDIA, PLAYLIST, "InPlaylist"), "relation_transition", "Media removed from playlists.")],
     "Owner removes several media from playlists.",
     extra_in=[("playlist_ids / PlaylistID(playlist)", "Target playlist ids.")])
bulk("user_bulk_set_ownership", "set_ownership", "Bulk grant ownership", "Create", "set_media_ownership",
     [eff(f_relation(principal_p("grantee", "User", "grantee", "PEER"), MEDIA, "Permission"),
          "relation_transition", "MediaPermission granted to users.")],
     [], "Owner grants viewer/editor/owner permission on media to users.",
     extra_in=[("users / Username(user)", "Grantee usernames."),
               ("ownership_type / OwnershipType(permission)", "viewer/editor/owner.")])
bulk("user_bulk_remove_ownership", "remove_ownership", "Bulk revoke ownership", "Delete", "remove_media_ownership",
     [], [eff(f_relation(principal_p("grantee", "User", "grantee", "PEER"), MEDIA, "Permission"),
             "relation_transition", "MediaPermission revoked.")],
     "Owner revokes permission on media from users.",
     extra_in=[("users / Username(user)", "Grantee usernames."),
               ("ownership_type / OwnershipType(permission)", "viewer/editor/owner.")])
bulk("user_bulk_add_to_category", "add_to_category", "Bulk add to category", "Create", "add_media_to_category",
     [eff(f_relation(MEDIA, CATEGORY, "InCategory"), "relation_transition", "Media added to categories.")],
     [], "Owner adds several media to categories.",
     extra_in=[("category_uids / CategoryUID(category)", "Target category uids.")])
bulk("user_bulk_remove_from_category", "remove_from_category", "Bulk remove from category", "Delete",
     "remove_media_from_category", [],
     [eff(f_relation(MEDIA, CATEGORY, "InCategory"), "relation_transition", "Media removed from categories.")],
     "Owner removes several media from categories.",
     extra_in=[("category_uids / CategoryUID(category)", "Target category uids.")])
bulk("user_bulk_add_tags", "add_tags", "Bulk add tags", "Create", "add_media_tags",
     [eff(f_relation(MEDIA, TAG, "Tagged"), "relation_transition", "Tags attached to media.")],
     [], "Owner tags several media.",
     extra_in=[("tag_titles / TagTitle(tag)", "Tag titles to add.")])
bulk("user_bulk_remove_tags", "remove_tags", "Bulk remove tags", "Delete", "remove_media_tags",
     [], [eff(f_relation(MEDIA, TAG, "Tagged"), "relation_transition", "Tags removed from media.")],
     "Owner untags several media.",
     extra_in=[("tag_titles / TagTitle(tag)", "Tag titles to remove.")])
bulk("user_bulk_course_cleanup", "course_cleanup", "Course cleanup", "Delete", "course_cleanup",
     [], [eff(f_relation(MEDIA, CATEGORY, "InCategory"), "relation_transition",
             "Course media detached and their permissions/comments optionally removed.")],
     "A course contributor cleans up a course's media, permissions and comments.",
     extra_in=[("category_uids / CategoryUID(category)", "Course category uids."),
               ("remove_permissions", "Whether to strip permissions."),
               ("remove_comments", "Whether to strip comments.")])

# membership/ownership READ queries (Know effects)
def bulk_read(akey, value, name, business, ref_type, ref_entity, desc, extra_in=None):
    ios = [io("input", "media_ids / MediaToken(media)", "req", [kf(KNOW_MEDIA)]),
           io("input", "action / " + value, "object_attribute", [], "Bulk query discriminator.")]
    for fld, reason in (extra_in or []):
        ios.append(io("input", fld, "object_attribute", [], reason))
    gfact = f_know(ACTOR, reference(ref_type, ref_entity))
    ios.append(io("output", "results", "gen", [kf(gfact)]))
    action(
        akey, name, "Read", business, "CurrentUser",
        obj("entity", "media", "Media", "request", "media_ids", "MediaToken(media)", role="collection"),
        requirements=[req("authentication", AUTH, "IsAuthenticated; caller's own media."),
                      req("knowledge", KNOW_MEDIA, "media_ids select the caller's media.")],
        gen=[eff(gfact, "io_reference", "Returns the shared memberships/owners of the selection.")],
        kill=[], io_accounting=ios,
        bindings=[bind(K("/api/v1/media/user/bulk_actions"), ["POST"], "action", [value])],
        vis="black_box", vis_reason="'My media' bulk info query.", reachable=True,
        reach_conds=["Authenticated; media owned by the caller."],
        evidence=[c.ev("source", "files/views/media.py:555-653", "bulk read value=" + value)],
        confidence=0.75, reasoning="MediaBulkUserActions read query action=" + value, description=desc,
    )


bulk_read("user_bulk_get_ownership", "get_ownership", "Query shared owners", "query_media_ownership",
          "Username", entity("grantee", "User", "grantee"),
          "Owner lists users who share a permission across all selected media.",
          extra_in=[("ownership_type / OwnershipType(permission)", "viewer/editor/owner.")])
bulk_read("user_bulk_playlist_membership", "playlist_membership", "Query playlist membership",
          "query_playlist_membership", "PlaylistToken", PLAYLIST,
          "Owner lists playlists containing all selected media.")
bulk_read("user_bulk_category_membership", "category_membership", "Query category membership",
          "query_category_membership", "CategoryUID", CATEGORY,
          "Owner lists categories containing all selected media.")
bulk_read("user_bulk_tag_membership", "tag_membership", "Query tag membership",
          "query_tag_membership", "TagTitle", TAG,
          "Owner lists tags on all selected media.")

# ---- search -----------------------------------------------------------------
action(
    "user_search_media", "Search media", "Read", "search_media", "CurrentUser",
    obj("entity", "media", "Media", "implicit", "", "MediaToken(media)", role="collection"),
    requirements=[],
    gen=[eff(KNOW_MEDIA, "io_reference", "Returns matching media and their tokens.")],
    kill=[],
    io_accounting=[io("output", "friendly_token / MediaToken(media)", "gen", [kf(KNOW_MEDIA)]),
                   io("input", "q", "object_attribute", [], "Free-text query, not a reference."),
                   io("input", "author / Username(user)", "object_attribute", [], "Author filter.")],
    bindings=[bind(K("/api/v1/search"), ["GET"])],
    vis="black_box", vis_reason="Search box.", reachable=True,
    reach_conds=["Public; scope limited to what the identity may see."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "q=clip 200")],
    confidence=0.9, reasoning="MediaSearch.get full-text search.",
    description="A visitor searches media by text/category/tag/author.",
)

# ---- simple reads (categories/tags/comments/profiles/user actions) ---------
def simple_read(akey, name, business, l1key, ref_type, ref_entity_type, ref_role, desc,
                subject="CurrentUser", reqs=None, reach=None, confirmed_ref="runtime"):
    e = entity(ref_entity_type.lower(), ref_entity_type, ref_role)
    gfact = f_know(ACTOR, reference(ref_type, e))
    action(
        akey, name, "Read", business, subject,
        obj("entity", ref_entity_type.lower(), ref_entity_type, "implicit", "", ref_type + "(" + ref_entity_type.lower() + ")",
            role="collection"),
        requirements=reqs or [],
        gen=[eff(gfact, "io_reference", "Returns " + ref_entity_type + " references.")],
        kill=[],
        io_accounting=[io("output", ref_type, "gen", [kf(gfact)])],
        bindings=[bind(K(l1key), ["GET"])],
        vis="black_box", vis_reason="Listing/detail page.", reachable=True,
        reach_conds=reach or ["Public read."],
        evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
        confidence=0.9, reasoning="Read endpoint.", description=desc,
    )


simple_read("user_list_categories", "List categories", "list_categories", "/api/v1/categories",
            "CategoryUID", "Category", "collection", "A visitor lists categories.")
simple_read("user_read_category", "Read category", "read_category", "/api/v1/categories/{uid}",
            "CategoryUID", "Category", "target", "A visitor reads one category.")
simple_read("contributor_list_courses", "List contributor courses", "list_contributor_courses",
            "/api/v1/categories/contributor", "CategoryUID", "Category", "collection",
            "A contributor lists LMS courses they may contribute to.",
            reqs=[req("authentication", AUTH, "Authenticated for non-empty results.")],
            reach=["Authenticated contributor; anonymous gets []."])
simple_read("user_list_tags", "List tags", "list_tags", "/api/v1/tags",
            "TagTitle", "Tag", "collection", "A visitor lists tags.")
simple_read("user_list_comments", "List comments", "list_comments", "/api/v1/comments",
            "CommentUID", "Comment", "collection", "A visitor lists recent comments on public media.")
simple_read("anon_list_encode_profiles", "List encode profiles", "list_encode_profiles",
            "/api/v1/encode_profiles/", "EncodeProfileName", "Profile", "collection",
            "Anyone lists encoding profiles (no permission class).", subject="Anonymous")
simple_read("user_list_action_media", "List acted-on media", "list_user_action_media",
            "/api/v1/user/action/{action}", "MediaToken", "Media", "collection",
            "A user lists media they liked/disliked/watched/reported.",
            reach=["Authenticated for user scope; anonymous uses session."])

# ---- playlists --------------------------------------------------------------
action(
    "user_list_playlists", "List playlists", "Read", "list_playlists", "CurrentUser",
    obj("entity", "playlist", "Playlist", "implicit", "", "PlaylistToken(playlist)", role="collection"),
    requirements=[],
    gen=[eff(f_know(ACTOR, reference("PlaylistToken", entity("playlist", "Playlist", "collection"))),
             "io_reference", "Returns playlist tokens.")],
    kill=[],
    io_accounting=[io("output", "friendly_token / PlaylistToken(playlist)", "gen",
                      [kf(f_know(ACTOR, reference("PlaylistToken", entity("playlist", "Playlist", "collection"))))])],
    bindings=[bind(K("/api/v1/playlists"), ["GET"])],
    vis="black_box", vis_reason="Playlists page.", reachable=True, reach_conds=["Public read."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
    confidence=0.9, reasoning="PlaylistList.get.", description="A visitor lists playlists.",
)

action(
    "user_create_playlist", "Create playlist", "Create", "create_playlist", "CurrentUser",
    obj("entity", "playlist", "Playlist", "response", "friendly_token", "PlaylistToken(playlist)", role="created"),
    requirements=[req("authentication", AUTH, "IsAuthenticated.")],
    gen=[eff(f_exists(entity("playlist", "Playlist", "created")), "action_semantics", "Playlist created."),
         eff(f_know(ACTOR, reference("PlaylistToken", entity("playlist", "Playlist", "created"))),
             "io_reference", "Returns the created playlist token.")],
    kill=[],
    io_accounting=[io("input", "title / PlaylistTitle(playlist)", "object_attribute", [], "New content."),
                   io("output", "friendly_token / PlaylistToken(playlist)", "gen",
                      [kf(f_know(ACTOR, reference("PlaylistToken", entity("playlist", "Playlist", "created"))))])],
    bindings=[bind(K("/api/v1/playlists"), ["POST"])],
    vis="black_box", vis_reason="Create-playlist form.", reachable=True, reach_conds=["Authenticated."],
    evidence=[c.ev("source", "files/views/playlists.py:53-64", "create")],
    confidence=0.9, reasoning="PlaylistList.post.", description="A user creates a playlist.",
)

PLAYLIST_T = entity("playlist", "Playlist", "target")
KNOW_PL = f_know(ACTOR, reference("PlaylistToken", PLAYLIST_T))
EXISTS_PL = f_exists(PLAYLIST_T)

action(
    "user_read_playlist", "View playlist", "Read", "read_playlist", "CurrentUser",
    obj("entity", "playlist", "Playlist", "request", "friendly_token", "PlaylistToken(playlist)"),
    requirements=[req("knowledge", KNOW_PL, "Playlist token in path."), req("existence", EXISTS_PL, "Playlist must exist.")],
    gen=[eff(KNOW_PL, "io_reference", "Returns playlist + visible member media.")],
    kill=[],
    io_accounting=[io("input", "friendly_token / PlaylistToken(playlist)", "req", [kf(KNOW_PL)])],
    bindings=[bind(K("/api/v1/playlists/{friendly_token}"), ["GET"])],
    vis="black_box", vis_reason="Playlist page.", reachable=True, reach_conds=["Public read."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
    confidence=0.9, reasoning="PlaylistDetail.get.", description="A visitor views a playlist and its media.",
)

action(
    "owner_update_playlist", "Edit playlist", "Update", "update_playlist", "CurrentUser",
    obj("state", "playlist", "Playlist", "request", "friendly_token", "PlaylistToken(playlist)", state_field="title"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_PL, "Playlist token."),
                  req("existence", EXISTS_PL, "Playlist must exist."),
                  req("authorization", f_can(ACTOR, "Update", PLAYLIST_T), "Owner or editor.")],
    gen=[eff(f_state(PLAYLIST_T, "title", "updated"), "state_transition", "Title/description updated.")],
    kill=[eff(f_state(PLAYLIST_T, "title", "previous"), "state_transition", "Previous title cleared.")],
    io_accounting=[io("input", "friendly_token / PlaylistToken(playlist)", "req", [kf(KNOW_PL)]),
                   io("input", "title / PlaylistTitle(playlist)", "object_attribute", [], "Updated value.")],
    bindings=[bind(K("/api/v1/playlists/{friendly_token}"), ["POST"])],
    vis="black_box", vis_reason="Owner edit.", reachable=True, reach_conds=["Owner or editor."],
    evidence=[c.ev("source", "files/views/playlists.py:120-134", "post edit")],
    confidence=0.85, reasoning="PlaylistDetail.post.", description="The owner edits a playlist's title/description.",
)

def playlist_put(akey, value, name, crud, business, gen, kill, desc):
    action(
        akey, name, crud, business, "CurrentUser",
        obj("relation", "playlistmedia", "PlaylistMedia", "request", "media_friendly_token", "MediaToken(media)",
            role="target",
            participants=[entity_p("playlist", "Playlist", "target",
                                   {"source": "request", "field": "friendly_token", "resource": "PlaylistToken(playlist)"}),
                          entity_p("media", "Media", "member",
                                   {"source": "request", "field": "media_friendly_token", "resource": "MediaToken(media)"})]),
        requirements=[req("authentication", AUTH, "Authenticated."),
                      req("knowledge", KNOW_PL, "Playlist token in path."),
                      req("knowledge", f_know(ACTOR, reference("MediaToken", entity("media", "Media", "member"))),
                          "media_friendly_token identifies the media."),
                      req("existence", EXISTS_PL, "Playlist must exist."),
                      req("authorization", f_can(ACTOR, "Update", PLAYLIST_T), "Owner or editor.")],
        gen=gen, kill=kill,
        io_accounting=[io("input", "friendly_token / PlaylistToken(playlist)", "req", [kf(KNOW_PL)]),
                       io("input", "media_friendly_token / MediaToken(media)", "req",
                          [kf(f_know(ACTOR, reference("MediaToken", entity("media", "Media", "member"))))]),
                       io("input", "type / " + value, "object_attribute", [], "PUT action discriminator."),
                       io("input", "ordering / PlaylistOrdering(playlist)", "object_attribute", [], "Position (ordering only).")],
        bindings=[bind(K("/api/v1/playlists/{friendly_token}"), ["PUT"], "type", [value])],
        vis="black_box", vis_reason="Playlist editor.", reachable=True, reach_conds=["Owner or editor."],
        evidence=[c.ev("source", "files/views/playlists.py:142-196", "put type=" + value)],
        confidence=0.85, reasoning="PlaylistDetail.put type=" + value, description=desc,
    )


MEDIA_MEMBER = entity("media", "Media", "member")
playlist_put("owner_add_media_to_playlist", "add", "Add media to playlist", "Create", "add_media_to_playlist",
             [eff(f_relation(MEDIA_MEMBER, PLAYLIST_T, "InPlaylist"), "relation_transition", "Media added.")],
             [], "The owner adds a media to a playlist.")
playlist_put("owner_remove_media_from_playlist", "remove", "Remove media from playlist", "Delete",
             "remove_media_from_playlist", [],
             [eff(f_relation(MEDIA_MEMBER, PLAYLIST_T, "InPlaylist"), "relation_transition", "Media removed.")],
             "The owner removes a media from a playlist.")
playlist_put("owner_reorder_playlist", "ordering", "Reorder playlist media", "Update", "reorder_playlist_media",
             [eff(f_state(PLAYLIST_T, "ordering", "updated"), "state_transition", "Media position updated.")],
             [eff(f_state(PLAYLIST_T, "ordering", "previous"), "state_transition", "Previous order cleared.")],
             "The owner reorders a media within a playlist.")

action(
    "owner_delete_playlist", "Delete playlist", "Delete", "delete_playlist", "CurrentUser",
    obj("entity", "playlist", "Playlist", "request", "friendly_token", "PlaylistToken(playlist)"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_PL, "Playlist token."),
                  req("existence", EXISTS_PL, "Playlist must exist."),
                  req("authorization", f_can(ACTOR, "Delete", PLAYLIST_T), "Owner or editor.")],
    gen=[], kill=[eff(EXISTS_PL, "state_transition", "Playlist removed.")],
    io_accounting=[io("input", "friendly_token / PlaylistToken(playlist)", "req", [kf(KNOW_PL)])],
    bindings=[bind(K("/api/v1/playlists/{friendly_token}"), ["DELETE"])],
    vis="black_box", vis_reason="Owner delete.", reachable=True, reach_conds=["Owner or editor."],
    evidence=[c.ev("source", "files/views/playlists.py:198-210", "delete")],
    confidence=0.85, reasoning="PlaylistDetail.delete.", description="The owner deletes a playlist.",
)

# ---- management (editor/manager) -------------------------------------------
action(
    "editor_list_all_media", "Manage media listing", "Read", "list_all_media", "MediaEditor",
    obj("entity", "media", "Media", "implicit", "", "MediaToken(media)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Read", MEDIA), "Editor/manager/admin.")],
    gen=[eff(KNOW_MEDIA, "io_reference", "Returns all media tokens for moderation.")],
    kill=[],
    io_accounting=[io("output", "friendly_token / MediaToken(media)", "gen", [kf(KNOW_MEDIA)])],
    bindings=[bind(K("/api/v1/manage_media"), ["GET"])],
    vis="black_box", vis_reason="Admin manage-media page.", reachable=True, reach_conds=["Editor/manager/admin."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
    confidence=0.9, reasoning="management_views.MediaList.get.", description="An editor lists all media.",
)

action(
    "manager_bulk_delete_media", "Manage: delete media", "Delete", "bulk_delete_media", "MediaManager",
    obj("entity", "media", "Media", "query", "tokens", "MediaToken(media)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("MediaToken", MEDIA)), "tokens select media."),
                  req("authorization", f_can(ACTOR, "Delete", MEDIA), "Manager/admin only.")],
    gen=[], kill=[eff(EXISTS_MEDIA, "state_transition", "Selected media deleted.")],
    io_accounting=[io("input", "tokens / MediaToken(media)", "req", [kf(f_know(ACTOR, reference("MediaToken", MEDIA)))])],
    bindings=[bind(K("/api/v1/manage_media"), ["DELETE"])],
    vis="black_box", vis_reason="Admin manage-media delete.", reachable=True, reach_conds=["Manager/admin."],
    evidence=[c.ev("source", "files/management_views.py:120-133", "manager delete")],
    confidence=0.85, reasoning="management MediaList.delete.", description="A manager bulk-deletes media.",
)

COMMENT_C = entity("comment", "Comment", "collection")
action(
    "editor_list_all_comments", "Manage comments listing", "Read", "list_all_comments", "MediaEditor",
    obj("entity", "comment", "Comment", "implicit", "", "CommentUID(comment)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Read", COMMENT_C), "Editor/manager/admin.")],
    gen=[eff(f_know(ACTOR, reference("CommentUID", COMMENT_C)), "io_reference", "All comment uids.")],
    kill=[],
    io_accounting=[io("output", "uid / CommentUID(comment)", "gen",
                      [kf(f_know(ACTOR, reference("CommentUID", COMMENT_C)))])],
    bindings=[bind(K("/api/v1/manage_comments"), ["GET"])],
    vis="black_box", vis_reason="Admin manage-comments page.", reachable=True, reach_conds=["Editor/manager/admin."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
    confidence=0.9, reasoning="management CommentList.get.", description="An editor lists all comments.",
)

action(
    "editor_bulk_delete_comments", "Manage: delete comments", "Delete", "bulk_delete_comments", "MediaEditor",
    obj("entity", "comment", "Comment", "query", "comment_ids", "CommentUID(comment)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))),
                      "comment_ids select comments."),
                  req("authorization", f_can(ACTOR, "Delete", entity("comment", "Comment", "target")),
                      "Editor/manager/admin.")],
    gen=[], kill=[eff(f_exists(entity("comment", "Comment", "target")), "state_transition", "Comments deleted.")],
    io_accounting=[io("input", "comment_ids / CommentUID(comment)", "req",
                      [kf(f_know(ACTOR, reference("CommentUID", entity("comment", "Comment", "target"))))])],
    bindings=[bind(K("/api/v1/manage_comments"), ["DELETE"])],
    vis="black_box", vis_reason="Admin manage-comments delete.", reachable=True, reach_conds=["Editor/manager/admin."],
    evidence=[c.ev("source", "files/management_views.py:177-188", "editor delete")],
    confidence=0.85, reasoning="management CommentList.delete.", description="An editor bulk-deletes comments.",
)

USER_C = entity("user", "User", "collection")
USER_T = entity("user", "User", "target")
KNOW_USER = f_know(ACTOR, reference("Username", USER_T))
EXISTS_USER = f_exists(USER_T)

action(
    "editor_list_all_users", "Manage users listing", "Read", "list_all_users", "MediaEditor",
    obj("entity", "user", "User", "implicit", "", "Username(user)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Read", USER_C), "Editor/manager/admin.")],
    gen=[eff(f_know(ACTOR, reference("Username", USER_C)), "io_reference", "All usernames.")],
    kill=[],
    io_accounting=[io("output", "username / Username(user)", "gen",
                      [kf(f_know(ACTOR, reference("Username", USER_C)))])],
    bindings=[bind(K("/api/v1/manage_users"), ["GET"])],
    vis="black_box", vis_reason="Admin manage-users page.", reachable=True, reach_conds=["Editor/manager/admin."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
    confidence=0.9, reasoning="management UserList.get.", description="An editor lists all users.",
)

action(
    "manager_bulk_delete_users", "Manage: delete users", "Delete", "bulk_delete_users", "MediaManager",
    obj("entity", "user", "User", "query", "tokens", "Username(user)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("Username", USER_T)), "tokens select usernames."),
                  req("authorization", f_can(ACTOR, "Delete", USER_T), "Manager/admin; only admin may delete a superuser.")],
    gen=[], kill=[eff(EXISTS_USER, "state_transition", "Selected users deleted.")],
    io_accounting=[io("input", "tokens / Username(user)", "req", [kf(f_know(ACTOR, reference("Username", USER_T)))])],
    bindings=[bind(K("/api/v1/manage_users"), ["DELETE"])],
    vis="black_box", vis_reason="Admin manage-users delete.", reachable=True, reach_conds=["Manager/admin."],
    evidence=[c.ev("source", "files/management_views.py:246-262", "manager delete")],
    confidence=0.85, reasoning="management UserList.delete.", description="A manager bulk-deletes users.",
)

action(
    "admin_list_tasks", "List tasks", "Read", "list_tasks", "Administrator",
    obj("entity", "task", "Task", "implicit", "", "TaskID(task)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Read", entity("task", "Task", "collection")), "is_staff/admin.")],
    gen=[eff(f_know(ACTOR, reference("TaskID", entity("task", "Task", "collection"))), "io_reference", "Active tasks.")],
    kill=[],
    io_accounting=[io("output", "tasks", "gen",
                      [kf(f_know(ACTOR, reference("TaskID", entity("task", "Task", "collection"))))])],
    bindings=[bind(K("/api/v1/tasks"), ["GET"])],
    vis="black_box", vis_reason="Admin tasks view.", reachable=True, reach_conds=["is_staff/admin."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
    confidence=0.85, reasoning="TasksList.get.", description="An admin lists background tasks.",
)

action(
    "admin_cancel_task", "Cancel task", "Delete", "cancel_task", "Administrator",
    obj("entity", "task", "Task", "request", "friendly_token", "TaskID(task)"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("knowledge", f_know(ACTOR, reference("TaskID", entity("task", "Task", "target"))), "Task id in path."),
                  req("authorization", f_can(ACTOR, "Delete", entity("task", "Task", "target")), "is_staff/admin.")],
    gen=[], kill=[eff(f_exists(entity("task", "Task", "target")), "state_transition",
                     "Intended to revoke the task (handler is currently a no-op; see annotation_issues).")],
    io_accounting=[io("input", "friendly_token / TaskID(task)", "req",
                      [kf(f_know(ACTOR, reference("TaskID", entity("task", "Task", "target"))))])],
    bindings=[bind(K("/api/v1/tasks/{friendly_token}"), ["DELETE"])],
    vis="black_box", vis_reason="Admin task cancel.", reachable=True, reach_conds=["is_staff/admin."],
    evidence=[c.ev("source", "files/views/tasks.py:20-30", "no-op delete")],
    confidence=0.6, reasoning="TaskDetail.delete returns 204; revoke is commented out.",
    description="An admin cancels a background task (handler is a no-op in this build).",
    notes="Behavior inferred from intent; the revoke call is commented out so no effect actually occurs.",
)

action(
    "system_authorize_protected_file", "Authorize protected file", "Read", "authorize_protected_file", "Anonymous",
    obj("entity", "media", "Media", "implicit", "", "MediaFile(media)"),
    requirements=[req("authorization", f_can(ACTOR, "Read", MEDIA),
                      "Decision from the requested path's media state and the caller's access.")],
    gen=[], kill=[],
    io_accounting=[io("input", "X-Original-URI", "object_attribute", [], "Protected path supplied by nginx; not a GT reference.")],
    bindings=[bind(K("/api/v1/media-auth"), ["GET"])],
    vis="grey_box", vis_reason="Internal nginx auth_request oracle; its contract (X-Original-URI header) is not user-facing.",
    reachable=True, reach_conds=["Any caller; returns 204/403 for the path's media based on access."],
    evidence=[c.ev("source", "files/views/media_auth.py:178-212", "auth oracle")],
    confidence=0.7, reasoning="media_auth authorizes file access for nginx.",
    description="The nginx auth_request subrequest (or a direct caller) checks access to a protected media file.",
)

# ---- users ------------------------------------------------------------------
action(
    "user_list_users", "List users", "Read", "list_users", "CurrentUser",
    obj("entity", "user", "User", "implicit", "", "Username(user)", role="collection"),
    requirements=[],
    gen=[eff(f_know(ACTOR, reference("Username", USER_C)), "io_reference", "Returns usernames.")],
    kill=[],
    io_accounting=[io("output", "username / Username(user)", "gen", [kf(f_know(ACTOR, reference("Username", USER_C)))]),
                   io("input", "name / UserName(user)", "object_attribute", [], "Search term.")],
    bindings=[bind(K("/api/v1/users"), ["GET"])],
    vis="black_box", vis_reason="Members page.", reachable=True,
    reach_conds=["Public (ALLOW_ANONYMOUS_USER_LISTING=True)."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=200")],
    confidence=0.9, reasoning="users.UserList.get.", description="A visitor lists users.",
)

action(
    "manager_create_user", "Create user", "Create", "create_user", "MediaManager",
    obj("entity", "user", "User", "response", "username", "Username(user)", role="created"),
    requirements=[req("authentication", AUTH, "Authenticated."),
                  req("authorization", f_can(ACTOR, "Create", USER_C), "Manager/admin only.")],
    gen=[eff(f_exists(entity("user", "User", "created")), "action_semantics", "New user created."),
         eff(f_know(ACTOR, reference("Username", entity("user", "User", "created"))), "io_reference",
             "Returns the created username.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "object_attribute", [], "New account username."),
                   io("input", "password / Password(user)", "object_attribute", [], "New credential."),
                   io("input", "email / UserEmail(user)", "object_attribute", [], "New email."),
                   io("output", "username / Username(user)", "gen",
                      [kf(f_know(ACTOR, reference("Username", entity("user", "User", "created"))))])],
    bindings=[bind(K("/api/v1/users"), ["POST"])],
    vis="black_box", vis_reason="Admin create-user.", reachable=True, reach_conds=["Manager/admin."],
    evidence=[c.ev("source", "users/views.py:248-290", "manager create")],
    confidence=0.85, reasoning="users.UserList.post.", description="A manager creates a new user account.",
)

action(
    "user_read_user_profile", "View user profile", "Read", "read_user_profile", "CurrentUser",
    obj("entity", "user", "User", "request", "username", "Username(user)"),
    requirements=[req("knowledge", KNOW_USER, "Username in path."), req("existence", EXISTS_USER, "User must exist.")],
    gen=[eff(KNOW_USER, "io_reference", "Returns the user's public profile.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)])],
    bindings=[bind(K("/api/v1/users/{username}"), ["GET"])],
    vis="black_box", vis_reason="Profile page.", reachable=True, reach_conds=["Public read."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
    confidence=0.9, reasoning="UserDetail.get.", description="A visitor reads a user's profile.",
)

action(
    "owner_update_user_profile", "Edit profile", "Update", "update_user_profile", "CurrentUser",
    obj("entity", "user", "User", "request", "username", "Username(user)"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", USER_T), "Self or manager.")],
    gen=[eff(f_state(USER_T, "name", "updated"), "state_transition", "Profile name/bio/logo updated.")],
    kill=[eff(f_state(USER_T, "name", "previous"), "state_transition", "Previous profile cleared.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)]),
                   io("input", "name / UserName(user)", "object_attribute", [], "Updated name."),
                   io("input", "logo / UserLogo(user)", "object_attribute", [], "Updated avatar.")],
    bindings=[bind(K("/api/v1/users/{username}"), ["POST"])],
    vis="black_box", vis_reason="Profile edit.", reachable=True, reach_conds=["Self or manager."],
    evidence=[c.ev("source", "users/views.py:340-355", "post edit")],
    confidence=0.85, reasoning="UserDetail.post.", description="A user edits their own (or a manager edits a) profile.",
)

action(
    "user_change_password", "Change password", "Update", "change_password", "CurrentUser",
    obj("state", "user", "User", "request", "username", "Username(user)", state_field="password"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", USER_T), "Self or manager; only admin for a superuser.")],
    gen=[eff(f_state(USER_T, "password", "updated"), "state_transition", "Password replaced.")],
    kill=[eff(f_state(USER_T, "password", "previous"), "state_transition", "Old password invalidated.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)]),
                   io("input", "password / Password(user)", "object_attribute", [], "New credential."),
                   io("input", "action / change_password", "object_attribute", [], "PUT discriminator.")],
    bindings=[bind(K("/api/v1/users/{username}"), ["PUT"], "action", ["change_password"])],
    vis="black_box", vis_reason="Change-password form.", reachable=True, reach_conds=["Self or manager."],
    evidence=[c.ev("source", "users/views.py:373-385", "change_password branch")],
    confidence=0.85, reasoning="UserDetail.put action=change_password.", description="A user changes a password.",
)

action(
    "manager_approve_user", "Approve user", "Update", "approve_user", "MediaManager",
    obj("state", "user", "User", "request", "username", "Username(user)", state_field="is_approved"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", USER_T), "Manager only.")],
    gen=[eff(f_state(USER_T, "is_approved", "true"), "state_transition", "User approved.")],
    kill=[eff(f_state(USER_T, "is_approved", "false"), "state_transition", "Prior unapproved state cleared.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)]),
                   io("input", "action / approve_user", "object_attribute", [], "PUT discriminator.")],
    bindings=[bind(K("/api/v1/users/{username}"), ["PUT"], "action", ["approve_user"])],
    vis="black_box", vis_reason="Admin approve control.", reachable=True,
    reach_conds=["Manager.", "Relevant mainly when USERS_NEEDS_TO_BE_APPROVED (off here) but the field is still set."],
    evidence=[c.ev("source", "users/views.py:387-396", "approve branch")],
    confidence=0.75, reasoning="UserDetail.put action=approve_user.", description="A manager approves a user.",
)

action(
    "manager_disapprove_user", "Disapprove user", "Update", "disapprove_user", "MediaManager",
    obj("state", "user", "User", "request", "username", "Username(user)", state_field="is_approved"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Update", USER_T), "Manager only.")],
    gen=[eff(f_state(USER_T, "is_approved", "false"), "state_transition", "User disapproved.")],
    kill=[eff(f_state(USER_T, "is_approved", "true"), "state_transition", "Prior approved state cleared.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)]),
                   io("input", "action / disapprove_user", "object_attribute", [], "PUT discriminator.")],
    bindings=[bind(K("/api/v1/users/{username}"), ["PUT"], "action", ["disapprove_user"])],
    vis="black_box", vis_reason="Admin disapprove control.", reachable=True, reach_conds=["Manager."],
    evidence=[c.ev("source", "users/views.py:392-396", "disapprove branch")],
    confidence=0.75, reasoning="UserDetail.put action=disapprove_user.", description="A manager disapproves a user.",
)

action(
    "user_delete_own_account", "Delete own account", "Delete", "delete_user", "CurrentUser",
    obj("entity", "user", "User", "request", "username", "Username(user)"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Own username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Delete", USER_T), "Self (object permission).")],
    gen=[], kill=[eff(EXISTS_USER, "state_transition", "Account and its media deleted.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)])],
    bindings=[bind(K("/api/v1/users/{username}"), ["DELETE"])],
    vis="black_box", vis_reason="Delete-account control.", reachable=True, reach_conds=["Self."],
    evidence=[c.ev("source", "users/views.py:409-419", "delete self")],
    confidence=0.8, reasoning="UserDetail.delete by self.", description="A user deletes their own account.",
)

action(
    "manager_delete_user_account", "Delete user account", "Delete", "delete_user", "MediaManager",
    obj("entity", "user", "User", "request", "username", "Username(user)"),
    requirements=[req("authentication", AUTH, "Authenticated."), req("knowledge", KNOW_USER, "Target username in path."),
                  req("existence", EXISTS_USER, "User must exist."),
                  req("authorization", f_can(ACTOR, "Delete", USER_T), "Manager/admin; only admin may delete a superuser.")],
    gen=[], kill=[eff(EXISTS_USER, "state_transition", "Target account and its media deleted.")],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)])],
    bindings=[bind(K("/api/v1/users/{username}"), ["DELETE"])],
    vis="black_box", vis_reason="Admin delete-user control.", reachable=True, reach_conds=["Manager/admin."],
    evidence=[c.ev("source", "users/views.py:409-419", "delete other")],
    confidence=0.8, reasoning="UserDetail.delete by manager.", description="A manager deletes another user's account.",
)

action(
    "user_contact_user", "Contact user", "Create", "contact_user", "CurrentUser",
    obj("relation", "message", "ContactMessage", "subject", "", "Username(user)", role="created",
        participants=[principal_p("recipient", "User", "recipient", "PEER",
                                  {"source": "request", "field": "username", "resource": "Username(user)"}),
                      principal_p("actor", "User", "sender", "SELF")],
        constraints=[{"kind": "distinct", "left": "recipient", "right": "actor"}]),
    requirements=[req("authentication", AUTH, "Authenticated sender."),
                  req("knowledge", KNOW_USER, "Recipient username in path."),
                  req("existence", EXISTS_USER, "Recipient must exist.")],
    gen=[eff(f_relation(ACTOR, principal_p("recipient", "User", "recipient", "PEER"), "SentMessageTo"),
             "relation_transition", "A contact message is sent to the recipient.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "req", [kf(KNOW_USER)]),
                   io("input", "body / ContactBody(message)", "object_attribute", [], "Message body content.")],
    bindings=[bind(K("/api/v1/users/{username}/contact"), ["POST"])],
    vis="black_box", vis_reason="Contact form on a profile.", reachable=True,
    reach_conds=["Authenticated; recipient allows contact or sender is editor.",
                 "EXTERNAL DEPENDENCY: SMTP for actual delivery."],
    evidence=[c.ev("source", "users/views.py:161-192", "contact")],
    confidence=0.8, reasoning="contact_user emails the recipient.",
    description="An authenticated user sends a contact message to another user.",
)

action(
    "user_read_own_profile", "Whoami", "Read", "read_own_profile", "CurrentUser",
    obj("entity", "user", "User", "subject", "", "Username(user)", role="self"),
    requirements=[req("authentication", AUTH, "IsAuthenticated.")],
    gen=[eff(f_know(ACTOR, reference("Username", entity("user", "User", "self"))), "io_reference",
             "Returns the caller's own profile.")],
    kill=[],
    io_accounting=[io("output", "username / Username(user)", "gen",
                      [kf(f_know(ACTOR, reference("Username", entity("user", "User", "self"))))])],
    bindings=[bind(K("/api/v1/whoami"), ["GET"])],
    vis="black_box", vis_reason="SPA bootstrap.", reachable=True, reach_conds=["Authenticated."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403 user=200")],
    confidence=0.95, reasoning="UserWhoami.get.", description="The logged-in user reads their own profile.",
)

action(
    "user_read_api_token", "Get API token", "Read", "read_api_token", "CurrentUser",
    obj("entity", "token", "AuthToken", "subject", "", "AuthToken(session)", role="self"),
    requirements=[req("authentication", AUTH, "IsAuthenticated.")],
    gen=[eff(f_know(ACTOR, reference("AuthToken", entity("token", "AuthToken", "self"))), "io_reference",
             "Returns (creating if needed) the caller's DRF token.")],
    kill=[],
    io_accounting=[io("output", "token / AuthToken(session)", "gen",
                      [kf(f_know(ACTOR, reference("AuthToken", entity("token", "AuthToken", "self"))))])],
    bindings=[bind(K("/api/v1/user/token"), ["GET"])],
    vis="black_box", vis_reason="API token retrieval.", reachable=True, reach_conds=["Authenticated."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403 user=200")],
    confidence=0.9, reasoning="UserToken.get.", description="The logged-in user reads their API token.",
)

action(
    "anon_login", "Login", "Create", "login", "Anonymous",
    obj("state", "session", "Session", "response", "token", "AuthToken(session)", role="created",
        state_field="authenticated"),
    requirements=[req("knowledge", f_know(ACTOR, reference("Password", entity("user", "User", "self"))),
                      "Caller supplies the account password (credential brought by the caller).")],
    gen=[eff(f_auth(ACTOR, "Session"), "auth_transition", "The caller becomes authenticated."),
         eff(f_know(ACTOR, reference("AuthToken", entity("session", "Session", "created"))), "io_reference",
             "Response returns an API token.")],
    kill=[],
    io_accounting=[io("input", "username / Username(user)", "object_attribute", [], "Login identifier."),
                   io("input", "password / Password(user)", "req",
                      [kf(f_know(ACTOR, reference("Password", entity("user", "User", "self"))))]),
                   io("output", "token / AuthToken(session)", "gen",
                      [kf(f_know(ACTOR, reference("AuthToken", entity("session", "Session", "created"))))])],
    bindings=[bind(K("/api/v1/login"), ["POST"])],
    vis="black_box", vis_reason="Login form.", reachable=True,
    reach_conds=["Valid credentials of an active (approved) account."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "no-body=400")],
    confidence=0.9, reasoning="users.LoginView.post authenticates and returns a token.",
    description="A visitor logs in with username/email + password and receives a token.",
)

# ---- uploader ---------------------------------------------------------------
action(
    "user_chunked_upload_media", "Chunked upload", "Create", "chunked_upload_media", "CurrentUser",
    obj("entity", "media", "Media", "response", "media_url", "MediaURL(media)", role="created"),
    requirements=[req("authentication", AUTH, "Authenticated with upload permission.")],
    gen=[eff(f_exists(entity("media", "Media", "created")), "action_semantics", "Media created on completion."),
         eff(f_know(ACTOR, reference("MediaURL", entity("media", "Media", "created"))), "io_reference",
             "Returns the created media URL.")],
    kill=[],
    io_accounting=[io("input", "qqfile / MediaFile(media)", "object_attribute", [], "Uploaded chunk/file content."),
                   io("output", "media_url / MediaURL(media)", "gen",
                      [kf(f_know(ACTOR, reference("MediaURL", entity("media", "Media", "created"))))])],
    bindings=[bind(K("/fu/upload/"), ["POST"])],
    vis="black_box", vis_reason="Drag-and-drop uploader.", reachable=True,
    reach_conds=["Authenticated with upload permission."],
    evidence=[c.ev("source", "uploader/views.py:19-76", "FineUploader")],
    confidence=0.85, reasoning="FineUploaderView creates a Media on completion.",
    description="A user uploads a media file in chunks via the fine-uploader endpoint.",
)

# ---- LTI public reads -------------------------------------------------------
action(
    "anon_read_lti_jwks", "Read LTI JWKS", "Read", "read_lti_jwks", "Anonymous",
    obj("entity", "ltikey", "LTIKey", "implicit", "", "LTIPublicKey(tool)", role="target"),
    requirements=[],
    gen=[eff(f_know(ACTOR, reference("LTIPublicKey", entity("ltikey", "LTIKey", "target"))), "io_reference",
             "Returns the tool JWKS.")],
    kill=[],
    io_accounting=[io("output", "keys", "gen",
                      [kf(f_know(ACTOR, reference("LTIPublicKey", entity("ltikey", "LTIKey", "target"))))])],
    bindings=[bind(K("/lti/jwks/"), ["GET"])],
    vis="black_box", vis_reason="Public JWKS endpoint.", reachable=True, reach_conds=["Public read."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "200 all")],
    confidence=0.8, reasoning="JWKSView.get.", description="Anyone reads the tool's LTI JWKS.",
)

action(
    "anon_read_lti_public_key", "Read LTI public key", "Read", "read_lti_public_key", "Anonymous",
    obj("entity", "ltikey", "LTIKey", "implicit", "", "LTIPublicKey(tool)", role="target"),
    requirements=[],
    gen=[eff(f_know(ACTOR, reference("LTIPublicKey", entity("ltikey", "LTIKey", "target"))), "io_reference",
             "Returns the tool public key (PEM).")],
    kill=[],
    io_accounting=[io("output", "pem", "observed_only", [], "PEM text (same key as JWKS).")],
    bindings=[bind(K("/lti/public-key/"), ["GET"])],
    vis="black_box", vis_reason="Public key endpoint.", reachable=True, reach_conds=["Public read."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "200 all")],
    confidence=0.8, reasoning="PublicKeyPEMView.get.", description="Anyone reads the tool's public key as PEM.",
)

# ============================================================================
# MIGRATIONS (superuser) -- ModelViewSet + @action routes, built in a loop
# ============================================================================
MIG = entity("migration", "Migration", "target")
KNOW_MIG = f_know(ACTOR, reference("MigrationID", MIG))
EXISTS_MIG = f_exists(MIG)
MIG_AUTHZ = req("authorization", f_can(ACTOR, "Update", MIG), "Superuser (IsSuperUser).")


def mig_detail_req(extra=None):
    r = [req("authentication", AUTH, "Authenticated superuser."),
         req("knowledge", KNOW_MIG, "Migration pk in path."),
         req("existence", EXISTS_MIG, "Migration must exist."), MIG_AUTHZ]
    return r + (extra or [])


action(
    "admin_list_migrations", "List migrations", "Read", "list_migrations", "Administrator",
    obj("entity", "migration", "Migration", "implicit", "", "MigrationID(migration)", role="collection"),
    requirements=[req("authentication", AUTH, "Authenticated superuser."),
                  req("authorization", f_can(ACTOR, "Read", entity("migration", "Migration", "collection")), "Superuser.")],
    gen=[eff(f_know(ACTOR, reference("MigrationID", entity("migration", "Migration", "collection"))),
             "io_reference", "Returns migration ids.")],
    kill=[],
    io_accounting=[io("output", "id / MigrationID(migration)", "gen",
                      [kf(f_know(ACTOR, reference("MigrationID", entity("migration", "Migration", "collection"))))])],
    bindings=[bind(K("/api/v1/migrations/"), ["GET"])],
    vis="black_box", vis_reason="Migrations dashboard.", reachable=True, reach_conds=["Superuser."],
    evidence=[c.ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
    confidence=0.85, reasoning="ViewSet list.", description="An admin lists migration services.",
)

action(
    "admin_create_migration", "Create migration", "Create", "create_migration", "Administrator",
    obj("entity", "migration", "Migration", "response", "id", "MigrationID(migration)", role="created"),
    requirements=[req("authentication", AUTH, "Authenticated superuser."),
                  req("authorization", f_can(ACTOR, "Create", entity("migration", "Migration", "collection")), "Superuser.")],
    gen=[eff(f_exists(entity("migration", "Migration", "created")), "action_semantics", "Migration created and scheduled."),
         eff(f_know(ACTOR, reference("MigrationID", entity("migration", "Migration", "created"))), "io_reference",
             "Returns the created migration id.")],
    kill=[],
    io_accounting=[io("input", "name / MigrationName(migration)", "object_attribute", [], "Migration name."),
                   io("input", "provider / MigrationProvider(migration)", "object_attribute", [], "Source provider."),
                   io("output", "id / MigrationID(migration)", "gen",
                      [kf(f_know(ACTOR, reference("MigrationID", entity("migration", "Migration", "created"))))])],
    bindings=[bind(K("/api/v1/migrations/"), ["POST"])],
    vis="black_box", vis_reason="Create-migration form.", reachable=True,
    reach_conds=["Superuser.", "EXTERNAL DEPENDENCY: reachable source system for a real run."],
    evidence=[c.ev("source", "migrationservice/views.py:137-141", "perform_create")],
    confidence=0.8, reasoning="ViewSet create schedules a migration.",
    description="An admin creates and schedules a migration from a source provider.",
)

action(
    "admin_read_migration", "Read migration", "Read", "read_migration", "Administrator",
    obj("entity", "migration", "Migration", "request", "pk", "MigrationID(migration)"),
    requirements=[req("authentication", AUTH, "Authenticated superuser."), req("knowledge", KNOW_MIG, "pk in path."),
                  req("existence", EXISTS_MIG, "Migration must exist."),
                  req("authorization", f_can(ACTOR, "Read", MIG), "Superuser.")],
    gen=[eff(KNOW_MIG, "io_reference", "Returns the migration.")],
    kill=[],
    io_accounting=[io("input", "pk / MigrationID(migration)", "req", [kf(KNOW_MIG)])],
    bindings=[bind(K("/api/v1/migrations/{pk}/"), ["GET"])],
    vis="black_box", vis_reason="Migration detail.", reachable=True, reach_conds=["Superuser."],
    evidence=[c.ev("source", "migrationservice/views.py:38-41", "retrieve")],
    confidence=0.8, reasoning="ViewSet retrieve.", description="An admin reads one migration.",
)

action(
    "admin_update_migration", "Update migration", "Update", "update_migration", "Administrator",
    obj("state", "migration", "Migration", "request", "pk", "MigrationID(migration)", state_field="config"),
    requirements=mig_detail_req(),
    gen=[eff(f_state(MIG, "config", "updated"), "state_transition", "Migration config updated and rescheduled.")],
    kill=[eff(f_state(MIG, "config", "previous"), "state_transition", "Previous config cleared.")],
    io_accounting=[io("input", "pk / MigrationID(migration)", "req", [kf(KNOW_MIG)]),
                   io("input", "name / MigrationName(migration)", "object_attribute", [], "Updated name.")],
    bindings=[bind(K("/api/v1/migrations/{pk}/"), ["PUT", "PATCH"])],
    vis="black_box", vis_reason="Migration edit.", reachable=True, reach_conds=["Superuser."],
    evidence=[c.ev("source", "migrationservice/views.py:143-144", "perform_update")],
    confidence=0.8, reasoning="ViewSet update.", description="An admin edits a migration's configuration.",
)

action(
    "admin_delete_migration", "Delete migration", "Delete", "delete_migration", "Administrator",
    obj("entity", "migration", "Migration", "request", "pk", "MigrationID(migration)"),
    requirements=mig_detail_req(),
    gen=[], kill=[eff(EXISTS_MIG, "state_transition", "Migration removed.")],
    io_accounting=[io("input", "pk / MigrationID(migration)", "req", [kf(KNOW_MIG)])],
    bindings=[bind(K("/api/v1/migrations/{pk}/"), ["DELETE"])],
    vis="black_box", vis_reason="Migration delete.", reachable=True, reach_conds=["Superuser."],
    evidence=[c.ev("source", "migrationservice/views.py:38-41", "destroy")],
    confidence=0.8, reasoning="ViewSet destroy.", description="An admin deletes a migration.",
)


# migration @action routes -- transitions (Update) and reads (Read)
def mig_transition(akey, suffix, name, field, value, desc):
    action(
        akey, name, "Update", akey.replace("admin_", ""), "Administrator",
        obj("state", "migration", "Migration", "request", "pk", "MigrationID(migration)", state_field="status"),
        requirements=mig_detail_req(),
        gen=[eff(f_state(MIG, "status", value), "state_transition", desc)],
        kill=[eff(f_state(MIG, "status", "previous"), "state_transition", "Previous status cleared.")],
        io_accounting=[io("input", "pk / MigrationID(migration)", "req", [kf(KNOW_MIG)])],
        bindings=[bind(K("/api/v1/migrations/" + suffix), ["POST"])],
        vis="black_box", vis_reason="Migration dashboard control.", reachable=True,
        reach_conds=["Superuser.", "EXTERNAL DEPENDENCY: reachable source system for an actual transfer."],
        evidence=[c.ev("source", "migrationservice/views.py:173-191", "transition " + suffix)],
        confidence=0.75, reasoning="ViewSet @action " + suffix, description=desc,
    )


mig_transition("admin_start_migration", "{pk}/start/", "Start migration", "status", "running",
               "An admin starts a migration.")
mig_transition("admin_resume_migration", "{pk}/resume/", "Resume migration", "status", "running",
               "An admin resumes a paused migration.")
mig_transition("admin_rerun_migration", "{pk}/rerun/", "Re-run migration", "status", "running",
               "An admin re-runs a finished migration.")
mig_transition("admin_pause_migration", "{pk}/pause/", "Pause migration", "status", "paused",
               "An admin pauses a running migration.")
mig_transition("admin_abort_migration", "{pk}/abort/", "Abort migration", "status", "aborted",
               "An admin aborts a migration.")


def mig_read(akey, suffix, name, ref_type, ref_type_name, desc, detail=True, methods=None):
    e = entity(ref_type_name.lower(), ref_type_name, "collection")
    gfact = f_know(ACTOR, reference(ref_type, e))
    reqs = ([req("authentication", AUTH, "Authenticated superuser."), req("knowledge", KNOW_MIG, "pk in path."),
             req("existence", EXISTS_MIG, "Migration must exist."),
             req("authorization", f_can(ACTOR, "Read", MIG), "Superuser.")] if detail else
            [req("authentication", AUTH, "Authenticated superuser."),
             req("authorization", f_can(ACTOR, "Read", entity("migration", "Migration", "collection")), "Superuser.")])
    ios = ([io("input", "pk / MigrationID(migration)", "req", [kf(KNOW_MIG)])] if detail else [])
    ios.append(io("output", ref_type, "gen", [kf(gfact)]))
    action(
        akey, name, "Read", akey.replace("admin_", ""), "Administrator",
        obj("entity", ref_type_name.lower(), ref_type_name, "implicit", "", ref_type + "(" + ref_type_name.lower() + ")",
            role="collection"),
        requirements=reqs,
        gen=[eff(gfact, "io_reference", desc)],
        kill=[], io_accounting=ios,
        bindings=[bind(K("/api/v1/migrations/" + suffix), methods or ["POST"])],
        vis="black_box", vis_reason="Migration dashboard info.", reachable=True,
        reach_conds=["Superuser."] + (["EXTERNAL DEPENDENCY: reachable source system."] if "source" in akey or "connection" in akey else []),
        evidence=[c.ev("source", "migrationservice/views.py", "action " + suffix)],
        confidence=0.7, reasoning="ViewSet @action " + suffix, description=desc,
    )


mig_read("admin_list_migration_records", "{pk}/records/", "List migration records", "MigrationRecordID",
         "MigrationRecord", "An admin lists a migration's mapping records.", True, ["GET"])
mig_read("admin_read_migration_progress", "{pk}/progress/", "Read migration progress", "MigrationProgress",
         "MigrationProgress", "An admin polls a migration's progress.", True, ["GET"])
mig_read("admin_check_migration_connection", "{pk}/check_connection/", "Check saved connection",
         "ConnectionResult", "ConnectionResult", "An admin tests a saved migration's source credentials.", True, ["POST"])
mig_read("admin_list_source_categories", "{pk}/source_categories/", "List source categories (saved)",
         "SourceCategory", "SourceCategory", "An admin lists source categories via saved credentials.", True, ["POST"])
mig_read("admin_list_source_roles", "{pk}/source_roles/", "List source roles (saved)",
         "SourceRole", "SourceRole", "An admin lists source roles via saved credentials.", True, ["POST"])
mig_read("admin_check_unsaved_connection", "check_connection/", "Check typed connection",
         "ConnectionResult", "ConnectionResult", "An admin tests typed (unsaved) source credentials.", False, ["POST"])
mig_read("admin_list_unsaved_source_categories", "source_categories/", "List source categories (unsaved)",
         "SourceCategory", "SourceCategory", "An admin lists source categories via typed credentials.", False, ["POST"])
mig_read("admin_list_unsaved_source_roles", "source_roles/", "List source roles (unsaved)",
         "SourceRole", "SourceRole", "An admin lists source roles via typed credentials.", False, ["POST"])
mig_read("admin_read_server_time", "server_time/", "Read server time", "ServerClock",
         "ServerClock", "An admin reads the portal clock for the scheduling form.", False, ["GET"])
mig_read("admin_list_lti_platforms", "lti_platforms/", "List LTI platforms", "LTIPlatformID",
         "LTIPlatform", "An admin lists LTI platforms a migrated course can bind to.", False, ["GET"])
