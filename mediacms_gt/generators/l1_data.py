# -*- coding: utf-8 -*-
"""MediaCMS 9.2.1 L1 endpoint inventory (data table).

Source-first: enumerated from the Django URLconf + DRF view handlers
(files/users/migrationservice/uploader/lti), reconciled against the live
URL resolver dump (mediacms_gt/url_dump.txt) and verified against the running
container (mediacms_gt/runtime_probe.txt). The deployment's own /swagger.json
is served but crashes during schema generation (see annotation_issues issue-001),
so the URL resolver dump is the authoritative route list for the running build.

Builds three groups consumed by build_l1.py:
  API_NODES  - kind=api, io_variants complete (L2 candidates)
  PAGE_NODES - kind=page/static (not L2 candidates)
  EDGES      - observed/supported navigation+request transitions
"""
from common import (key, node, variant, rf, of, resp_json, resp_empty, resp_scalar,
                    resp_raw, dec_for, dec, ev)

# fixtures used as runtime samples (mediacms_gt/runtime_probe.txt)
PUB = "Yt7r1RFGP"      # public media, owner alice
PRIV = "EzRFgOP5p"     # private media, owner alice
CAT = "KgeToe8439eWLe9R"
PL = "UQSagkaGR"

ST_READ_PUBLIC = {"anonymous": [200], "user": [200], "admin": [200]}


def paginated(item_fields):
    """DRF LimitOffset/Page paginated envelope."""
    fields = [
        of("count", "integer", flow=False, description="Total count (pagination)."),
        of("next", "string", flow=False, description="Next page URL (pagination)."),
        of("previous", "string", flow=False, description="Previous page URL (pagination)."),
    ]
    for f in item_fields:
        f = dict(f)
        f["path"] = "results[]." + f["name"]
        fields.append(f)
    return resp_json(fields)


MEDIA_ITEM = [
    of("friendly_token", "string", True, "Stable media identifier (reference-capable)."),
    of("title", "string", True, "Media title."),
    of("description", "string", True, "Media description."),
    of("user", "string", True, "Owner username."),
    of("state", "string", True, "Visibility state: public/unlisted/private."),
    of("media_type", "string", True, "video/image/audio/pdf."),
    of("url", "string", False, "Display URL (presentation)."),
    of("views", "integer", False, "View counter (summary)."),
]

API_NODES = []


def A(n):
    API_NODES.append(n)
    return n


# ----------------------------------------------------------------------------
# MEDIA
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/media"), "api", ["GET", "POST"],
    operation_semantic="browse_or_create_media",
    params=["page", "author", "show", "t", "ordering", "sort_by", "media_type",
            "upload_date", "duration", "publish_state", "shared_user", "shared_group", "q"],
    variants=[
        variant("GET",
                request_fields=[
                    rf("author", "query", "string", False, True, "Filter by owner username."),
                    rf("t", "query", "string", False, True, "Filter by tag title."),
                    rf("media_type", "query", "string", False, True, "Filter by media type."),
                    rf("show", "query", "string", False, False, "recommended/featured/latest/shared_* view."),
                    rf("q", "query", "string", False, False, "Full-text query (control)."),
                    rf("page", "query", "integer", False, False, "Page number (pagination)."),
                ],
                response=paginated(MEDIA_ITEM),
                reason="MediaList.get returns listable media the identity may see, paginated.",
                evidence="files/views/media.py:103-308; runtime anon/user/admin=200"),
        variant("POST",
                request_fields=[
                    rf("media_file", "body", "file", True, True, "Uploaded media file (new content)."),
                    rf("title", "body", "string", False, True, "Title (new content)."),
                    rf("description", "body", "string", False, True, "Description (new content)."),
                ],
                response=resp_json(MEDIA_ITEM),
                body_format="form",
                reason="MediaList.post creates a Media owned by the authenticated user; IsAuthorizedToAdd gates upload.",
                evidence="files/views/media.py:321-332; runtime upload token=Yt7r1RFGP -> 201"),
    ],
    sem_in_decisions=[dec_for("author"), dec_for("t", "TagTitle(tag)"), dec_for("media_type"),
                      dec_for("media_file"), dec_for("title"), dec_for("description")],
    sem_out_decisions=[dec_for("friendly_token"), dec_for("title"), dec_for("description"),
                       dec_for("user"), dec_for("state"), dec_for("media_type")],
    statuses=[200, 201, 400, 403],
    identity_statuses={"anonymous": [200, 403], "user": [200, 201], "admin": [200, 201]},
    route_confirmed=True,
    visibility="black_box",
    vis_reason="Listing/upload are issued by the user-visible SPA and appear in network traffic.",
    reach_conds=["For POST: authenticated session or DRF token; upload permission (CAN_ADD_MEDIA=all)."],
    evidence=[ev("source", "files/views/media.py:55-332", "Methods, permission class, IO"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200 all identities; POST upload 201")],
    samples=[{"identity": "user", "method": "POST", "status": 201,
              "url": key("/api/v1/media"), "request_body": "multipart: media_file,title",
              "response_body_sample": '{"friendly_token":"Yt7r1RFGP","state":"unlisted",...}',
              "source": "manual_runtime_probe"}],
))

A(node(
    key("/api/v1/media/{friendly_token}"), "api", ["GET", "POST", "PUT", "DELETE"],
    operation_semantic="media_detail",
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier.")],
                response=resp_json([
                    of("title", "string", True, "Title."),
                    of("description", "string", True, "Description."),
                    of("user", "string", True, "Owner username."),
                    of("state", "string", True, "Visibility state."),
                    of("media_type", "string", True, "Media type."),
                    of("enable_comments", "boolean", True, "Whether comments are enabled."),
                    of("allow_download", "boolean", True, "Whether download is enabled."),
                    of("is_reviewed", "boolean", True, "Review flag."),
                    of("chapter_data", "array", True, "Chapter markers."),
                    of("related_media", "array", False, "Related media (presentation)."),
                ]),
                reason="MediaDetail.get returns SingleMediaSerializer; private media needs owner/member/editor access.",
                evidence="files/views/media.py:864-884; runtime pub=200, private anon=400 user=200"),
        variant("POST",
                request_fields=[
                    rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                    rf("type", "body", "string", True, False, "Manager action: encode|review (discriminator)."),
                    rf("encoding_profiles", "body", "array", False, True, "Encode profile ids (for encode)."),
                    rf("result", "body", "boolean", False, True, "Reviewed result (for review)."),
                ],
                response=resp_json([of("detail", "string", False, "Result message.")]),
                body_format="form",
                reason="MediaDetail.post runs editor/manager actions (encode/review).",
                evidence="files/views/media.py:905-952"),
        variant("PUT",
                request_fields=[
                    rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                    rf("title", "body", "string", False, True, "Updated title."),
                    rf("description", "body", "string", False, True, "Updated description."),
                    rf("media_file", "body", "file", False, True, "Replacement file."),
                ],
                response=resp_json(MEDIA_ITEM),
                body_format="form",
                reason="MediaDetail.put updates media; owner/contributor/editor only.",
                evidence="files/views/media.py:965-985"),
        variant("DELETE",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier.")],
                response=resp_empty(),
                reason="MediaDetail.delete removes media; owner/contributor/editor only.",
                evidence="files/views/media.py:998-1004; runtime nonexistent anon=403 user=400"),
    ],
    sem_in_decisions=[dec_for("friendly_token"), dec_for("title"), dec_for("description"),
                      dec_for("media_file"), dec_for("encoding_profiles"), dec_for("result")],
    sem_out_decisions=[dec_for("friendly_token"), dec_for("title"), dec_for("description"),
                       dec_for("user"), dec_for("state"), dec("enable_comments", "MediaCommentsFlag(media)", "state", reason="comments toggle"),
                       dec("allow_download", "MediaDownloadFlag(media)", "state", reason="download toggle"),
                       dec("chapter_data", "MediaChapters(media)", "content", reason="chapter markers")],
    statuses=[200, 201, 400, 401, 403, 204],
    identity_statuses={"anonymous": [200, 400], "user": [200, 201, 400], "admin": [200, 201, 204]},
    route_confirmed=True,
    vis_reason="Media page issues GET; owner UI issues PUT/DELETE/POST actions.",
    reach_conds=["GET public: any; private: owner/member/editor.",
                 "PUT/DELETE: media owner, contributor, or editor.",
                 "POST encode/review: editor/manager."],
    evidence=[ev("source", "files/views/media.py:823-1004", "Four methods, permission + split"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET pub=200; private anon=400,user=200; missing=400")],
))

A(node(
    key("/api/v1/media/{friendly_token}/actions"), "api", ["GET", "POST", "DELETE"],
    operation_semantic="media_actions",
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier.")],
                response=resp_json([of("reported", "array", True, "Report entries (owner/editor only).")]),
                reason="MediaActions.get lists reports; owner or editor only.",
                evidence="files/views/media.py:1035-1051; runtime anon=400 user(owner)=200"),
        variant("POST",
                request_fields=[
                    rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                    rf("type", "body", "string", True, False, "Action: like|dislike|report|watch (discriminator)."),
                    rf("extra_info", "body", "string", False, True, "Report reason (for report)."),
                ],
                response=resp_json([of("detail", "string", False, "action received.")]),
                body_format="json",
                reason="MediaActions.post records like/dislike/report/watch; anonymous limited to ALLOW_ANONYMOUS_ACTIONS.",
                evidence="files/views/media.py:1059-1086; runtime no-type=400"),
        variant("DELETE",
                request_fields=[
                    rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                    rf("type", "body", "string", True, False, "Must be 'report' to reset reports."),
                ],
                response=resp_json([of("detail", "string", False, "reset reported times counter.")]),
                body_format="json",
                reason="MediaActions.delete resets reports; superuser only.",
                evidence="files/views/media.py:1094-1113"),
    ],
    sem_in_decisions=[dec_for("friendly_token"), dec_for("extra_info")],
    sem_out_decisions=[],
    statuses=[200, 201, 400],
    identity_statuses={"anonymous": [201, 400], "user": [200, 201, 400], "admin": [200, 201, 400]},
    route_confirmed=True,
    vis_reason="Like/dislike/report/watch buttons on the media page issue this.",
    reach_conds=["POST like/dislike/report/watch: anonymous allowed for ALLOW_ANONYMOUS_ACTIONS; others need session.",
                 "GET reports: owner/editor.", "DELETE reset: superuser."],
    evidence=[ev("source", "files/views/media.py:1007-1113", "AllowAny + per-branch checks"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET anon=400 user=200; POST no-type=400")],
))

A(node(
    key("/api/v1/media/{friendly_token}/comments"), "api", ["GET", "POST"],
    operation_semantic="media_comments",
    params=["page"],
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier.")],
                response=paginated([
                    of("uid", "string", True, "Comment identifier."),
                    of("text", "string", True, "Comment text."),
                    of("author_name", "string", True, "Author display name."),
                    of("parent", "string", True, "Parent comment id (threading)."),
                ]),
                reason="CommentDetail.get lists a media's comments; private media needs media access.",
                evidence="files/views/comments.py:98-108; runtime pub=200"),
        variant("POST",
                request_fields=[
                    rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                    rf("text", "body", "string", True, True, "Comment text (new content)."),
                    rf("parent", "body", "string", False, True, "Parent comment uid (reply)."),
                ],
                response=resp_json([
                    of("uid", "string", True, "Created comment id."),
                    of("text", "string", True, "Comment text."),
                    of("author_name", "string", True, "Author name."),
                ]),
                body_format="json",
                reason="CommentDetail.post adds a comment when comments are enabled and the user may comment.",
                evidence="files/views/comments.py:141-162"),
    ],
    sem_in_decisions=[dec_for("friendly_token"), dec_for("text"), dec_for("parent")],
    sem_out_decisions=[dec("uid", "CommentUID(comment)", "identifier", reference_capable=True, reason="Comment identifier."), dec_for("text")],
    statuses=[200, 201, 400],
    identity_statuses={"anonymous": [200, 400], "user": [200, 201], "admin": [200, 201]},
    route_confirmed=True,
    vis_reason="Comment list/box on the media page.",
    reach_conds=["POST: authenticated and allowed to comment (CAN_COMMENT=all); comments enabled on the media."],
    evidence=[ev("source", "files/views/comments.py:64-162", "GET/POST, permission"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200 all")],
))
# note: SEM has no "uid" key for the created comment output; handled by dec_for("comment_uid") alias below

A(node(
    key("/api/v1/media/{friendly_token}/comments/{uid}"), "api", ["GET", "DELETE"],
    operation_semantic="delete_comment",
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                                rf("uid", "path", "string", True, True, "Comment identifier.")],
                response=paginated([of("uid", "string", True, "Comment id."), of("text", "string", True, "Text.")]),
                reason="Same CommentDetail.get handler (uid ignored on GET).",
                evidence="files/urls.py:92-95; files/views/comments.py:98-108"),
        variant("DELETE",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                                rf("uid", "path", "string", True, True, "Comment to delete.")],
                response=resp_empty(),
                reason="CommentDetail.delete removes a comment; author, media owner, or editor.",
                evidence="files/views/comments.py:116-133"),
    ],
    sem_in_decisions=[dec_for("friendly_token"), dec("uid", "CommentUID(comment)", "identifier",
                      reference_capable=True, reason="Path comment id selects the comment to delete.")],
    sem_out_decisions=[],
    statuses=[200, 204, 400],
    identity_statuses={"anonymous": [200, 400], "user": [200, 204, 400], "admin": [200, 204]},
    route_confirmed=False,
    vis_reason="Delete-comment control; comment id from the comment list.",
    reach_conds=["DELETE: comment author, media owner, or MediaCMS editor/manager/admin."],
    evidence=[ev("source", "files/views/comments.py:64-133", "DELETE auth branch")],
))

A(node(
    key("/api/v1/media/{friendly_token}/share"), "api", ["POST"],
    operation_semantic="share_media_to_course",
    variants=[
        variant("POST",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                                rf("courseid", "body", "string", False, False, "LTI context id (optional).")],
                response=resp_raw("Empty 200/401/403 HttpResponse."),
                body_format="form",
                reason="media_share marks the media shared (owner-only); creates owner MediaPermission.",
                evidence="files/views/media.py:1251-1274"),
    ],
    sem_in_decisions=[dec_for("friendly_token")],
    sem_out_decisions=[],
    statuses=[200, 401, 403],
    identity_statuses={"anonymous": [401], "user": [200, 403], "admin": [200, 403]},
    route_confirmed=False,
    vis_reason="Owner embed/share action from the LTI plugin.",
    reach_conds=["Authenticated owner of the media."],
    evidence=[ev("source", "files/views/media.py:1251-1274", "require_POST, owner check")],
))

A(node(
    key("/api/v1/media/{friendly_token}/chapters"), "api", ["POST"],
    operation_semantic="set_media_chapters",
    variants=[
        variant("POST",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                                rf("chapters", "body", "array", True, True, "Chapter markers (startTime/endTime/chapterTitle).")],
                response=resp_json([of("success", "boolean", False, "Outcome.")]),
                body_format="json",
                reason="video_chapters replaces the media's chapter set; editor/contributor only.",
                evidence="files/views/pages.py:301-358"),
    ],
    sem_in_decisions=[dec_for("friendly_token"), dec_for("chapters")],
    sem_out_decisions=[],
    statuses=[200, 400],
    identity_statuses={"anonymous": [302], "user": [200, 400], "admin": [200, 400]},
    route_confirmed=False,
    vis_reason="Chapter editor on the edit page posts the chapter array.",
    reach_conds=["Authenticated editor or media contributor."],
    evidence=[ev("source", "files/views/pages.py:301-358", "login_required, editor/contributor check")],
))

A(node(
    key("/api/v1/media/{friendly_token}/trim_video"), "api", ["POST"],
    operation_semantic="trim_video",
    variants=[
        variant("POST",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target media identifier."),
                                rf("trim_data", "body", "object", True, False, "Trim segments payload.")],
                response=resp_json([of("success", "boolean", False, "Outcome."),
                                    of("request_id", "integer", False, "Trim request id.")]),
                body_format="json",
                reason="trim_video queues a trim request; editor/contributor only; gated by ALLOW_VIDEO_TRIMMER.",
                evidence="files/views/pages.py:542-570"),
    ],
    sem_in_decisions=[dec_for("friendly_token")],
    sem_out_decisions=[],
    statuses=[200, 400],
    identity_statuses={"anonymous": [302], "user": [200, 400], "admin": [200, 400]},
    route_confirmed=False,
    reachable=True,
    vis_reason="Video trimmer tool posts here.",
    reach_conds=["Authenticated editor or media contributor.",
                 "ALLOW_VIDEO_TRIMMER enabled (default True)."],
    evidence=[ev("source", "files/views/pages.py:542-570", "trimmer gate + auth")],
))

A(node(
    key("/api/v1/media/{friendly_token}/pdf"), "api", ["GET"],
    operation_semantic="read_media_pdf",
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Target pdf media identifier.")],
                response=resp_raw("application/pdf stream (or X-Accel redirect)."),
                content_types=["application/pdf"],
                reason="view_pdf streams the original pdf; private needs member/editor access.",
                evidence="files/views/media_auth.py:215-233"),
    ],
    sem_in_decisions=[dec_for("friendly_token")],
    sem_out_decisions=[],
    statuses=[200, 403, 404],
    identity_statuses={"anonymous": [200, 403, 404], "user": [200, 403, 404], "admin": [200, 404]},
    route_confirmed=False,
    vis_reason="PDF viewer embeds this URL.",
    reach_conds=["media_type=pdf; public: any; private: owner/member/editor."],
    evidence=[ev("source", "files/views/media_auth.py:215-233", "require_safe, access check")],
))

A(node(
    key("/api/v1/media/user/bulk_actions"), "api", ["GET", "POST"],
    operation_semantic="media_bulk_actions",
    variants=[
        variant("GET",
                request_fields=[],
                response=resp_empty(),
                reason="Same view; GET has no handler (405/empty) - bulk ops use POST.",
                evidence="files/urls.py:57-58"),
        variant("POST",
                request_fields=[
                    rf("media_ids", "body", "array", True, True, "Target media tokens (owned by caller)."),
                    rf("action", "body", "string", True, False, "Bulk action discriminator (21 values)."),
                    rf("playlist_ids", "body", "array", False, True, "Playlist ids (add/remove_from_playlist)."),
                    rf("category_uids", "body", "array", False, True, "Category uids (add/remove_from_category)."),
                    rf("tag_titles", "body", "array", False, True, "Tag titles (add/remove_tags)."),
                    rf("state", "body", "string", False, True, "New state (set_state)."),
                    rf("owner", "body", "string", False, True, "New owner username (change_owner)."),
                    rf("users", "body", "array", False, True, "Usernames (set/remove_ownership)."),
                    rf("ownership_type", "body", "string", False, True, "viewer/editor/owner."),
                ],
                response=resp_json([of("detail", "string", False, "Result message."),
                                    of("results", "array", False, "Membership query results.")]),
                body_format="json",
                reason="MediaBulkUserActions.post dispatches 21 bulk actions over media the caller owns.",
                evidence="files/views/media.py:335-820; runtime no-ids=400, anon=403"),
    ],
    sem_in_decisions=[dec_for("media_ids"), dec_for("playlist_ids"), dec_for("category_uids"),
                      dec_for("tag_titles"), dec_for("state"), dec_for("owner"),
                      dec_for("users"), dec_for("ownership_type")],
    sem_out_decisions=[],
    statuses=[200, 400, 401, 403],
    identity_statuses={"anonymous": [403], "user": [200, 400], "admin": [200, 400]},
    route_confirmed=True,
    vis_reason="'My media' management toolbar issues bulk actions.",
    reach_conds=["Authenticated; acts only on media owned by the caller."],
    evidence=[ev("source", "files/views/media.py:335-820", "21-way action dispatch"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403, user no-ids=400")],
))

A(node(
    key("/api/v1/search"), "api", ["GET"],
    operation_semantic="search_media",
    params=["q", "c", "t", "media_type", "author", "upload_date", "sort_by", "ordering", "show"],
    variants=[
        variant("GET",
                request_fields=[
                    rf("q", "query", "string", False, False, "Full-text query (control input)."),
                    rf("c", "query", "string", False, True, "Category uid or title."),
                    rf("t", "query", "string", False, True, "Tag title."),
                    rf("author", "query", "string", False, True, "Author username."),
                    rf("media_type", "query", "string", False, True, "Media type filter."),
                ],
                response=paginated([
                    of("title", "string", True, "Matched media title."),
                    of("friendly_token", "string", True, "Media identifier."),
                    of("author_name", "string", True, "Author name."),
                ]),
                reason="MediaSearch.get full-text searches media the identity may see.",
                evidence="files/views/media.py:1116-1248; runtime q=clip -> 200"),
    ],
    sem_in_decisions=[dec_for("c", "CategoryUID(category)"), dec_for("t", "TagTitle(tag)"),
                      dec_for("author"), dec_for("media_type")],
    sem_out_decisions=[dec_for("friendly_token"), dec("author_name", "UserName(user)", "attribute", reason="author display name")],
    statuses=[200],
    identity_statuses=ST_READ_PUBLIC,
    route_confirmed=True,
    vis_reason="Search box issues this query.",
    reach_conds=["Public read; results scoped to what the identity may see."],
    evidence=[ev("source", "files/views/media.py:1116-1248", "search handler"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "q=clip 200")],
))

# ----------------------------------------------------------------------------
# CATEGORIES / TAGS
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/categories"), "api", ["GET"],
    operation_semantic="list_categories",
    variants=[variant("GET", response=resp_json([
        of("title", "string", True, "Category title."),
        of("uid", "string", True, "Category identifier."),
        of("description", "string", True, "Category description."),
        of("media_count", "integer", False, "Media count (summary)."),
        of("user", "string", True, "Owner username."),
    ]), reason="CategoryList.get lists visible categories.",
        evidence="files/views/categories.py:40-57; runtime 200")],
    sem_in_decisions=[],
    sem_out_decisions=[dec_for("category_uid", "CategoryUID(category)"),
                       dec("title", "CategoryTitle(category)", "attribute", reason="category title"),
                       dec_for("user")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="Categories page lists these.",
    reach_conds=["Public read."],
    evidence=[ev("source", "files/views/categories.py:40-57", "list"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "200")],
))

A(node(
    key("/api/v1/categories/contributor"), "api", ["GET"],
    operation_semantic="list_contributor_categories",
    variants=[variant("GET", response=resp_json([
        of("uid", "string", True, "Category identifier."),
        of("title", "string", True, "Category title."),
    ]), reason="CategoryListContributor.get lists LMS courses the user contributes to; anon -> [].",
        evidence="files/views/categories.py:82-100; runtime anon=200 ([])")],
    sem_in_decisions=[],
    sem_out_decisions=[dec_for("category_uid", "CategoryUID(category)"),
                       dec("title", "CategoryTitle(category)", "attribute", reason="category title")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="Contributor course picker.",
    reach_conds=["Authenticated for non-empty results (RBAC contributor); anon returns []."],
    evidence=[ev("source", "files/views/categories.py:82-100", "contributor list")],
))

A(node(
    key("/api/v1/categories/{uid}"), "api", ["GET"],
    operation_semantic="read_category",
    variants=[variant("GET",
        request_fields=[rf("uid", "path", "string", True, True, "Category identifier.")],
        response=resp_json([
            of("title", "string", True, "Category title."),
            of("uid", "string", True, "Category identifier."),
            of("description", "string", True, "Description."),
        ]), reason="CategoryDetail.get returns one visible category by uid.",
        evidence="files/views/categories.py:60-79; runtime 200")],
    sem_in_decisions=[dec("uid", "CategoryUID(category)", "identifier", reference_capable=True,
                          reason="Path uid selects the category.")],
    sem_out_decisions=[dec_for("category_uid", "CategoryUID(category)"),
                       dec("title", "CategoryTitle(category)", "attribute", reason="category title")],
    statuses=[200, 404], identity_statuses={"anonymous": [200, 404], "user": [200, 404], "admin": [200, 404]},
    route_confirmed=True,
    vis_reason="Category page fetch.",
    reach_conds=["Public read of a visible category."],
    evidence=[ev("source", "files/views/categories.py:60-79", "detail"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "200")],
))

A(node(
    key("/api/v1/tags"), "api", ["GET"],
    operation_semantic="list_tags",
    params=["page"],
    variants=[variant("GET",
        request_fields=[rf("page", "query", "integer", False, False, "Page number.")],
        response=paginated([
            of("title", "string", True, "Tag title (identifier)."),
            of("media_count", "integer", False, "Media count (summary)."),
        ]), reason="TagList.get paginated tags by media_count.",
        evidence="files/views/categories.py:103-123; runtime 200")],
    sem_in_decisions=[],
    sem_out_decisions=[dec_for("tag_title", "TagTitle(tag)")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="Tags page lists these.",
    reach_conds=["Public read."],
    evidence=[ev("source", "files/views/categories.py:103-123", "tag list")],
))

A(node(
    key("/api/v1/encode_profiles/"), "api", ["GET"],
    operation_semantic="list_encode_profiles",
    variants=[variant("GET", response=resp_json([
        of("name", "string", True, "Profile name."),
        of("resolution", "integer", False, "Resolution."),
        of("codec", "string", False, "Codec."),
    ]), reason="EncodeProfileList.get lists all encode profiles (no auth class).",
        evidence="files/views/encoding.py:9-22; runtime 200 all")],
    sem_in_decisions=[],
    sem_out_decisions=[dec("name", "EncodeProfileName(profile)", "identifier", reference_capable=True,
                          reason="Profile name identifies an encode profile.")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="Encode-profile list is served to any client.",
    reach_conds=["Public read (no permission class)."],
    evidence=[ev("source", "files/views/encoding.py:9-22", "no auth"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "200 all identities")],
    notes="No permission_classes set -> readable by anyone. See annotation_issues.",
))

# ----------------------------------------------------------------------------
# COMMENTS (global list)
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/comments"), "api", ["GET"],
    operation_semantic="list_comments",
    params=["page", "author"],
    variants=[variant("GET",
        request_fields=[rf("author", "query", "string", False, True, "Filter by author username.")],
        response=paginated([
            of("uid", "string", True, "Comment id."),
            of("text", "string", True, "Comment text."),
            of("author_name", "string", True, "Author name."),
            of("media_url", "string", False, "Media URL (presentation)."),
        ]), reason="CommentList.get lists comments on public media.",
        evidence="files/views/comments.py:29-61; runtime 200")],
    sem_in_decisions=[dec_for("author")],
    sem_out_decisions=[dec("uid", "CommentUID(comment)", "identifier", reference_capable=True, reason="Comment identifier."),
                       dec("text", "CommentText(comment)", "content", reason="comment text")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="Recent-comments listings.",
    reach_conds=["Public read (public media only)."],
    evidence=[ev("source", "files/views/comments.py:29-61", "global comment list")],
))

# ----------------------------------------------------------------------------
# PLAYLISTS
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/playlists"), "api", ["GET", "POST"],
    operation_semantic="browse_or_create_playlist",
    params=["author", "page"],
    variants=[
        variant("GET",
                request_fields=[rf("author", "query", "string", False, True, "Filter by owner username.")],
                response=paginated([
                    of("friendly_token", "string", True, "Playlist identifier."),
                    of("title", "string", True, "Playlist title."),
                    of("user", "string", True, "Owner username."),
                    of("media_count", "integer", False, "Media count (summary)."),
                ]),
                reason="PlaylistList.get paginated playlists.",
                evidence="files/views/playlists.py:30-51; runtime 200"),
        variant("POST",
                request_fields=[
                    rf("title", "body", "string", True, True, "Playlist title (new content)."),
                    rf("description", "body", "string", False, True, "Description."),
                ],
                response=resp_json([
                    of("friendly_token", "string", True, "Created playlist id."),
                    of("title", "string", True, "Title."),
                    of("user", "string", True, "Owner username."),
                ]),
                body_format="json",
                reason="PlaylistList.post creates a playlist owned by the user.",
                evidence="files/views/playlists.py:53-64"),
    ],
    sem_in_decisions=[dec_for("author"), dec("title", "PlaylistTitle(playlist)", "content", reason="playlist title"),
                      dec("description", "PlaylistDescription(playlist)", "content", reason="playlist description")],
    sem_out_decisions=[dec("friendly_token", "PlaylistToken(playlist)", "identifier", reference_capable=True,
                          reason="Created playlist friendly_token."),
                       dec("title", "PlaylistTitle(playlist)", "content", reason="playlist title"),
                       dec_for("user")],
    statuses=[200, 201, 400], identity_statuses={"anonymous": [200], "user": [200, 201], "admin": [200, 201]},
    route_confirmed=True,
    vis_reason="Playlists page + create form.",
    reach_conds=["POST: authenticated."],
    evidence=[ev("source", "files/views/playlists.py:24-64", "list/create"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
))

A(node(
    key("/api/v1/playlists/{friendly_token}"), "api", ["GET", "POST", "PUT", "DELETE"],
    operation_semantic="playlist_detail",
    variants=[
        variant("GET",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Playlist identifier.")],
                response=resp_json([
                    of("title", "string", True, "Title."),
                    of("description", "string", True, "Description."),
                    of("user", "string", True, "Owner username."),
                    of("playlist_media", "array", True, "Member media the user may see."),
                ]),
                reason="PlaylistDetail.get returns playlist + visible member media.",
                evidence="files/views/playlists.py:86-118; runtime 200"),
        variant("POST",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Playlist identifier."),
                                rf("title", "body", "string", False, True, "Updated title."),
                                rf("description", "body", "string", False, True, "Updated description.")],
                response=resp_json([of("title", "string", True, "Title."), of("description", "string", True, "Description.")]),
                body_format="json",
                reason="PlaylistDetail.post edits title/description; owner/editor.",
                evidence="files/views/playlists.py:120-134"),
        variant("PUT",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Playlist identifier."),
                                rf("type", "body", "string", True, False, "add|remove|ordering (discriminator)."),
                                rf("media_friendly_token", "body", "string", True, True, "Media to add/remove/reorder."),
                                rf("ordering", "body", "integer", False, True, "New position (ordering).")],
                response=resp_json([of("detail", "string", False, "Result message.")]),
                body_format="json",
                reason="PlaylistDetail.put adds/removes/reorders a media in the playlist; owner/editor.",
                evidence="files/views/playlists.py:136-196"),
        variant("DELETE",
                request_fields=[rf("friendly_token", "path", "string", True, True, "Playlist identifier.")],
                response=resp_empty(),
                reason="PlaylistDetail.delete removes the playlist; owner/editor.",
                evidence="files/views/playlists.py:198-210"),
    ],
    sem_in_decisions=[dec("friendly_token", "PlaylistToken(playlist)", "identifier", reference_capable=True,
                          reason="Path playlist token."),
                      dec("media_friendly_token", "MediaToken(media)", "identifier", reference_capable=True,
                          reason="Media added/removed/reordered."),
                      dec("title", "PlaylistTitle(playlist)", "content", reason="playlist title"),
                      dec("description", "PlaylistDescription(playlist)", "content", reason="playlist description"),
                      dec_for("ordering")],
    sem_out_decisions=[dec("title", "PlaylistTitle(playlist)", "content", reason="playlist title")],
    statuses=[200, 201, 400, 204], identity_statuses={"anonymous": [200], "user": [200, 201, 400, 204], "admin": [200, 201, 204]},
    route_confirmed=True,
    vis_reason="Playlist page + owner edit controls.",
    reach_conds=["GET public; POST/PUT/DELETE: owner or editor."],
    evidence=[ev("source", "files/views/playlists.py:67-210", "detail methods"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
))

# ----------------------------------------------------------------------------
# USER ACTIONS (likes/history etc)
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/user/action/{action}"), "api", ["GET"],
    operation_semantic="list_user_action_media",
    variants=[variant("GET",
        request_fields=[rf("action", "path", "string", True, False, "like|dislike|watch|report|rate (discriminator).")],
        response=paginated(MEDIA_ITEM),
        reason="UserActions.get lists media the user (or session) acted on.",
        evidence="files/views/user.py:15-45; runtime like 200")],
    sem_in_decisions=[],
    sem_out_decisions=[dec_for("friendly_token"), dec_for("title"), dec_for("user")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="History/liked pages fetch this.",
    reach_conds=["Authenticated for user-scoped results; anonymous uses session key."],
    evidence=[ev("source", "files/views/user.py:15-45", "action listing"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "like 200")],
))

# ----------------------------------------------------------------------------
# MANAGEMENT (editor/manager)
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/manage_media"), "api", ["GET", "DELETE"],
    operation_semantic="manage_media",
    params=["sort_by", "ordering", "state", "encoding_status", "media_type", "featured", "is_reviewed", "category"],
    variants=[
        variant("GET",
                request_fields=[rf("state", "query", "string", False, True, "Filter by state."),
                                rf("encoding_status", "query", "string", False, False, "Filter by encoding status.")],
                response=paginated(MEDIA_ITEM),
                reason="management_views.MediaList.get lists all media for editors.",
                evidence="files/management_views.py:20-118; runtime admin=200 user/anon=403"),
        variant("DELETE",
                request_fields=[rf("tokens", "query", "string", True, True, "Comma-separated media tokens to delete.")],
                response=resp_empty(),
                reason="management_views.MediaList.delete bulk-deletes media; managers only.",
                evidence="files/management_views.py:120-133"),
    ],
    sem_in_decisions=[dec_for("state"), dec_for("tokens")],
    sem_out_decisions=[dec_for("friendly_token"), dec_for("title"), dec_for("user"), dec_for("state")],
    statuses=[200, 204, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200, 204]},
    route_confirmed=True,
    vis_reason="Admin 'manage media' page.",
    reach_conds=["GET: editor/manager/admin.", "DELETE: manager/admin."],
    evidence=[ev("source", "files/management_views.py:20-133", "IsMediacmsEditor"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon/user=403, admin=200")],
))

A(node(
    key("/api/v1/manage_comments"), "api", ["GET", "DELETE"],
    operation_semantic="manage_comments",
    params=["sort_by", "ordering"],
    variants=[
        variant("GET", response=paginated([of("uid", "string", True, "Comment id."), of("text", "string", True, "Text.")]),
                reason="management_views.CommentList.get lists all comments for editors.",
                evidence="files/management_views.py:136-175; runtime admin=200"),
        variant("DELETE",
                request_fields=[rf("comment_ids", "query", "string", True, True, "Comma-separated comment uids.")],
                response=resp_empty(),
                reason="management_views.CommentList.delete bulk-deletes comments; editors.",
                evidence="files/management_views.py:177-188"),
    ],
    sem_in_decisions=[dec_for("comment_ids")],
    sem_out_decisions=[dec("uid", "CommentUID(comment)", "identifier", reference_capable=True, reason="Comment identifier.")],
    statuses=[200, 204, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200, 204]},
    route_confirmed=True,
    vis_reason="Admin 'manage comments' page.",
    reach_conds=["Editor/manager/admin."],
    evidence=[ev("source", "files/management_views.py:136-188", "IsMediacmsEditor"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon/user=403, admin=200")],
))

A(node(
    key("/api/v1/manage_users"), "api", ["GET", "DELETE"],
    operation_semantic="manage_users",
    params=["sort_by", "ordering", "role"],
    variants=[
        variant("GET",
                request_fields=[rf("role", "query", "string", False, False, "Filter by role.")],
                response=paginated([of("username", "string", True, "Username."), of("name", "string", True, "Name.")]),
                reason="management_views.UserList.get lists users for editors.",
                evidence="files/management_views.py:191-244; runtime admin=200"),
        variant("DELETE",
                request_fields=[rf("tokens", "query", "string", True, True, "Comma-separated usernames to delete.")],
                response=resp_empty(),
                reason="management_views.UserList.delete bulk-deletes users; managers only; cannot delete superuser unless admin.",
                evidence="files/management_views.py:246-262"),
    ],
    sem_in_decisions=[dec("tokens", "Username(user)", "identifier", reference_capable=True,
                          reason="Usernames to delete (comma-separated).")],
    sem_out_decisions=[dec_for("username", "Username(user)"), dec("name", "UserName(user)", "attribute", reason="display name")],
    statuses=[200, 204, 400, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200, 204]},
    route_confirmed=True,
    vis_reason="Admin 'manage users' page.",
    reach_conds=["GET: editor/manager/admin.", "DELETE: manager/admin; only admin may delete a superuser."],
    evidence=[ev("source", "files/management_views.py:191-262", "IsMediacmsEditor + manager delete"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon/user=403, admin=200")],
))

A(node(
    key("/api/v1/tasks"), "api", ["GET"],
    operation_semantic="list_tasks",
    variants=[variant("GET", response=resp_json([of("tasks", "array", False, "Active task descriptions.")]),
        reason="TasksList.get lists celery tasks; IsAdminUser.",
        evidence="files/views/tasks.py:8-17; runtime admin=200 else 403")],
    sem_in_decisions=[], sem_out_decisions=[],
    statuses=[200, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200]},
    route_confirmed=True,
    vis_reason="Admin tasks view.",
    reach_conds=["is_staff/admin."],
    evidence=[ev("source", "files/views/tasks.py:8-17", "IsAdminUser"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
))

A(node(
    key("/api/v1/tasks/{friendly_token}"), "api", ["DELETE"],
    operation_semantic="cancel_task",
    variants=[variant("DELETE",
        request_fields=[rf("friendly_token", "path", "string", True, True, "Task id.")],
        response=resp_empty(),
        reason="TaskDetail.delete returns 204 (revoke is commented out); IsAdminUser.",
        evidence="files/views/tasks.py:20-30")],
    sem_in_decisions=[dec("friendly_token", "TaskID(task)", "identifier", reference_capable=True,
                          reason="Path task id.")],
    sem_out_decisions=[],
    statuses=[204, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [204]},
    route_confirmed=False,
    vis_reason="Admin task cancel control.",
    reach_conds=["is_staff/admin."],
    evidence=[ev("source", "files/views/tasks.py:20-30", "IsAdminUser; no-op delete")],
    notes="Handler is a no-op (revoke commented out); DELETE always 204. See annotation_issues.",
))

A(node(
    key("/api/v1/media-auth"), "api", ["GET"],
    operation_semantic="authorize_protected_file",
    variants=[variant("GET",
        request_fields=[rf("X-Original-URI", "header", "string", True, False, "Original protected URI (from nginx).")],
        response=resp_raw("Empty 204 (allow) / 403 (deny) for nginx auth_request."),
        reason="media_auth authorizes an nginx auth_request for a protected media file.",
        evidence="files/views/media_auth.py:178-212")],
    sem_in_decisions=[], sem_out_decisions=[],
    statuses=[204, 403], identity_statuses={"anonymous": [204, 403], "user": [204, 403], "admin": [204, 403]},
    route_confirmed=False,
    vis_reason="Internal nginx subrequest; also directly callable.",
    reach_conds=["Decision from the X-Original-URI path and the caller's access to that media."],
    evidence=[ev("source", "files/views/media_auth.py:178-212", "path-only decision")],
))

# ----------------------------------------------------------------------------
# USERS
# ----------------------------------------------------------------------------
A(node(
    key("/api/v1/users"), "api", ["GET", "POST"],
    operation_semantic="browse_or_create_user",
    params=["page", "name", "exclude_self"],
    variants=[
        variant("GET",
                request_fields=[rf("name", "query", "string", False, True, "Search by name/username.")],
                response=paginated([
                    of("username", "string", True, "Username."),
                    of("name", "string", True, "Display name."),
                    of("is_editor", "boolean", False, "Editor flag."),
                ]),
                reason="users.UserList.get paginated user listing (anonymous allowed by default).",
                evidence="users/views.py:195-246; runtime anon=200"),
        variant("POST",
                request_fields=[
                    rf("username", "body", "string", True, True, "New username."),
                    rf("password", "body", "string", True, True, "New password (credential)."),
                    rf("email", "body", "string", True, True, "New email."),
                    rf("name", "body", "string", True, True, "Display name."),
                ],
                response=resp_json([of("username", "string", True, "Created username."), of("name", "string", True, "Name.")]),
                body_format="json",
                reason="users.UserList.post creates a user; managers only.",
                evidence="users/views.py:248-290"),
    ],
    sem_in_decisions=[dec("name", "UserName(user)", "attribute", reason="display name / search term"),
                      dec_for("username", "Username(user)"), dec_for("password"), dec_for("email")],
    sem_out_decisions=[dec_for("username", "Username(user)"),
                       dec("name", "UserName(user)", "attribute", reason="display name")],
    statuses=[200, 201, 400, 403], identity_statuses={"anonymous": [200], "user": [200, 403], "admin": [200, 201, 400]},
    route_confirmed=True,
    vis_reason="Members page lists users; admin create-user form.",
    reach_conds=["GET: public (ALLOW_ANONYMOUS_USER_LISTING=True).", "POST: manager/admin."],
    evidence=[ev("source", "users/views.py:195-290", "list/create"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET anon=200")],
))

A(node(
    key("/api/v1/users/{username}"), "api", ["GET", "POST", "PUT", "DELETE"],
    operation_semantic="user_detail",
    variants=[
        variant("GET",
                request_fields=[rf("username", "path", "string", True, True, "Target username.")],
                response=resp_json([
                    of("username", "string", True, "Username."),
                    of("name", "string", True, "Display name."),
                    of("description", "string", True, "Bio."),
                    of("media_info", "object", False, "Media stats (summary)."),
                ]),
                reason="UserDetail.get returns a user's public profile.",
                evidence="users/views.py:319-326; runtime 200"),
        variant("POST",
                request_fields=[rf("username", "path", "string", True, True, "Target username."),
                                rf("name", "body", "string", False, True, "Updated name."),
                                rf("description", "body", "string", False, True, "Updated bio."),
                                rf("logo", "body", "file", False, True, "Avatar image.")],
                response=resp_json([of("username", "string", True, "Username."), of("name", "string", True, "Name.")]),
                body_format="form",
                reason="UserDetail.post edits profile; self or manager.",
                evidence="users/views.py:340-355"),
        variant("PUT",
                request_fields=[rf("username", "path", "string", True, True, "Target username."),
                                rf("action", "body", "string", True, False, "change_password|approve_user|disapprove_user."),
                                rf("password", "body", "string", False, True, "New password (change_password).")],
                response=resp_json([of("username", "string", True, "Username.")]),
                body_format="form",
                reason="UserDetail.put changes password (self/manager) or approves a user (manager).",
                evidence="users/views.py:366-401"),
        variant("DELETE",
                request_fields=[rf("username", "path", "string", True, True, "Target username.")],
                response=resp_empty(),
                reason="UserDetail.delete removes a user and their media; self, or manager/admin (admin for superuser).",
                evidence="users/views.py:409-419"),
    ],
    sem_in_decisions=[dec_for("username", "Username(user)"), dec("name", "UserName(user)", "attribute", reason="display name"),
                      dec("description", "UserDescription(user)", "content", reason="profile bio"),
                      dec_for("logo"), dec_for("password")],
    sem_out_decisions=[dec_for("username", "Username(user)"), dec("name", "UserName(user)", "attribute", reason="display name")],
    statuses=[200, 201, 400], identity_statuses={"anonymous": [200, 400], "user": [200, 201, 400], "admin": [200, 201, 204]},
    route_confirmed=True,
    vis_reason="User profile page + edit/password/delete controls.",
    reach_conds=["GET public; POST/PUT/DELETE: self or manager; only admin may act on a superuser."],
    evidence=[ev("source", "users/views.py:293-419", "detail methods + split"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "GET 200")],
))

A(node(
    key("/api/v1/users/{username}/contact"), "api", ["POST"],
    operation_semantic="contact_user",
    variants=[variant("POST",
        request_fields=[rf("username", "path", "string", True, True, "Recipient username."),
                        rf("body", "body", "string", True, True, "Message body.")],
        response=resp_empty(),
        body_format="json",
        reason="contact_user emails the target user if they allow contact; authenticated only.",
        evidence="users/views.py:161-192")],
    sem_in_decisions=[dec_for("username", "Username(user)"), dec_for("body")],
    sem_out_decisions=[],
    statuses=[204, 401], identity_statuses={"anonymous": [401], "user": [204], "admin": [204]},
    route_confirmed=False,
    vis_reason="Contact form on a user profile.",
    reach_conds=["Authenticated; recipient has allow_contact or caller is editor.",
                 "EXTERNAL DEPENDENCY: SMTP for actual delivery (send is fail_silently)."],
    evidence=[ev("source", "users/views.py:161-192", "api_view POST, auth check")],
))

A(node(
    key("/api/v1/whoami"), "api", ["GET"],
    operation_semantic="read_own_profile",
    variants=[variant("GET", response=resp_json([
        of("username", "string", True, "Own username."),
        of("name", "string", True, "Name."),
        of("edit_url", "string", False, "Edit URL (presentation)."),
    ]), reason="UserWhoami.get returns the authenticated user's own detail.",
        evidence="users/views.py:422-438; runtime anon=403 user=200")],
    sem_in_decisions=[],
    sem_out_decisions=[dec_for("username", "Username(user)"), dec("name", "UserName(user)", "attribute", reason="display name")],
    statuses=[200, 403], identity_statuses={"anonymous": [403], "user": [200], "admin": [200]},
    route_confirmed=True,
    vis_reason="SPA bootstraps the session user from whoami.",
    reach_conds=["Authenticated."],
    evidence=[ev("source", "users/views.py:422-438", "IsAuthenticated"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403 user=200")],
))

A(node(
    key("/api/v1/user/token"), "api", ["GET"],
    operation_semantic="read_api_token",
    variants=[variant("GET", response=resp_json([of("token", "string", True, "The caller's DRF auth token (credential).")]),
        reason="UserToken.get returns (creating if needed) the caller's API token.",
        evidence="users/views.py:441-456; runtime anon=403 user=200")],
    sem_in_decisions=[],
    sem_out_decisions=[dec("token", "AuthToken(session)", "credential", reason="DRF token for the caller.")],
    statuses=[200, 403], identity_statuses={"anonymous": [403], "user": [200], "admin": [200]},
    route_confirmed=True,
    vis_reason="API-token retrieval for the logged-in user.",
    reach_conds=["Authenticated."],
    evidence=[ev("source", "users/views.py:441-456", "IsAuthenticated token"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "anon=403 user=200")],
))

A(node(
    key("/api/v1/login"), "api", ["POST"],
    operation_semantic="login",
    variants=[variant("POST",
        request_fields=[rf("username", "body", "string", False, True, "Username (or use email)."),
                        rf("email", "body", "string", False, True, "Email (or use username)."),
                        rf("password", "body", "string", True, True, "Password (credential).")],
        response=resp_json([of("username", "string", True, "Authenticated username."),
                            of("email", "string", True, "Email."),
                            of("token", "string", True, "Issued DRF token (credential).")]),
        body_format="form",
        reason="users.LoginView.post authenticates and returns a token; AllowAny.",
        evidence="users/views.py:459-482; users/serializers.py:95-138; runtime no-body=400")],
    sem_in_decisions=[dec_for("username", "Username(user)"), dec_for("email"), dec_for("password")],
    sem_out_decisions=[dec_for("username", "Username(user)"), dec_for("email"),
                       dec("token", "AuthToken(session)", "credential", reason="issued token")],
    statuses=[200, 400], identity_statuses={"anonymous": [200, 400], "user": [200, 400], "admin": [200, 400]},
    route_confirmed=True,
    vis_reason="Login form posts credentials here.",
    reach_conds=["Valid credentials of an active (approved) account."],
    evidence=[ev("source", "users/views.py:459-482", "AllowAny login"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "no-body=400")],
))

# ----------------------------------------------------------------------------
# MIGRATION SERVICE (superuser)  -- ModelViewSet + @action routes
# ----------------------------------------------------------------------------
MIG_ITEM = [
    of("id", "integer", True, "Migration id."),
    of("name", "string", True, "Migration name."),
    of("provider", "string", True, "Source provider."),
    of("status", "string", True, "Migration status."),
]

A(node(
    key("/api/v1/migrations/"), "api", ["GET", "POST"],
    operation_semantic="browse_or_create_migration",
    variants=[
        variant("GET", response=paginated(MIG_ITEM),
                reason="MigrationServiceViewSet list; IsSuperUser.",
                evidence="migrationservice/views.py:38-41; runtime admin=200 else 403"),
        variant("POST",
                request_fields=[rf("name", "body", "string", True, True, "Migration name."),
                                rf("provider", "body", "string", True, True, "Source provider."),
                                rf("connection", "body", "object", False, False, "Source credentials."),
                                rf("options", "body", "object", False, False, "Migration options.")],
                response=resp_json(MIG_ITEM), body_format="json",
                reason="ModelViewSet create -> schedules the migration.",
                evidence="migrationservice/views.py:137-141"),
    ],
    sem_in_decisions=[dec("name", "MigrationName(migration)", "content", reason="migration name"), dec_for("provider")],
    sem_out_decisions=[dec("id", "MigrationID(migration)", "identifier", reference_capable=True, reason="migration id"),
                       dec("provider", "MigrationProvider(migration)", "attribute", reason="provider")],
    statuses=[200, 201, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200, 201]},
    route_confirmed=True,
    vis_reason="Admin migrations dashboard.",
    reach_conds=["Superuser."],
    evidence=[ev("source", "migrationservice/views.py:38-141", "IsSuperUser viewset"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "admin=200 else 403")],
))

A(node(
    key("/api/v1/migrations/{pk}/"), "api", ["GET", "PUT", "PATCH", "DELETE"],
    operation_semantic="migration_detail",
    variants=[
        variant("GET", request_fields=[rf("pk", "path", "integer", True, True, "Migration id.")],
                response=resp_json(MIG_ITEM), reason="ViewSet retrieve.",
                evidence="migrationservice/views.py:38-41"),
        variant("PUT", request_fields=[rf("pk", "path", "integer", True, True, "Migration id."),
                                       rf("name", "body", "string", False, True, "Name."),
                                       rf("options", "body", "object", False, False, "Options.")],
                response=resp_json(MIG_ITEM), body_format="json", reason="ViewSet update -> reschedule.",
                evidence="migrationservice/views.py:143-144"),
        variant("PATCH", request_fields=[rf("pk", "path", "integer", True, True, "Migration id.")],
                response=resp_json(MIG_ITEM), body_format="json", reason="ViewSet partial update.",
                evidence="migrationservice/views.py:143-144"),
        variant("DELETE", request_fields=[rf("pk", "path", "integer", True, True, "Migration id.")],
                response=resp_empty(), reason="ViewSet destroy.",
                evidence="migrationservice/views.py:38-41"),
    ],
    sem_in_decisions=[dec_for("pk"), dec("name", "MigrationName(migration)", "content", reason="name")],
    sem_out_decisions=[dec("id", "MigrationID(migration)", "identifier", reference_capable=True, reason="migration id")],
    statuses=[200, 204, 403], identity_statuses={"anonymous": [403], "user": [403], "admin": [200, 204]},
    route_confirmed=False,
    vis_reason="Migration dashboard detail.",
    reach_conds=["Superuser."],
    evidence=[ev("source", "migrationservice/views.py:38-144", "ModelViewSet detail")],
))

# migration @action routes (all IsSuperUser; POST transitions / GET reads)
def mig_action(suffix, methods, op, desc, detail=True, inputs=None, outputs=None):
    reqf = [rf("pk", "path", "integer", True, True, "Migration id.")] if detail else []
    reqf += (inputs or [])
    vlist = []
    for m in methods:
        vlist.append(variant(m, request_fields=reqf if m != "GET" else [f for f in reqf if f["location"] != "body"],
                              response=resp_json(outputs or [of("ok", "boolean", False, desc)]),
                              body_format="json" if m in ("POST", "PUT") else "none",
                              reason=desc, evidence="migrationservice/views.py"))
    return node(
        key("/api/v1/migrations/" + suffix), "api", methods,
        operation_semantic=op,
        variants=vlist,
        sem_in_decisions=([dec_for("pk")] if detail else []),
        sem_out_decisions=[],
        statuses=[200, 403, 409], identity_statuses={"anonymous": [403], "user": [403], "admin": [200]},
        route_confirmed=False,
        visibility="black_box",
        vis_reason="Migration dashboard control.",
        reach_conds=["Superuser.", "EXTERNAL DEPENDENCY: reachable source system (Kaltura etc.) for connection/category/role checks."],
        evidence=[ev("source", "migrationservice/views.py", desc)],
    )

for suf, meth, op, desc, det in [
    ("{pk}/start/", ["POST"], "start_migration", "Start a saved migration.", True),
    ("{pk}/resume/", ["POST"], "resume_migration", "Resume a paused migration.", True),
    ("{pk}/rerun/", ["POST"], "rerun_migration", "Re-run a finished migration.", True),
    ("{pk}/pause/", ["POST"], "pause_migration", "Pause a running migration.", True),
    ("{pk}/abort/", ["POST"], "abort_migration", "Abort a migration.", True),
    ("{pk}/records/", ["GET"], "list_migration_records", "List mapping records of a migration.", True),
    ("{pk}/progress/", ["GET"], "read_migration_progress", "Poll progress of a migration.", True),
    ("{pk}/check_connection/", ["POST"], "check_migration_connection", "Test stored source credentials.", True),
    ("{pk}/source_categories/", ["POST"], "list_migration_source_categories", "List source categories (saved).", True),
    ("{pk}/source_roles/", ["POST"], "list_migration_source_roles", "List source roles (saved).", True),
    ("check_connection/", ["POST"], "check_unsaved_connection", "Test typed source credentials.", False),
    ("source_categories/", ["POST"], "list_unsaved_source_categories", "List source categories (unsaved).", False),
    ("source_roles/", ["POST"], "list_unsaved_source_roles", "List source roles (unsaved).", False),
    ("server_time/", ["GET"], "read_server_time", "Portal clock for the scheduling form.", False),
    ("lti_platforms/", ["GET"], "list_lti_platforms", "LTI platforms a course can bind to.", False),
]:
    A(mig_action(suf, meth, op, desc, det))

# ----------------------------------------------------------------------------
# UPLOADER
# ----------------------------------------------------------------------------
A(node(
    key("/fu/upload/"), "api", ["POST"],
    operation_semantic="chunked_upload",
    variants=[variant("POST",
        request_fields=[rf("qqfile", "body", "file", True, True, "Uploaded file chunk."),
                        rf("qquuid", "body", "string", False, False, "Upload uuid."),
                        rf("qqtotalparts", "body", "integer", False, False, "Total chunks.")],
        response=resp_json([of("success", "boolean", False, "Outcome."),
                            of("media_url", "string", True, "Created media URL.")]),
        body_format="form",
        reason="FineUploaderView handles chunked uploads; creates a Media on completion; upload permission required.",
        evidence="uploader/views.py:19-76")],
    sem_in_decisions=[dec("qqfile", "MediaFile(media)", "content", reason="uploaded chunk/file")],
    sem_out_decisions=[dec("media_url", "MediaURL(media)", "locator", reference_capable=True,
                          reason="URL of the created media.")],
    statuses=[200, 400, 403], identity_statuses={"anonymous": [403], "user": [200, 400], "admin": [200, 400]},
    route_confirmed=False,
    vis_reason="Drag-and-drop uploader posts chunks here.",
    reach_conds=["Authenticated with upload permission."],
    evidence=[ev("source", "uploader/views.py:19-76", "user_allowed_to_upload gate")],
))

# ----------------------------------------------------------------------------
# LTI (USE_LTI=False in this deployment; routes still mounted)
# ----------------------------------------------------------------------------
A(node(
    key("/lti/jwks/"), "api", ["GET"],
    operation_semantic="read_lti_jwks",
    variants=[variant("GET", response=resp_json([of("keys", "array", True, "JWKS public keys.")]),
        reason="JWKSView.get serves the tool's public JWKS.",
        evidence="lti/views.py:655-666; runtime 200 all")],
    sem_in_decisions=[], sem_out_decisions=[dec("keys", "LTIPublicKey(tool)", "credential", mergeable=False, reason="public JWKS")],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="LTI platforms fetch the tool JWKS; publicly served.",
    reach_conds=["Public read."],
    evidence=[ev("source", "lti/views.py:655-666", "public JWKS"),
              ev("runtime", "mediacms_gt/runtime_probe.txt", "200 all")],
))

A(node(
    key("/lti/public-key/"), "api", ["GET"],
    operation_semantic="read_lti_public_key",
    variants=[variant("GET", response=resp_raw("PEM public key text."), content_types=["text/plain"],
        reason="PublicKeyPEMView.get serves the tool public key as PEM.",
        evidence="lti/views.py:669-674; runtime 200 all")],
    sem_in_decisions=[], sem_out_decisions=[],
    statuses=[200], identity_statuses=ST_READ_PUBLIC, route_confirmed=True,
    vis_reason="LTI key distribution; publicly served.",
    reach_conds=["Public read."],
    evidence=[ev("source", "lti/views.py:669-674", "public key PEM")],
))

# ----------------------------------------------------------------------------
# PAGES (kind=page) and auth flows -- not L2 candidates
# ----------------------------------------------------------------------------
PAGE_NODES = []


def P(path, name, methods=None, vis_reason="Server-rendered page in the MediaCMS SPA/template set.",
      reach_conds=None, statuses=None, ident=None, evidence=None, notes=None, confirmed=False):
    PAGE_NODES.append(node(
        key(path), "page", methods or ["GET"],
        operation_semantic="",
        statuses=statuses or [200],
        identity_statuses=ident or ST_READ_PUBLIC,
        route_confirmed=confirmed,
        visibility="black_box", vis_reason=vis_reason,
        reach_conds=reach_conds or ["Public."],
        evidence=evidence or [ev("source", "files/urls.py / users/urls.py", "Registered page route")],
        notes=notes,
    ))


# core SPA + content pages
for path, name in [
    ("/", "index"), ("/about", "about"), ("/featured", "featured"), ("/history", "history"),
    ("/liked", "liked"), ("/latest", "latest"), ("/members", "members"), ("/popular", "popular"),
    ("/recommended", "recommended"), ("/search", "search_page"), ("/tags", "tags_page"),
    ("/categories", "categories_page"), ("/tos", "tos"), ("/contact", "contact"),
    ("/upload", "upload_page"), ("/scpublisher", "scpublisher"), ("/record_screen", "record_screen"),
    ("/embed", "embed_media"), ("/publish", "publish_media"),
    ("/edit", "edit_media_page"), ("/edit_video", "edit_video_page"), ("/edit_chapters", "edit_chapters_page"),
    ("/replace_media", "replace_media"), ("/add_subtitle", "add_subtitle"), ("/edit_subtitle", "edit_subtitle"),
    ("/manage/media", "manage_media_page"), ("/manage/comments", "manage_comments_page"),
    ("/manage/users", "manage_users_page"), ("/playlist/{friendly_token}", "view_playlist"),
    ("/playlists/{friendly_token}", "view_playlist2"), ("/edit_category/{uid}", "edit_category"),
    ("/user/{username}", "user_profile"), ("/user/{username}/about", "user_about"),
    ("/user/{username}/playlists", "user_playlists"), ("/user/{username}/edit", "user_edit"),
    ("/user/{username}/shared_with_me", "shared_with_me"), ("/user/{username}/shared_by_me", "shared_by_me"),
    ("/channel/{friendly_token}", "view_channel"), ("/channel/{friendly_token}/edit", "edit_channel"),
    ("/{slug}", "flat_page"),
]:
    P(path, name)

P("/view", "view_media_page", vis_reason="Media watch page.", confirmed=True,
  evidence=[ev("runtime", "http GET / -> 200", "SPA entry reachable")])

# migrations pages (superuser)
for path in ["/migrations", "/migrations/new", "/migrations/new/{source}",
             "/migrations/{pk}", "/migrations/{pk}/edit"]:
    P(path, path, vis_reason="Migration admin page.",
      reach_conds=["Superuser (else redirect to /)."], ident={"anonymous": [302], "user": [302], "admin": [200]},
      statuses=[200, 302], evidence=[ev("source", "migrationservice/views.py:253-287", "login_required + superuser")])

# auth pages (allauth) -- GET renders, POST acts
P("/accounts/login/", "account_login", methods=["GET", "POST"],
  vis_reason="allauth login page.", statuses=[200, 302],
  ident={"anonymous": [200, 302], "user": [200, 302], "admin": [200, 302]},
  reach_conds=["Public."], evidence=[ev("source", "cms/urls.py:28 allauth.urls", "account_login")])
P("/accounts/signup/", "account_signup", methods=["GET", "POST"],
  vis_reason="allauth registration page.", statuses=[200, 302],
  reach_conds=["Public; USERS_CAN_SELF_REGISTER=True."],
  evidence=[ev("source", "allauth.account.views.SignupView", "account_signup")])
P("/accounts/logout/", "account_logout", methods=["GET", "POST"],
  vis_reason="allauth logout.", statuses=[200, 302],
  reach_conds=["Authenticated."], evidence=[ev("source", "allauth logout", "account_logout")])
P("/accounts/password/change/", "account_change_password", methods=["GET", "POST"],
  vis_reason="allauth change password.", statuses=[200, 302],
  reach_conds=["Authenticated."], evidence=[ev("source", "allauth", "account_change_password")])
P("/accounts/password/reset/", "account_reset_password", methods=["GET", "POST"],
  vis_reason="allauth password reset request.", statuses=[200, 302],
  reach_conds=["Public.", "EXTERNAL DEPENDENCY: SMTP to deliver the reset email."],
  evidence=[ev("source", "allauth", "account_reset_password")])
P("/accounts/email/", "account_email", methods=["GET", "POST"],
  vis_reason="allauth manage email addresses.", statuses=[200, 302],
  reach_conds=["Authenticated."], evidence=[ev("source", "allauth", "account_email")])

# docs / spec / robots / rss (static-ish)
P("/swagger/", "swagger_ui", vis_reason="drf-yasg Swagger UI (schema generation errors; see issues).",
  confirmed=True, evidence=[ev("runtime", "GET /swagger.json -> 200 error page", "schema gen crash")])
P("/docs/api/", "redoc", vis_reason="drf-yasg ReDoc page.")
P("/swagger.json", "swagger_json", vis_reason="OpenAPI schema endpoint (returns an error page in this build).",
  confirmed=True, statuses=[200],
  evidence=[ev("runtime", "mediacms_gt/runtime_probe.txt", "200 but HTML error body")],
  notes="Schema generation crashes; body is the MediaCMS error template, not JSON. See issue-001.")
P("/robots.txt", "robots", vis_reason="robots.txt.", evidence=[ev("source", "cms/urls.py:21-24", "TemplateView")])
P("/rss/", "rss_index", vis_reason="Index RSS feed.", evidence=[ev("source", "files/feeds.py", "IndexRSSFeed")])
P("/rss/search", "rss_search", vis_reason="Search RSS feed.", evidence=[ev("source", "files/feeds.py", "SearchRSSFeed")])

# ----------------------------------------------------------------------------
# EDGES -- real navigation/request transitions
# ----------------------------------------------------------------------------
EDGES = [
    {"src": key("/view"), "dst": key("/api/v1/media/{friendly_token}"), "methods": ["GET"], "triggers": ["fetch"],
     "gt": {"evidence": [ev("source", "frontend media page", "Watch page fetches media detail")]}},
    {"src": key("/view"), "dst": key("/api/v1/media/{friendly_token}/comments"), "methods": ["GET", "POST"], "triggers": ["xhr"],
     "gt": {"evidence": [ev("source", "frontend media page", "Comments widget")]}},
    {"src": key("/view"), "dst": key("/api/v1/media/{friendly_token}/actions"), "methods": ["POST"], "triggers": ["xhr"],
     "gt": {"evidence": [ev("source", "frontend media page", "Like/dislike/report buttons")]}},
    {"src": key("/"), "dst": key("/api/v1/media"), "methods": ["GET"], "triggers": ["fetch"],
     "gt": {"evidence": [ev("runtime", "home page", "Home lists media")]}},
    {"src": key("/search"), "dst": key("/api/v1/search"), "methods": ["GET"], "triggers": ["fetch"],
     "gt": {"evidence": [ev("source", "frontend search page", "Search box")]}},
    {"src": key("/members"), "dst": key("/api/v1/users"), "methods": ["GET"], "triggers": ["fetch"],
     "gt": {"evidence": [ev("source", "frontend members page", "Members listing")]}},
    {"src": key("/upload"), "dst": key("/fu/upload/"), "methods": ["POST"], "triggers": ["xhr"],
     "gt": {"evidence": [ev("source", "frontend uploader", "Chunked upload")]}},
    {"src": key("/accounts/login/"), "dst": key("/api/v1/whoami"), "methods": ["GET"], "triggers": ["fetch", "redirect"],
     "gt": {"evidence": [ev("source", "SPA bootstrap", "whoami after login")]}},
    {"src": key("/manage/media"), "dst": key("/api/v1/manage_media"), "methods": ["GET"], "triggers": ["fetch"],
     "gt": {"evidence": [ev("source", "admin manage page", "manage media listing")]}},
]
