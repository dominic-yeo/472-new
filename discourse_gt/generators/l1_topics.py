# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Topics (TopicsController). Routes under /t and /topics,
config/routes.rb ~1543-1738. Source app/controllers/topics_controller.rb (1733 lines).
Read-view aliases (show/print/summary/feed/by external id) grouped into t/{id}.
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, dec, ev

T = "app/controllers/topics_controller.rb"
PUB = {"anonymous": [200, 403, 404], "user": [200]}
USER = {"anonymous": [403], "user": [200]}
STAFF = {"anonymous": [403], "user": [403], "staff": [200]}
ADMIN = {"anonymous": [403], "user": [403], "staff": [403], "admin": [200]}
PID = [{"name": "topic_id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."}]


def n(path, methods, sem, idst, variants, vis_reason, src, notes=None, params=None, statuses=None, sin=None, sout=None):
    return node(K(path), "api", methods, variants=variants, operation_semantic=sem,
                statuses=statuses or [200, 403, 404], identity_statuses=idst, params=params if params is not None else PID,
                sem_in_decisions=sin or [], sem_out_decisions=sout or [], route_confirmed=True,
                vis_reason=vis_reason, evidence=[ev("source", src, sem)], notes=notes)


def V(method, fields=None, resp=None, reason="", src="", ex=None):
    return variant(method, body_format="json" if fields else "none", body_example=ex or {},
                   request_fields=fields or [], response=resp if resp is not None else resp_empty(),
                   reason=reason, evidence=src)


NODES = [
    n("/t/{id}", ["GET", "PUT", "DELETE"], "topic_crud", PUB,
      [V("GET", resp=resp_json([of("post_stream", "object", True, "Posts + participants."),
                                of("title", "string", True, "Topic title.")]),
         reason="Reads a topic (post stream). Groups print/summary/feed/by-external-id views.", src=f"{T}:77"),
       V("PUT", [rf("title", "body", "string", required=False, flow=True, description="New title."),
                 rf("category_id", "body", "integer", required=False, flow=True, description="New category."),
                 rf("tags", "body", "array", required=False, flow=True, description="Tags.")],
         resp_json([of("basic_topic", "object", True, "Updated topic.")]),
         reason="Edits topic title/category/tags.", src=f"{T}:433", ex={"title": "New title"}),
       V("DELETE", reason="Soft-deletes a topic.", src=f"{T}:786")],
      "Public read; author/staff edit+delete.", f"{T}:77",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."}],
      notes="PRIMARY content read. Edit/delete via Guardian; title/category changes are moderation-relevant.",
      sin=[dec("title", "TopicTitle(content)", "content", reason="Topic title (rendered)."),
           dec("category_id", "CategoryId(taxonomy)", "identifier", reference_capable=True, reason="Target category.")],
      sout=[dec("post_stream", "PostStream(content)", "content", reason="Topic posts + participants.")]),

    n("/t/{topic_id}/posts", ["GET"], "topic_posts", PUB,
      [V("GET", resp=resp_json([of("post_stream", "object", True, "Requested posts.")]),
         reason="Loads a slice of the topic's posts.", src=f"{T}:309")],
      "Public read (visibility-gated).", f"{T}:309", notes="Groups post_ids + excerpts readers."),

    n("/t/{topic_id}/recover", ["PUT"], "recover_topic", STAFF,
      [V("PUT", reason="Restores a soft-deleted topic.", src=f"{T}:812")], "Author/staff restore.", f"{T}:812"),

    n("/t/{topic_id}/status", ["PUT"], "set_topic_status", STAFF,
      [V("PUT", [rf("status", "body", "string", required=True, flow=True, description="closed/archived/visible/pinned/..."),
                 rf("enabled", "body", "boolean", required=True, flow=True, description="On/off.")],
         reason="Opens/closes/archives/pins/unlists a topic.", src=f"{T}:587", ex={"status": "closed", "enabled": "true"})],
      "Staff/author status change.", f"{T}:587", notes="Moderation state transitions."),

    n("/t/{topic_id}/mute", ["PUT"], "mute_topic", USER,
      [V("PUT", reason="Mutes a topic for the caller.", src=f"{T}:638")], "Self mute.", f"{T}:638",
      notes="Groups /unmute."),

    n("/t/{topic_id}/timer", ["POST"], "set_topic_timer", STAFF,
      [V("POST", [rf("time", "body", "string", required=False, flow=True, description="When."),
                  rf("status_type", "body", "string", required=True, flow=True, description="close/open/delete/publish_to_category/...")],
         resp_json([of("execute_at", "string", False, "Scheduled time.")]),
         reason="Schedules an automated topic action (close/delete/publish).", src=f"{T}:646")],
      "Staff topic timer.", f"{T}:646", notes="Schedules a future state change (incl. auto-delete/publish)."),

    n("/t/{topic_id}/make-banner", ["PUT"], "make_banner", ADMIN,
      [V("PUT", reason="Promotes a topic to the global banner.", src=f"{T}:704")], "Admin banner.", f"{T}:704",
      notes="Global site banner (shown to all users); groups /remove-banner."),

    n("/t/{id}/publish", ["PUT"], "publish_topic", STAFF,
      [V("PUT", [rf("destination_category_id", "body", "integer", required=True, flow=True, description="Target category.")],
         reason="Publishes a shared draft to a category.", src=f"{T}:244", ex={"destination_category_id": 3})],
      "Staff publish.", f"{T}:244",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."}]),

    n("/t/{id}/shared-draft", ["PUT"], "update_shared_draft", STAFF,
      [V("PUT", [rf("category_id", "body", "integer", required=True, flow=True, description="Draft category.")],
         reason="Updates a shared-draft's target category.", src=f"{T}:414")], "Staff shared draft.", f"{T}:414",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."}]),

    n("/t/{id}/convert-topic/{type}", ["PUT"], "convert_topic", STAFF,
      [V("PUT", reason="Converts between public topic and private message.", src=f"{T}:1323")],
      "Staff convert.", f"{T}:1323", notes="PM<->public conversion changes who can see the content.",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."},
              {"name": "type", "in": "path", "type": "string", "required": True, "flow": True, "description": "public|private."}]),

    n("/t/{topic_id}/tags", ["PUT"], "update_topic_tags", USER,
      [V("PUT", [rf("tags", "body", "array", required=True, flow=True, description="Tag names.")],
         reason="Replaces a topic's tags.", src=f"{T}:529", ex={"tags": ["a", "b"]})], "Author/staff tagging.", f"{T}:529",
      sin=[dec("tags", "TagSet(taxonomy)", "collection", reason="Topic tags.")]),

    n("/t/{topic_id}/invite", ["POST"], "invite_to_topic", USER,
      [V("POST", [rf("user", "body", "string", required=False, flow=True, description="Username to invite."),
                  rf("email", "body", "string", required=False, flow=True, description="Email to invite.")],
         reason="Invites a user (or email) to a topic/PM.", src=f"{T}:887", ex={"user": "bob"})],
      "Participant invite.", f"{T}:887", notes="On PMs this grants read access to another user.",
      sin=[dec("email", "InviteEmail(identity)", "identifier", reference_capable=True, reason="Invitee email.")]),

    n("/t/{topic_id}/invite-group", ["POST"], "invite_group_to_topic", USER,
      [V("POST", [rf("group", "body", "string", required=True, flow=True, description="Group name.")],
         reason="Invites a group to a topic/PM.", src=f"{T}:854", ex={"group": "team"})], "Group invite.", f"{T}:854",
      notes="Grants a whole group access to a PM."),

    n("/t/{topic_id}/remove-allowed-user", ["PUT"], "remove_allowed_user", USER,
      [V("PUT", [rf("username", "body", "string", required=True, flow=True, description="User to remove.")],
         reason="Removes an allowed user from a PM.", src=f"{T}:826", ex={"username": "bob"})],
      "PM participant removal.", f"{T}:826", notes="Groups /remove-allowed-group."),

    n("/t/{topic_id}/move-posts", ["POST"], "move_posts", STAFF,
      [V("POST", [rf("post_ids", "body", "array", required=True, flow=True, description="Posts to move."),
                  rf("destination_topic_id", "body", "integer", required=False, flow=True, description="Target topic."),
                  rf("title", "body", "string", required=False, flow=True, description="New topic title if splitting.")],
         reason="Moves/splits posts into another or new topic.", src=f"{T}:999", ex={"post_ids": [2, 3]})],
      "Staff move/split.", f"{T}:999"),

    n("/t/{topic_id}/merge-topic", ["POST"], "merge_topic", STAFF,
      [V("POST", [rf("destination_topic_id", "body", "integer", required=True, flow=True, description="Topic to merge into.")],
         reason="Merges this topic into another.", src=f"{T}:964", ex={"destination_topic_id": 9})], "Staff merge.", f"{T}:964"),

    n("/t/{topic_id}/change-owner", ["POST"], "change_post_owners", STAFF,
      [V("POST", [rf("username", "body", "string", required=True, flow=True, description="New owner."),
                  rf("post_ids", "body", "array", required=True, flow=True, description="Posts to reassign.")],
         reason="Reassigns authorship of posts.", src=f"{T}:1040", ex={"username": "bob", "post_ids": [2]})],
      "Staff/admin owner change.", f"{T}:1040", notes="Rewrites post authorship (attribution integrity)."),

    n("/t/{topic_id}/change-timestamp", ["PUT"], "change_timestamps", STAFF,
      [V("PUT", [rf("timestamp", "body", "string", required=True, flow=True, description="New created_at.")],
         reason="Rewrites a topic's timestamps.", src=f"{T}:1060", ex={"timestamp": "1700000000"})],
      "Staff timestamp edit.", f"{T}:1060"),

    n("/t/{topic_id}/timings", ["POST"], "topic_timings", USER,
      [V("POST", [rf("topic_time", "body", "integer", required=False, flow=False, description="Total time."),
                  rf("timings", "body", "object", required=False, flow=False, description="Per-post read times.")],
         reason="Records read state / time spent.", src=f"{T}:1098")], "Self read-tracking.", f"{T}:1098"),

    n("/t/{topic_id}/bookmark", ["PUT"], "bookmark_topic", USER,
      [V("PUT", reason="Bookmarks the topic for the caller.", src=f"{T}:775")], "Self bookmark.", f"{T}:775",
      notes="Groups /remove_bookmarks."),

    n("/t/{topic_id}/notifications", ["POST"], "set_topic_notifications", USER,
      [V("POST", [rf("notification_level", "body", "integer", required=True, flow=True, description="watching/tracking/muted/...")],
         reason="Sets the caller's notification level for a topic.", src=f"{T}:955", ex={"notification_level": 3})],
      "Self notification level.", f"{T}:955"),

    n("/t/{id}/archive-message", ["PUT"], "archive_pm", USER,
      [V("PUT", reason="Archives/moves a PM to inbox for the caller.", src=f"{T}:729")], "Self PM archive.", f"{T}:729",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Topic id."}],
      notes="Groups /move-to-inbox."),

    n("/topics/bulk", ["PUT"], "bulk_topics", USER,
      [V("PUT", [rf("topic_ids", "body", "array", required=False, flow=True, description="Topics to operate on."),
                 rf("operation", "body", "object", required=True, flow=True, description="dismiss/change_category/change_tags/close/...")],
         reason="Applies a bulk operation to many topics.", src=f"{T}:1145", ex={"operation": {"type": "dismiss"}})],
      "Bulk topic operations.", f"{T}:1145", params=[], notes="Bulk mutation; per-topic Guardian still applies."),

    n("/topics/reset-new", ["PUT"], "reset_new", USER,
      [V("PUT", reason="Dismisses new/unread tracking.", src=f"{T}:1239")], "Self dismiss-new.", f"{T}:1239",
      params=[], notes="Groups pm-reset-new."),
]
