# -*- coding: utf-8 -*-
"""Discourse L1 -- module: Posts (PostsController). Routes: resources :posts +
members, config/routes.rb ~1355. Source app/controllers/posts_controller.rb.
Revision view ops (show/unlist/relist) grouped; security-relevant ops modeled.
"""
from common import key as K, node, variant, rf, of, resp_json, resp_empty, resp_scalar, resp_raw, dec, dec_for, ev

P = "app/controllers/posts_controller.rb"
ST_PUB = {"anonymous": [200, 403, 404], "user": [200]}
ST_USER = {"anonymous": [403], "user": [200]}
ST_STAFF = {"anonymous": [403], "user": [403], "staff": [200]}


def n(path, methods, sem, statuses, idst, variants, vis_reason, src, notes=None,
      params=None, sin=None, sout=None, reach=None):
    return node(K(path), "api", methods, variants=variants, operation_semantic=sem,
                statuses=statuses, identity_statuses=idst, params=params or [],
                sem_in_decisions=sin or [], sem_out_decisions=sout or [],
                route_confirmed=True, vis_reason=vis_reason, reach_conds=reach or [],
                evidence=[ev("source", src, sem)], notes=notes)


NODES = [
    n("/posts", ["POST"], "create_post", [200, 403, 422, 429], ST_USER,
      [variant("POST", body_format="json",
               body_example={"raw": "hello", "topic_id": 5, "category": 2},
               request_fields=[rf("raw", "body", "string", required=True, flow=True, description="Post markdown body."),
                               rf("topic_id", "body", "integer", required=False, flow=True, description="Target topic (reply)."),
                               rf("title", "body", "string", required=False, flow=True, description="Title when creating a new topic."),
                               rf("category", "body", "integer", required=False, flow=True, description="Category for a new topic."),
                               rf("target_recipients", "body", "string", required=False, flow=True, description="PM recipients."),
                               rf("archetype", "body", "string", required=False, flow=False, description="regular|private_message.")],
               response=resp_json([of("id", "integer", True, "New post id."), of("cooked", "string", True, "Rendered HTML.")]),
               reason="Creates a post/reply or a new topic/PM.", evidence=f"{P}:168")],
      "Authenticated posting boundary.", f"{P}:168",
      notes="PRIMARY untrusted content entry; raw markdown is cooked to HTML (stored-XSS surface). Rate-limited, spam/newuser gated.",
      sin=[dec("raw", "PostBody(content)", "content", reason="User markdown, rendered to HTML."),
           dec("title", "TopicTitle(content)", "content", reason="Topic title (rendered)."),
           dec("target_recipients", "PmRecipients(identity)", "collection", reason="PM target users/groups.")],
      sout=[dec("cooked", "CookedHtml(content)", "content", reason="Server-rendered post HTML.")]),

    n("/posts/{id}", ["GET", "PUT", "DELETE"], "post_crud", [200, 403, 404, 422], ST_PUB,
      [variant("GET", response=resp_json([of("post", "object", True, "Serialized post.")]),
               reason="Reads a post.", evidence=f"{P}:297"),
       variant("PUT", body_format="json", body_example={"post": {"raw": "edited"}, "edit_reason": "typo"},
               request_fields=[rf("raw", "body", "string", required=True, flow=True, description="New markdown body."),
                               rf("edit_reason", "body", "string", required=False, flow=True, description="Edit reason.")],
               response=resp_json([of("post", "object", True, "Updated post.")]),
               reason="Edits a post (author or staff; wiki posts editable by trust level).", evidence=f"{P}:198"),
       variant("DELETE", response=resp_empty(), reason="Soft-deletes a post.", evidence=f"{P}:332")],
      "Public read; author/staff edit+delete.", f"{P}:198",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}],
      notes="Edit permission via Guardian#can_edit_post? (author window, wiki, staff). Delete is soft (recoverable).",
      sin=[dec("raw", "PostBody(content)", "content", reason="Edited markdown.")],
      sout=[dec("post", "Post(content)", "content", reason="Serialized post incl. cooked HTML.")]),

    n("/posts/{id}/recover", ["PUT"], "recover_post", [200, 403], ST_STAFF,
      [variant("PUT", response=resp_empty(), reason="Restores a soft-deleted post.", evidence=f"{P}:375")],
      "Author/staff restore.", f"{P}:375", notes="Undo of soft delete.",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/destroy_many", ["DELETE"], "destroy_many_posts", [200, 403], ST_STAFF,
      [variant("DELETE", body_format="json", body_example={"post_ids": [1, 2, 3]},
               request_fields=[rf("post_ids", "body", "array", required=True, flow=True, description="Posts to delete.")],
               response=resp_empty(), reason="Bulk-deletes posts.", evidence=f"{P}:401")],
      "Staff bulk delete.", f"{P}:401", notes="Staff moderation; agree_with_flags option."),

    n("/posts/merge_posts", ["PUT"], "merge_posts", [200, 403], ST_STAFF,
      [variant("PUT", body_format="json", body_example={"post_ids": [1, 2]},
               request_fields=[rf("post_ids", "body", "array", required=True, flow=True, description="Posts to merge.")],
               response=resp_empty(), reason="Merges multiple posts into one.", evidence=f"{P}:424")],
      "Staff merge.", f"{P}:424"),

    n("/posts/{id}/wiki", ["PUT"], "toggle_wiki", [200, 403], ST_STAFF,
      [variant("PUT", body_format="json", body_example={"wiki": True},
               request_fields=[rf("wiki", "body", "boolean", required=True, flow=True, description="Wiki flag.")],
               response=resp_empty(), reason="Toggles wiki (community-editable) status.", evidence=f"{P}:728")],
      "Staff/author wiki toggle.", f"{P}:728",
      notes="Wiki posts become editable by any trusted user (widens edit surface).",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/post_type", ["PUT"], "set_post_type", [200, 403], ST_STAFF,
      [variant("PUT", body_format="json", body_example={"post_type": 4},
               request_fields=[rf("post_type", "body", "integer", required=True, flow=True, description="regular/moderator_action/...")],
               response=resp_empty(), reason="Changes the post type.", evidence=f"{P}:740")],
      "Staff post-type change.", f"{P}:740",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/rebake", ["PUT"], "rebake_post", [200, 403], ST_STAFF,
      [variant("PUT", response=resp_empty(), reason="Re-renders the post HTML from markdown.", evidence=f"{P}:766")],
      "Staff rebake.", f"{P}:766",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/locked", ["PUT"], "lock_post", [200, 403], ST_STAFF,
      [variant("PUT", body_format="json", body_example={"locked": True},
               request_fields=[rf("locked", "body", "boolean", required=True, flow=True, description="Lock flag.")],
               response=resp_empty(), reason="Locks/unlocks a post against edits.", evidence=f"{P}:677")],
      "Staff lock.", f"{P}:677",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/notice", ["PUT"], "set_post_notice", [200, 403], ST_STAFF,
      [variant("PUT", body_format="json", body_example={"notice": "staff note"},
               request_fields=[rf("notice", "body", "string", required=False, flow=True, description="Staff notice markdown.")],
               response=resp_empty(), reason="Adds/removes a staff notice on a post.", evidence=f"{P}:684")],
      "Staff notice.", f"{P}:684", notes="Staff-authored notice (rendered).",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}],
      sin=[dec("notice", "StaffNotice(content)", "content", reason="Staff notice (rendered).")]),

    n("/posts/{id}/replies", ["GET"], "post_replies", [200, 403, 404], ST_PUB,
      [variant("GET", response=resp_json([of("replies", "array", True, "Direct replies to the post.")]),
               reason="Lists replies to a post.", evidence=f"{P}:436")],
      "Public read (visibility-gated).", f"{P}:436",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/revisions/{revision}", ["GET"], "post_revision", [200, 403, 404], ST_PUB,
      [variant("GET", response=resp_json([of("revision", "object", True, "A specific post revision diff.")]),
               reason="Reads a post revision (edit history).", evidence=f"{P}:469")],
      "Revision read (visibility-gated).", f"{P}:469",
      notes="Groups revisions/latest + show/unlist/relist view ops.",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."},
              {"name": "revision", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Revision number."}]),

    n("/posts/{id}/revisions/{revision}/hide", ["PUT"], "hide_revision", [200, 403], ST_STAFF,
      [variant("PUT", response=resp_empty(), reason="Hides a post revision from non-staff.", evidence=f"{P}:499")],
      "Staff revision moderation.", f"{P}:499", notes="Also backs show/unlist/relist/revert revision ops (grouped).",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."},
              {"name": "revision", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Revision number."}]),

    n("/posts/{id}/revisions/{revision}/revert", ["PUT"], "revert_revision", [200, 403], ST_STAFF,
      [variant("PUT", response=resp_empty(), reason="Reverts a post to a prior revision.", evidence=f"{P}:597")],
      "Staff/author revert.", f"{P}:597",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."},
              {"name": "revision", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Revision number."}]),

    n("/posts/{id}/revisions/permanently_delete", ["DELETE"], "permanently_delete_revisions", [200, 403], ST_STAFF,
      [variant("DELETE", response=resp_empty(), reason="Irreversibly deletes post revisions.", evidence=f"{P}:526")],
      "Staff/admin hard delete.", f"{P}:526", notes="Irreversible; requires an earlier permanently_delete_check.",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),

    n("/posts/{id}/bookmark", ["DELETE"], "destroy_post_bookmark", [200, 403], ST_USER,
      [variant("DELETE", response=resp_empty(), reason="Removes the caller's bookmark on a post.", evidence=f"{P}:713")],
      "Self bookmark removal.", f"{P}:713",
      params=[{"name": "id", "in": "path", "type": "integer", "required": True, "flow": True, "description": "Post id."}]),
]
