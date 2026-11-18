# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Posts. Importing registers actions."""
from common import key as K, reference, entity, f_know, f_state, f_exists, eff, subj
from l2lib import qa

A = subj()
P = "app/controllers/posts_controller.rb"
POST = entity("post", "Post", "target")

qa("disc_create_post", "Create post", "Create", "create_post", "User",
   K("/posts"), ["POST"], "Post", entity_id="post",
   vis_reason="Authenticated posting boundary.", src=f"{P}:168",
   description="Creates a post/reply or a new topic.",
   notes="PRIMARY untrusted content entry; raw markdown cooked to HTML (stored-XSS surface).")

qa("disc_read_post", "Read post", "Read", "read_post", "Anonymous",
   K("/posts/{id}"), ["GET"], "Post", vis_reason="Public read (visibility-gated).",
   src=f"{P}:297", description="Reads a post.")

qa("disc_edit_post", "Edit post", "Update", "update_post", "User",
   K("/posts/{id}"), ["PUT"], "Post", vis_reason="Author/staff edit.", src=f"{P}:198",
   description="Edits a post's body.", notes="Guardian#can_edit_post? (author window/wiki/staff).")

qa("disc_delete_post", "Delete post", "Delete", "destroy_post", "User",
   K("/posts/{id}"), ["DELETE"], "Post", vis_reason="Author/staff delete.", src=f"{P}:332",
   description="Soft-deletes a post.", notes="Recoverable.")

qa("disc_recover_post", "Recover post", "Update", "recover_post", "Staff",
   K("/posts/{id}/recover"), ["PUT"], "Post", vis_reason="Author/staff restore.", src=f"{P}:375",
   description="Restores a soft-deleted post.")

qa("disc_destroy_many_posts", "Bulk delete posts", "Delete", "destroy_many_posts", "Staff",
   K("/posts/destroy_many"), ["DELETE"], "Post", vis_reason="Staff bulk delete.", src=f"{P}:401",
   description="Bulk-deletes posts.")

qa("disc_merge_posts", "Merge posts", "Update", "merge_posts", "Staff",
   K("/posts/merge_posts"), ["PUT"], "Post", vis_reason="Staff merge.", src=f"{P}:424",
   description="Merges posts.")

qa("disc_toggle_wiki", "Toggle wiki", "Update", "toggle_wiki", "Staff",
   K("/posts/{id}/wiki"), ["PUT"], "Post", vis_reason="Staff/author wiki toggle.", src=f"{P}:728",
   description="Toggles wiki status.", notes="Widens edit surface to trusted users.")

qa("disc_set_post_type", "Set post type", "Update", "set_post_type", "Staff",
   K("/posts/{id}/post_type"), ["PUT"], "Post", vis_reason="Staff post-type change.", src=f"{P}:740",
   description="Changes post type.")

qa("disc_rebake_post", "Rebake post", "Update", "rebake_post", "Staff",
   K("/posts/{id}/rebake"), ["PUT"], "Post", vis_reason="Staff rebake.", src=f"{P}:766",
   description="Re-renders post HTML.")

qa("disc_lock_post", "Lock post", "Update", "lock_post", "Staff",
   K("/posts/{id}/locked"), ["PUT"], "Post", vis_reason="Staff lock.", src=f"{P}:677",
   description="Locks/unlocks a post.")

qa("disc_set_post_notice", "Set post notice", "Update", "set_post_notice", "Staff",
   K("/posts/{id}/notice"), ["PUT"], "Post", vis_reason="Staff notice.", src=f"{P}:684",
   description="Adds/removes a staff notice.")

qa("disc_post_replies", "List post replies", "Read", "post_replies", "Anonymous",
   K("/posts/{id}/replies"), ["GET"], "PostReplies", vis_reason="Public read.", src=f"{P}:436",
   description="Lists replies to a post.")

qa("disc_post_revision", "Read post revision", "Read", "post_revision", "Anonymous",
   K("/posts/{id}/revisions/{revision}"), ["GET"], "PostRevision", vis_reason="Revision read.", src=f"{P}:469",
   description="Reads a post revision.", notes="Groups revision view ops.")

qa("disc_hide_revision", "Hide revision", "Update", "hide_revision", "Staff",
   K("/posts/{id}/revisions/{revision}/hide"), ["PUT"], "PostRevision", vis_reason="Staff revision moderation.",
   src=f"{P}:499", description="Hides a revision.", notes="Groups show/unlist/relist revision ops.")

qa("disc_revert_revision", "Revert revision", "Update", "revert_revision", "Staff",
   K("/posts/{id}/revisions/{revision}/revert"), ["PUT"], "Post", vis_reason="Staff/author revert.",
   src=f"{P}:597", description="Reverts to a prior revision.")

qa("disc_perm_delete_revisions", "Permanently delete revisions", "Delete", "permanently_delete_revisions", "Staff",
   K("/posts/{id}/revisions/permanently_delete"), ["DELETE"], "PostRevision",
   vis_reason="Staff/admin hard delete.", src=f"{P}:526",
   description="Irreversibly deletes post revisions.", notes="Irreversible.")

qa("disc_destroy_post_bookmark", "Remove post bookmark", "Delete", "destroy_post_bookmark", "User",
   K("/posts/{id}/bookmark"), ["DELETE"], "Bookmark", vis_reason="Self bookmark removal.", src=f"{P}:713",
   description="Removes the caller's bookmark on a post.")
