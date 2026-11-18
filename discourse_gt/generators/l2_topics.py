# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Topics. Importing registers actions."""
from common import key as K
from l2lib import qa

T = "app/controllers/topics_controller.rb"

qa("disc_read_topic", "Read topic", "Read", "show_topic", "Anonymous",
   K("/t/{id}"), ["GET"], "Topic", vis_reason="Public read (visibility-gated).", src=f"{T}:77",
   description="Reads a topic's post stream.", notes="Groups print/summary/feed/external-id views.")
qa("disc_update_topic", "Edit topic", "Update", "update_topic", "User",
   K("/t/{id}"), ["PUT"], "Topic", vis_reason="Author/staff edit.", src=f"{T}:433",
   description="Edits topic title/category/tags.")
qa("disc_delete_topic", "Delete topic", "Delete", "destroy_topic", "User",
   K("/t/{id}"), ["DELETE"], "Topic", vis_reason="Author/staff delete.", src=f"{T}:786",
   description="Soft-deletes a topic.")
qa("disc_topic_posts", "Load topic posts", "Read", "topic_posts", "Anonymous",
   K("/t/{topic_id}/posts"), ["GET"], "PostStream", vis_reason="Public read.", src=f"{T}:309",
   description="Loads a slice of a topic's posts.", notes="Groups post_ids/excerpts.")
qa("disc_recover_topic", "Recover topic", "Update", "recover_topic", "Staff",
   K("/t/{topic_id}/recover"), ["PUT"], "Topic", vis_reason="Author/staff restore.", src=f"{T}:812",
   description="Restores a soft-deleted topic.")
qa("disc_topic_status", "Set topic status", "Update", "set_topic_status", "Staff",
   K("/t/{topic_id}/status"), ["PUT"], "Topic", vis_reason="Staff/author status change.", src=f"{T}:587",
   description="Opens/closes/archives/pins/unlists a topic.")
qa("disc_mute_topic", "Mute topic", "Update", "mute_topic", "User",
   K("/t/{topic_id}/mute"), ["PUT"], "TopicNotification", vis_reason="Self mute.", src=f"{T}:638",
   description="Mutes/unmutes a topic.")
qa("disc_topic_timer", "Set topic timer", "Update", "set_topic_timer", "Staff",
   K("/t/{topic_id}/timer"), ["POST"], "TopicTimer", vis_reason="Staff topic timer.", src=f"{T}:646",
   description="Schedules an automated topic action.", notes="Future auto close/delete/publish.")
qa("disc_make_banner", "Make topic banner", "Update", "make_banner", "Admin",
   K("/t/{topic_id}/make-banner"), ["PUT"], "Topic", vis_reason="Admin banner.", src=f"{T}:704",
   description="Promotes a topic to the global banner.", notes="Shown to all users.")
qa("disc_publish_topic", "Publish shared draft", "Update", "publish_topic", "Staff",
   K("/t/{id}/publish"), ["PUT"], "Topic", vis_reason="Staff publish.", src=f"{T}:244",
   description="Publishes a shared draft to a category.")
qa("disc_shared_draft", "Update shared draft", "Update", "update_shared_draft", "Staff",
   K("/t/{id}/shared-draft"), ["PUT"], "Topic", vis_reason="Staff shared draft.", src=f"{T}:414",
   description="Updates a shared draft's category.")
qa("disc_convert_topic", "Convert topic type", "Update", "convert_topic", "Staff",
   K("/t/{id}/convert-topic/{type}"), ["PUT"], "Topic", vis_reason="Staff convert.", src=f"{T}:1323",
   description="Converts between public topic and PM.", notes="Changes visibility audience.")
qa("disc_update_topic_tags", "Update topic tags", "Update", "update_topic_tags", "User",
   K("/t/{topic_id}/tags"), ["PUT"], "Topic", vis_reason="Author/staff tagging.", src=f"{T}:529",
   description="Replaces a topic's tags.")
qa("disc_invite_to_topic", "Invite to topic", "Create", "invite_to_topic", "User",
   K("/t/{topic_id}/invite"), ["POST"], "TopicInvite", vis_reason="Participant invite.", src=f"{T}:887",
   description="Invites a user/email to a topic/PM.", notes="On PMs grants another user read access.")
qa("disc_invite_group_to_topic", "Invite group to topic", "Create", "invite_group_to_topic", "User",
   K("/t/{topic_id}/invite-group"), ["POST"], "TopicInvite", vis_reason="Group invite.", src=f"{T}:854",
   description="Invites a group to a topic/PM.")
qa("disc_remove_allowed_user", "Remove PM participant", "Delete", "remove_allowed_user", "User",
   K("/t/{topic_id}/remove-allowed-user"), ["PUT"], "TopicParticipant", vis_reason="PM participant removal.",
   src=f"{T}:826", description="Removes an allowed user/group from a PM.")
qa("disc_move_posts", "Move/split posts", "Update", "move_posts", "Staff",
   K("/t/{topic_id}/move-posts"), ["POST"], "Topic", vis_reason="Staff move/split.", src=f"{T}:999",
   description="Moves/splits posts into another or new topic.")
qa("disc_merge_topic", "Merge topic", "Update", "merge_topic", "Staff",
   K("/t/{topic_id}/merge-topic"), ["POST"], "Topic", vis_reason="Staff merge.", src=f"{T}:964",
   description="Merges this topic into another.")
qa("disc_change_owner", "Change post owner", "Update", "change_post_owners", "Staff",
   K("/t/{topic_id}/change-owner"), ["POST"], "Post", vis_reason="Staff/admin owner change.", src=f"{T}:1040",
   description="Reassigns authorship of posts.", notes="Attribution integrity.")
qa("disc_change_timestamps", "Change topic timestamps", "Update", "change_timestamps", "Staff",
   K("/t/{topic_id}/change-timestamp"), ["PUT"], "Topic", vis_reason="Staff timestamp edit.", src=f"{T}:1060",
   description="Rewrites a topic's timestamps.")
qa("disc_topic_timings", "Record read timings", "Update", "topic_timings", "User",
   K("/t/{topic_id}/timings"), ["POST"], "ReadState", vis_reason="Self read-tracking.", src=f"{T}:1098",
   description="Records read state / time spent.")
qa("disc_bookmark_topic", "Bookmark topic", "Update", "bookmark_topic", "User",
   K("/t/{topic_id}/bookmark"), ["PUT"], "Bookmark", vis_reason="Self bookmark.", src=f"{T}:775",
   description="Bookmarks the topic.")
qa("disc_topic_notifications", "Set topic notification level", "Update", "set_topic_notifications", "User",
   K("/t/{topic_id}/notifications"), ["POST"], "TopicNotification", vis_reason="Self notification level.",
   src=f"{T}:955", description="Sets the caller's topic notification level.")
qa("disc_archive_pm", "Archive PM", "Update", "archive_message", "User",
   K("/t/{id}/archive-message"), ["PUT"], "PrivateMessage", vis_reason="Self PM archive.", src=f"{T}:729",
   description="Archives/moves a PM.")
qa("disc_bulk_topics", "Bulk topic operation", "Update", "bulk_topics", "User",
   K("/topics/bulk"), ["PUT"], "Topic", vis_reason="Bulk topic operations.", src=f"{T}:1145",
   description="Applies a bulk operation to many topics.")
qa("disc_reset_new", "Dismiss new/unread", "Update", "reset_new", "User",
   K("/topics/reset-new"), ["PUT"], "ReadState", vis_reason="Self dismiss-new.", src=f"{T}:1239",
   description="Dismisses new/unread tracking.")
