# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Reviewables."""
from common import key as K
from l2lib import qa

R = "app/controllers/reviewables_controller.rb"
qa("disc_reviewables_index", "List moderation queue", "Read", "reviewables_index", "Staff", K("/review"), ["GET"],
   "ReviewableList", vis_reason="Staff queue.", src=f"{R}:13", description="Lists the moderation queue.",
   notes="Discloses flagged/hidden content to staff.")
qa("disc_read_reviewable", "Read reviewable", "Read", "show_reviewable", "Staff", K("/review/{reviewable_id}"), ["GET"],
   "Reviewable", vis_reason="Staff.", src=f"{R}:173", description="Reads a reviewable.")
qa("disc_update_reviewable", "Edit reviewable", "Update", "update_reviewable", "Staff", K("/review/{reviewable_id}"), ["PUT"],
   "Reviewable", vis_reason="Staff.", src=f"{R}:227", description="Edits the reviewable's target content.")
qa("disc_delete_reviewable", "Delete reviewable", "Delete", "destroy_reviewable", "Staff", K("/review/{reviewable_id}"), ["DELETE"],
   "Reviewable", vis_reason="Staff.", src=f"{R}:192", description="Deletes a reviewable.")
qa("disc_perform_reviewable", "Perform moderation action", "Update", "perform_reviewable", "Staff",
   K("/review/{reviewable_id}/perform/{action_id}"), ["PUT"], "Reviewable", vis_reason="Staff moderation action.",
   src=f"{R}:266", description="Performs a moderation action (approve/reject/delete/suspend).",
   notes="HIGH-IMPACT moderation authority (can delete/suspend users).")
qa("disc_scrub_reviewable", "Scrub reviewable", "Update", "scrub_reviewable", "Staff",
   K("/review/{reviewable_id}/scrub"), ["PUT"], "Reviewable", vis_reason="Staff scrub.", src=f"{R}:207",
   description="Scrubs sensitive content.")
qa("disc_reviewable_note", "Add reviewable note", "Create", "create_reviewable_note", "Staff",
   K("/review/{reviewable_id}/notes"), ["POST"], "ReviewableNote", vis_reason="Staff.",
   src="app/controllers/reviewable_notes_controller.rb:1", description="Adds a moderator note.")
qa("disc_dsa_classify", "Record DSA classification", "Update", "dsa_classify", "Staff",
   K("/review/{reviewable_id}/dsa-classification"), ["PUT"], "DsaStatement", vis_reason="Staff.",
   src="app/controllers/dsa_statements_controller.rb:1", description="Records a DSA statement of reasons.")
qa("disc_read_reviewable_settings", "Read queue settings", "Read", "reviewable_settings", "Staff",
   K("/review/settings"), ["GET"], "ReviewableSettings", vis_reason="Staff.", src=f"{R}:310",
   description="Reads moderation-queue settings.")
qa("disc_update_reviewable_settings", "Update queue settings", "Update", "update_reviewable_settings", "Staff",
   K("/review/settings"), ["PUT"], "ReviewableSettings", vis_reason="Staff.", src=f"{R}:310",
   description="Updates moderation-queue settings.")
qa("disc_reviewable_count", "Reviewable count", "Read", "reviewable_count", "Staff", K("/review/count"), ["GET"],
   "ReviewableCount", vis_reason="Staff.", src=f"{R}:120", description="Pending-review count.")
qa("disc_claim_reviewable_topic", "Claim topic reviewables", "Create", "claim_reviewable_topic", "Staff",
   K("/reviewable_claimed_topics"), ["POST"], "ReviewableClaim", vis_reason="Staff.",
   src="app/controllers/reviewable_claimed_topics_controller.rb:1", description="Claims a topic's reviewables.")
qa("disc_release_reviewable_topic", "Release claimed topic", "Delete", "release_reviewable_topic", "Staff",
   K("/reviewable_claimed_topics"), ["DELETE"], "ReviewableClaim", vis_reason="Staff.",
   src="app/controllers/reviewable_claimed_topics_controller.rb:1", description="Releases a claimed topic.")
