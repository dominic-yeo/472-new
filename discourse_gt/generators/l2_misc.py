# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Misc public surfaces."""
from common import key as K
from l2lib import qa

qa("disc_search", "Search content", "Read", "search", "Anonymous", K("/search"), ["GET"], "SearchResults",
   vis_reason="Public search (visibility-gated).", src="app/controllers/search_controller.rb:1",
   description="Full-text search across visible content.", notes="Honors per-user visibility.")
qa("disc_directory_items", "List user directory", "Read", "directory_items", "Anonymous", K("/directory_items"), ["GET"],
   "DirectoryItemList", vis_reason="Public directory.", src="app/controllers/directory_items_controller.rb:1",
   description="Lists the user directory.")
qa("disc_about", "Read about page", "Read", "about", "Anonymous", K("/about"), ["GET"], "AboutInfo",
   vis_reason="Public.", src="app/controllers/about_controller.rb:1", description="Site about + staff listing.")
qa("disc_site", "Read site bootstrap", "Read", "site", "Anonymous", K("/site"), ["GET"], "SiteConfig",
   vis_reason="Public bootstrap.", src="app/controllers/site_controller.rb:1",
   description="Site metadata for the SPA.", notes="Exposes client-visible settings.")
qa("disc_like_post", "Like/flag post", "Create", "create_post_action", "User", K("/post_actions"), ["POST"], "PostAction",
   vis_reason="Authenticated like/flag.", src="app/controllers/post_actions_controller.rb:1",
   description="Applies a post action (like or flag).", notes="Flags enqueue a reviewable; rate-limited.")
qa("disc_unlike_post", "Remove post action", "Delete", "destroy_post_action", "User", K("/post_actions"), ["DELETE"],
   "PostAction", vis_reason="Authenticated.", src="app/controllers/post_actions_controller.rb:1",
   description="Removes a post action (unlike).")
qa("disc_user_actions", "List user actions", "Read", "user_actions", "Anonymous", K("/user_actions"), ["GET"],
   "UserActionStream", vis_reason="Public (visibility-gated).", src="app/controllers/user_actions_controller.rb:1",
   description="Lists a user's activity stream.")
qa("disc_dsa_report", "Report illegal content", "Create", "dsa_report", "Anonymous", K("/dsa/report-illegal-content"),
   ["POST"], "DsaNotice", vis_reason="Public report intake.", src="app/controllers/dsa_notices_controller.rb:1",
   description="Submits a DSA illegal-content report.", notes="Email-verified; rate-limited.")
qa("disc_composer_mentions", "Resolve mentions", "Read", "composer_mentions", "User", K("/composer/mentions"), ["GET"],
   "MentionCandidates", vis_reason="Authenticated.", src="app/controllers/composer_controller.rb:1",
   description="Resolves @mention candidates.")
qa("disc_track_click", "Track outbound click", "Create", "track_click", "Anonymous", K("/clicks/track"), ["POST"],
   "LinkClick", vis_reason="Public click tracking.", src="app/controllers/clicks_controller.rb:1",
   description="Records an outbound click and redirects.", notes="Open-redirect-validated.")
