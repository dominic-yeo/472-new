# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Invites."""
from common import key as K, reference, entity, f_exists, f_state, f_auth, eff, subj
from l2lib import qa

A = subj()
I = "app/controllers/invites_controller.rb"
NEW = entity("new_user", "User", "target")

qa("disc_create_invite", "Create invite", "Create", "create_invite", "User", K("/invites"), ["POST"], "Invite",
   vis_reason="Authenticated invite management.", src=f"{I}:142", description="Creates an email/link invite.",
   notes="group_ids auto-grants groups on redemption; link invites reusable.")
qa("disc_delete_invite", "Delete invite", "Delete", "destroy_invite", "User", K("/invites"), ["DELETE"], "Invite",
   vis_reason="Authenticated.", src=f"{I}:370", description="Deletes an invite.")
qa("disc_show_invite", "Show invite", "Read", "show_invite", "Anonymous", K("/invites/{id}"), ["GET"], "Invite",
   vis_reason="Public invite landing.", src=f"{I}:610", description="Shows an invite for redemption.")
qa("disc_accept_invite", "Redeem invite", "Create", "accept_invite", "Anonymous", K("/invites/show/{id}"), ["PUT"],
   "User", entity_id="new_user",
   extra_req=[{"type": "knowledge", "fact": {"predicate": "Know", "arguments": [A, reference("InviteToken", NEW)]},
               "reason": "The invite token authorizes account creation."}],
   gen=[eff(f_exists(NEW), "action_semantics", "Redeeming the invite provisions/activates the account."),
        eff(f_state(NEW, "groups", "granted"), "state_transition", "Invite group grants are applied."),
        eff(f_auth(A, "Session"), "auth_transition", "The new account is signed in.")],
   vis_reason="Public invite redemption boundary.", src=f"{I}:383",
   description="Redeems an invite to create/activate an account.", notes="Applies invite group grants.")
qa("disc_invite_sso", "Redeem invite via SSO", "Create", "invite_sso", "Anonymous", K("/invites/{id}/sso"), ["POST"],
   "User", entity_id="new_user", vis_reason="Public SSO invite redemption.", src=f"{I}:59",
   description="Redeems an invite via DiscourseConnect.")
qa("disc_create_multiple_invites", "Bulk create invites", "Create", "create_multiple_invites", "Staff",
   K("/invites/create-multiple"), ["POST"], "Invite", vis_reason="Staff bulk invite.", src=f"{I}:73",
   description="Bulk-creates invites.")
qa("disc_invite_upload_csv", "Invite from CSV", "Create", "invite_upload_csv", "Staff", K("/invites/upload_csv"), ["POST"],
   "Invite", vis_reason="Staff CSV invite.", src=f"{I}:536", description="Bulk-invites from a CSV.", notes="File ingestion.")
qa("disc_resend_invite", "Resend invite", "Update", "resend_invite", "User", K("/invites/reinvite"), ["POST"], "Invite",
   vis_reason="Resend.", src=f"{I}:496", description="Resends an invite email.", notes="Groups reinvite-all/destroy-expired.")
qa("disc_retrieve_invite", "Retrieve invite", "Read", "retrieve_invite", "User", K("/invites/retrieve"), ["GET"], "Invite",
   vis_reason="Self lookup.", src=f"{I}:220", description="Retrieves an existing invite.")
