# -*- coding: utf-8 -*-
"""Discourse L2 -- module: Users + Account. Importing registers actions (l2lib).

Uses the compact qa() helper; security-relevant effects (privilege grant, session
revocation, credential reset) are passed explicitly.
"""
from common import key as K, reference, entity, f_know, f_state, f_exists, f_auth, f_can, req, eff, subj
from l2lib import qa, bind

A = subj()
U = "app/controllers/users_controller.rb"
UE = "app/controllers/users_email_controller.rb"


def _know(resource, ent):
    return eff(f_know(A, reference(resource, ent)), "io_reference", f"Response discloses {resource}.")


USER = entity("self", "User", "target")

# ---- registration + availability ------------------------------------------
qa("disc_register", "Register account", "Create", "register_account", "Anonymous",
   K("/u"), ["POST"], "User", entity_id="new_user",
   vis_reason="Public registration boundary.", reach_conds=["allow_new_registrations"],
   src=f"{U}:737", description="An anonymous visitor self-registers an account.",
   notes="Honeypot + approval/activation gated; name/user_fields stored-reflected.")

qa("disc_check_username", "Check username availability", "Read", "check_username", "Anonymous",
   K("/u/check_username"), ["GET"], "UsernameAvailability", vis_reason="Public signup helper.",
   src=f"{U}:634", description="Tests whether a username is free.", notes="Username enumeration surface.")

qa("disc_check_email", "Check email availability", "Read", "check_email", "Anonymous",
   K("/u/check_email"), ["GET"], "EmailAvailability", vis_reason="Public signup helper.",
   src=f"{U}:697", description="Tests whether an email is free.", notes="Email enumeration surface; rate-limited.")

qa("disc_search_users", "Search users", "Read", "search_users", "Anonymous",
   K("/u/search/users"), ["GET"], "UserDirectory", vis_reason="Public typeahead directory.",
   src=f"{U}:1342", description="Typeahead search over users.", notes="Directory enumeration surface.")

# ---- profile / preference reads -------------------------------------------
qa("disc_show_user", "View user profile", "Read", "show_user", "Anonymous",
   K("/u/{username}.json"), ["GET"], "UserProfile", vis_reason="Public profile (visibility-gated).",
   src=f"{U}:134", description="Reads a user's public profile.", notes="Groups the users#show view aliases.")

qa("disc_user_summary", "View user summary", "Read", "user_summary", "Anonymous",
   K("/u/{username}/summary"), ["GET"], "UserSummary", vis_reason="Public summary (visibility-gated).",
   src=f"{U}:526", description="Reads a user's activity summary.")

qa("disc_read_prefs", "Read account preferences", "Read", "read_preferences", "User",
   K("/u/{username}/preferences"), ["GET"], "UserPreferences",
   vis_reason="Self (or staff) preference view.", src=f"{U}:507",
   description="Reads a user's editable preferences.", notes="Self-or-staff guarded; groups /preferences/* views.")

qa("disc_check_emails", "Reveal account emails", "Read", "check_emails", "User",
   K("/u/{username}/emails"), ["GET"], "UserEmail",
   vis_reason="Self-or-staff email disclosure.", src=f"{U}:319",
   description="Reveals a user's email addresses.", notes="Sensitive PII; staff can view other users' emails.")

# ---- profile mutations -----------------------------------------------------
qa("disc_update_user", "Update profile", "Update", "update_user", "User",
   K("/u/{username}"), ["PUT"], "User", entity_id="self",
   vis_reason="Self (or staff) profile edit.", src=f"{U}:219",
   description="Updates a user's profile + preferences.", notes="bio/website/user_fields stored-reflected.")

qa("disc_change_username", "Change username", "Update", "change_username", "User",
   K("/u/{username}/preferences/username"), ["PUT"], "Username",
   vis_reason="Self (or staff) username change.", src=f"{U}:288",
   description="Renames the account.", notes="Impacts @mentions and references.")

qa("disc_set_primary_email", "Set primary email", "Update", "set_primary_email", "User",
   K("/u/{username}/preferences/primary-email"), ["PUT"], "UserEmail",
   gen=[eff(f_state(USER, "primary_email", "changed"), "state_transition", "Identity/recovery email changed.")],
   vis_reason="Self (or staff) primary-email change.", src=f"{U}:372",
   description="Promotes a secondary email to primary.", notes="Account-takeover-relevant (recovery email).")

qa("disc_add_email", "Add secondary email", "Create", "add_email", "User",
   K("/u/{username}/preferences/email"), ["POST"], "UserEmail", entity_id="secondary_email",
   vis_reason="Self (or staff) email add.", src=f"{UE}:1",
   description="Adds a secondary email (confirmation sent).")

qa("disc_change_email", "Change email", "Update", "change_email", "User",
   K("/u/{username}/preferences/email"), ["PUT"], "UserEmail",
   vis_reason="Self (or staff) email change.", src=f"{UE}:1",
   description="Changes the account email (confirmation flow).")

qa("disc_remove_email", "Remove secondary email", "Delete", "remove_email", "User",
   K("/u/{username}/preferences/email"), ["DELETE"], "UserEmail", entity_id="secondary_email",
   vis_reason="Self (or staff) email removal.", src=f"{U}:406",
   description="Removes a secondary email.")

qa("disc_set_badge_title", "Set badge title", "Update", "set_badge_title", "User",
   K("/u/{username}/preferences/badge_title"), ["PUT"], "ProfileTitle",
   vis_reason="Self badge-title set.", src=f"{U}:459", description="Sets the profile title from an owned badge.")

qa("disc_pick_avatar", "Pick avatar", "Update", "pick_avatar", "User",
   K("/u/{username}/preferences/avatar/pick"), ["PUT"], "Avatar",
   vis_reason="Self avatar set.", src=f"{U}:1430", description="Sets the avatar to an uploaded image.")

qa("disc_select_avatar", "Select avatar by URL", "Update", "select_avatar", "User",
   K("/u/{username}/preferences/avatar/select"), ["PUT"], "Avatar",
   vis_reason="Self avatar select.", src=f"{U}:1465",
   description="Selects an avatar by source URL.", notes="URL-sourced (server fetch -> SSRF-relevant).")

qa("disc_destroy_user_image", "Clear profile image", "Delete", "destroy_user_image", "User",
   K("/u/{username}/preferences/user_image"), ["DELETE"], "ProfileImage",
   vis_reason="Self image removal.", src=f"{U}:1496", description="Clears a profile/card background image.")

qa("disc_revoke_oauth", "Unlink OAuth account", "Delete", "revoke_associated_account", "User",
   K("/u/{username}/preferences/revoke-account"), ["POST"], "OAuthLink",
   vis_reason="Self OAuth-link removal.", src=f"{U}:1915",
   description="Unlinks an associated external/OAuth account.")

qa("disc_revoke_token", "Revoke session token(s)", "Delete", "revoke_auth_token", "User",
   K("/u/{username}/preferences/revoke-auth-token"), ["POST"], "SessionToken",
   kill=[eff(f_auth(A, "Session"), "auth_transition", "One or all device session tokens are revoked.")],
   vis_reason="Self session revocation.", src=f"{U}:1948",
   description="Revokes one or all active session tokens.", notes="Logs out other devices.")

qa("disc_user_notif_level", "Set user notification level", "Update", "set_user_notification_level", "User",
   K("/u/{username}/notification_level"), ["PUT"], "UserNotificationRelation",
   vis_reason="Caller sets a relation to another user.", src=f"{U}:1521",
   description="Sets ignore/mute/watch relation to another user.", notes="Ignoring staff is restricted.")

# ---- two-factor + passkeys -------------------------------------------------
qa("disc_list_2fa", "List second factors", "Read", "list_second_factors", "User",
   K("/u/second_factors"), ["POST"], "SecondFactorInventory",
   vis_reason="Self 2FA inventory (confirmed session).", src=f"{U}:1673",
   description="Lists configured second factors.", notes="Requires a confirmed session.")

qa("disc_update_2fa", "Edit second factor", "Update", "update_second_factor", "User",
   K("/u/second_factor"), ["PUT"], "SecondFactor",
   vis_reason="Self 2FA edit.", src=f"{U}:1872", description="Edits/renames a second factor.")

qa("disc_create_totp", "Create TOTP secret", "Create", "create_second_factor_totp", "User",
   K("/u/create_second_factor_totp"), ["POST"], "TotpSecret",
   vis_reason="Self 2FA enrollment.", src=f"{U}:1706",
   description="Generates a pending TOTP secret.", notes="Activated by enable_second_factor_totp.")

qa("disc_enable_totp", "Enable TOTP", "Update", "enable_second_factor_totp", "User",
   K("/u/enable_second_factor_totp"), ["POST"], "SecondFactor", entity_id="totp",
   vis_reason="Self 2FA activation.", src=f"{U}:1830", description="Activates TOTP after verifying a code.")

qa("disc_disable_2fa", "Disable second factor", "Delete", "disable_second_factor", "User",
   K("/u/disable_second_factor"), ["PUT"], "SecondFactor",
   vis_reason="Self 2FA removal (confirmed session).", src=f"{U}:1858",
   description="Removes a second factor.", notes="Weakens account auth.")

qa("disc_create_seckey", "Stage security-key challenge", "Read", "create_security_key", "User",
   K("/u/create_second_factor_security_key"), ["POST"], "SecurityKeyChallenge",
   vis_reason="Self security-key enrollment.", src=f"{U}:1721",
   description="Stages a WebAuthn security-key challenge.")

qa("disc_register_seckey", "Register security key", "Create", "register_security_key", "User",
   K("/u/register_second_factor_security_key"), ["POST"], "SecurityKey",
   vis_reason="Self security-key enrollment.", src=f"{U}:1740", description="Completes security-key registration.")

qa("disc_update_seckey", "Edit security key", "Update", "update_security_key", "User",
   K("/u/security_key"), ["PUT"], "SecurityKey",
   vis_reason="Self security-key management.", src=f"{U}:1820", description="Edits/toggles/removes a security key.")

qa("disc_backup_codes", "Generate 2FA backup codes", "Create", "create_second_factor_backup", "User",
   K("/u/second_factors_backup"), ["PUT"], "BackupCodes",
   vis_reason="Self backup-code generation.", src=f"{U}:1700",
   description="Regenerates 2FA backup codes.", notes="Returns recovery credentials (shown once).")

qa("disc_create_passkey", "Stage passkey challenge", "Read", "create_passkey", "User",
   K("/u/create_passkey"), ["POST"], "PasskeyChallenge",
   vis_reason="Self passkey enrollment.", src=f"{U}:1756", description="Stages a passkey registration challenge.")

qa("disc_register_passkey", "Register passkey", "Create", "register_passkey", "User",
   K("/u/register_passkey"), ["POST"], "Passkey",
   vis_reason="Self passkey enrollment.", src=f"{U}:1771", description="Completes passkey registration.")

qa("disc_rename_passkey", "Rename passkey", "Update", "rename_passkey", "User",
   K("/u/rename_passkey/{id}"), ["PUT"], "Passkey",
   vis_reason="Self passkey rename.", src=f"{U}:1807", description="Renames a passkey.")

qa("disc_delete_passkey", "Delete passkey", "Delete", "delete_passkey", "User",
   K("/u/delete_passkey/{id}"), ["DELETE"], "Passkey",
   vis_reason="Self passkey removal.", src=f"{U}:1791", description="Deletes a passkey.")

qa("disc_trusted_session", "Check trusted session", "Read", "trusted_session", "User",
   K("/u/trusted-session"), ["GET"], "SessionTrust",
   vis_reason="Self confirmed-session check.", src=f"{U}:1669", description="Reports confirmed-session state.")

qa("disc_confirm_session", "Confirm session (step-up)", "Update", "confirm_session", "User",
   K("/u/confirm-session"), ["POST"], "SessionTrust",
   gen=[eff(f_state(entity("session", "Session", "target"), "trusted", "confirmed"), "state_transition",
            "Session is elevated to trusted for sensitive operations.")],
   vis_reason="Self session confirmation.", src=f"{U}:1655",
   description="Confirms the session (password/passkey) for sensitive ops.")

# ---- account lifecycle / token flows (anonymous) --------------------------
qa("disc_pwreset_show", "Check reset token", "Read", "password_reset_show", "Anonymous",
   K("/u/password-reset/{token}"), ["GET"], "PasswordResetInfo",
   extra_req=[req("knowledge", f_know(A, reference("AuthToken", USER)), "Caller presents the reset token.")],
   vis_reason="Token-gated reset check.", src=f"{U}:897", description="Validates a password-reset token.")

qa("disc_pwreset_update", "Redeem password reset", "Update", "password_reset_update", "Anonymous",
   K("/u/password-reset/{token}"), ["PUT"], "User", entity_id="self",
   extra_req=[req("knowledge", f_know(A, reference("AuthToken", USER)), "The reset token is the credential.")],
   gen=[eff(f_state(USER, "password", "reset"), "state_transition", "Password is replaced via the token."),
        eff(f_auth(A, "Session"), "auth_transition", "A session may be opened on success.")],
   vis_reason="Token-gated credential reset.", src=f"{U}:955",
   description="Sets a new password via the reset token.", notes="2FA enforced; rate-limited.")

qa("disc_activate_show", "Show activation", "Read", "activate_account_show", "Anonymous",
   K("/u/activate-account/{token}"), ["GET"], "ActivationInfo",
   vis_reason="Token-gated activation.", src=f"{U}:1197", description="Shows account activation for a token.")

qa("disc_activate_perform", "Activate account", "Update", "activate_account", "Anonymous",
   K("/u/activate-account/{token}"), ["PUT"], "User", entity_id="self",
   extra_req=[req("knowledge", f_know(A, reference("AuthToken", USER)), "Activation token proves email ownership.")],
   gen=[eff(f_state(USER, "active", "true"), "state_transition", "The account is activated (email confirmed).")],
   vis_reason="Token-gated activation.", src=f"{U}:1208", description="Activates the account via the token.")

qa("disc_update_activation_email", "Change pre-activation email", "Update", "update_activation_email", "Anonymous",
   K("/u/update-activation-email"), ["PUT"], "UserEmail",
   vis_reason="Pre-activation email correction.", src=f"{U}:1256",
   description="Changes the email on an unactivated account.", notes="Password-gated when a password exists; rate-limited.")

qa("disc_send_activation", "Resend activation email", "Create", "send_activation_email", "Anonymous",
   K("/u/action/send_activation_email"), ["POST"], "ActivationEmail",
   vis_reason="Public activation-resend.", src=f"{U}:1312",
   description="Resends the activation email.", notes="Rate-limited; enumeration-resistant.")

qa("disc_confirm_email_token", "Confirm email token", "Update", "confirm_email_token", "Anonymous",
   K("/u/confirm-email-token/{token}"), ["GET"], "UserEmail",
   extra_req=[req("knowledge", f_know(A, reference("AuthToken", USER)), "Email-confirmation token.")],
   vis_reason="Token-gated email confirmation.", src=f"{U}:1066", description="Confirms an email-change token.")

qa("disc_admin_login_show", "Show admin recovery login", "Read", "admin_login_show", "Anonymous",
   K("/u/admin-login"), ["GET"], "AdminLoginForm",
   vis_reason="Emergency admin-recovery login.", src=f"{U}:1086", description="Shows the admin email-login form.")

qa("disc_admin_login_request", "Request admin login link", "Create", "admin_login_request", "Anonymous",
   K("/u/admin-login"), ["PUT"], "AdminLoginLink",
   vis_reason="Emergency admin-recovery login.", src=f"{U}:1086",
   description="Emails an admin a one-time login link.", notes="Admin account-recovery path; rate-limited.")

qa("disc_confirm_admin_show", "Show confirm-admin", "Read", "confirm_admin_show", "Anonymous",
   K("/u/confirm-admin/{token}"), ["GET"], "ConfirmAdminInfo",
   vis_reason="Token-gated admin grant.", src=f"{U}:1636", description="Shows the grant-admin confirmation.")

qa("disc_confirm_admin_grant", "Grant admin via token", "Update", "confirm_admin", "Anonymous",
   K("/u/confirm-admin/{token}"), ["POST"], "User", entity_id="self",
   extra_req=[req("knowledge", f_know(A, reference("AuthToken", USER)), "Grant-admin token from the bootstrap email.")],
   gen=[eff(f_state(USER, "role", "admin"), "state_transition", "The account is elevated to admin."),
        eff(f_can(A, "Administer", entity("instance", "Instance", "authority")), "auth_transition",
            "Admin authority is granted.")],
   vis_reason="Token-gated admin grant (bootstrap).", src=f"{U}:1636",
   description="Redeems a grant-admin token to make the account an admin.",
   notes="PRIVILEGE ESCALATION path -- guarded by the emailed one-time token.")

qa("disc_request_email_login", "Request email login link", "Create", "request_email_login", "Anonymous",
   K("/u/email-login"), ["POST"], "EmailLoginLink",
   vis_reason="Public email-login request.", src=f"{U}:1112",
   description="Requests a passwordless email-login link.", notes="Enumeration-resistant.")

# ---- minor self endpoints --------------------------------------------------
qa("disc_toggle_anon", "Toggle anonymous mode", "Update", "toggle_anon", "User",
   K("/u/toggle-anon"), ["POST"], "AnonMode",
   vis_reason="Self anon-mode toggle.", reach_conds=["allow_anonymous_mode"], src=f"{U}:1153",
   description="Switches to/from the shadow anonymous account.")

qa("disc_read_recent_searches", "Read recent searches", "Read", "recent_searches", "User",
   K("/u/recent-searches"), ["GET"], "SearchHistory",
   vis_reason="Self search-history read.", src=f"{U}:1581", description="Reads the caller's recent searches.")

qa("disc_clear_recent_searches", "Clear recent searches", "Delete", "reset_recent_searches", "User",
   K("/u/recent-searches"), ["DELETE"], "SearchHistory",
   vis_reason="Self search-history clear.", src=f"{U}:1611", description="Clears recent search history.")
