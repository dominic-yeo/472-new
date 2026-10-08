"""L2 cores, part 4: the 0.5.36-binary-only operations (contracts from live /api/spec)."""
from l2lib import *
from l2_spec import A, OBJ, authed, U, API, BASE

B_ = SUBJ()  # bot acts as actor:User[SELF] (the bot's own uid)
def bot_authed():
    return req("authentication", FACT("Authenticated", B_, "APIToken"), "Valid bot API key required.")

# ---- bot command subsystem --------------------------------------------------
def O_command(role="target", source="request", field="command_id"):
    return OBJ("entity", "command", "BotCommand", "Bot slash-command", "BotCommand", role, source, field, "BotCommandID(bot_command)")

A(API + "/bot/command", "GET", akey="bot_list_commands", name="Bot lists its commands", business="bot_list_commands", crud="Read",
  subject="bot", obj=OBJ("entity", "command_list", "BotCommand", "Bot commands", "BotCommand", "target", "response", "command_id", "BotCommandID(bot_command)"),
  req_facts=[bot_authed()],
  gen=[eff(FACT("Know", B_, REF("BotCommandID", ENT("command", "BotCommand", "target"))), "io_reference", "Command ids returned.")],
  io_out={"command_id": "know", "command": "observed", "command_desc": "observed"}, conf=0.65)
A(API + "/bot/command", "POST", akey="bot_add_command", name="Bot adds a command", business="bot_add_command", crud="Create",
  subject="bot", obj=O_command("created", "response"),
  req_facts=[bot_authed()],
  gen=[eff(FACT("Exists", ENT("command", "BotCommand", "created")), "action_semantics", "A new bot slash-command is registered."),
       eff(FACT("Know", B_, REF("BotCommandID", ENT("command", "BotCommand", "created"))), "io_reference", "New command id returned.")],
  io_in={"command": "attr", "command_desc": "attr"}, io_out={"command_id": "know"}, conf=0.65)
A(API + "/bot/command/{id}", "PUT", akey="bot_update_command", name="Bot updates a command", business="bot_update_command", crud="Update",
  subject="bot", obj=OBJ("entity", "command", "BotCommand", "Bot slash-command", "BotCommand", "target", "request", "command_id", "BotCommandID(bot_command)", state_field="command"),
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("BotCommandID", ENT("command", "BotCommand", "target"))), "Bot names the command id.")],
  kill=[eff(FACT("State", ENT("command", "BotCommand", "target"), "command", "previous"), "state_transition", "Old command text/description replaced.")],
  gen=[eff(FACT("State", ENT("command", "BotCommand", "target"), "command", "updated"), "state_transition", "Command updated.")],
  io_in={"command_id": "req_know", "command": "attr_state", "command_desc": "attr_state"}, conf=0.6)
A(API + "/bot/command/{id}", "DELETE", akey="bot_delete_command", name="Bot deletes a command", business="bot_delete_command", crud="Delete",
  subject="bot", obj=O_command(),
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("BotCommandID", ENT("command", "BotCommand", "target"))), "Bot names the command id.")],
  kill=[eff(FACT("Exists", ENT("command", "BotCommand", "target")), "action_semantics", "Command row removed.")],
  io_in={"command_id": "req_know"}, conf=0.6)
A(API + "/bot/delete/{mid}", "DELETE", akey="bot_delete_message", name="Bot deletes a message", business="bot_delete_message", crud="Delete",
  subject="bot", obj=OBJ("entity", "message", "Message", "Chat message", "Message", "target", "request", "mid", "MessageID(message)"),
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("MessageID", ENT("message", "Message", "target"))), "Bot names the message id.")],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "visibility", "deleted"), "state_transition", "A delete overlay is appended, establishing the deleted state (append-only model).")],
  io_in={"mid": "req_know"}, io_out={"mid": "observed"}, conf=0.6)
A(API + "/bot/edit/{mid}", "PUT", akey="bot_edit_message", name="Bot edits a message", business="bot_edit_message", crud="Update",
  subject="bot", obj=OBJ("entity", "message", "Message", "Chat message", "Message", "target", "request", "mid", "MessageID(message)", state_field="content"),
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("MessageID", ENT("message", "Message", "target"))), "Bot names the message id.")],
  kill=[eff(FACT("State", ENT("message", "Message", "target"), "content", "previous"), "state_transition", "Prior content superseded in the merged view.")],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "content", "updated"), "state_transition", "New content applied via an appended edit reaction.")],
  io_in={"mid": "req_know", "content": "attr_state"}, io_out={"mid": "observed"}, conf=0.6)
A(API + "/bot/reply/{mid}", "POST", akey="bot_reply_message_message", name="Bot replies to a message", business="bot_reply_message", crud="Create",
  subject="bot", obj=OBJ("entity", "reply", "Message", "Reply message", "Message", "created", "response", "", "MessageID(message)"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("MessageID", ENT("message", "Message", "target"))), "Bot names the message replied to.")],
  gen=[eff(FACT("Exists", ENT("reply", "Message", "created")), "action_semantics", "A new reply message is stored."),
       eff(FACT("Know", B_, REF("MessageID", ENT("reply", "Message", "created"))), "io_reference", "New reply mid returned.")],
  io_in={"mid": "req_know_msg", "content": "attr"}, io_out={"mid": "know"}, conf=0.6)
A(API + "/bot/user/{uid}/messages", "GET", akey="bot_read_dm_history", name="Bot reads recent DM messages", business="bot_read_dm_history", crud="Read",
  subject="bot", obj=OBJ("entity", "message_list", "Message", "DM history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[PRIN("peer", "User", "peer", "PEER")],
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("UserID", PRIN("peer", "User", "peer", "PEER"))), "Bot names the peer uid.")],
  gen=[eff(FACT("Know", B_, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Message ids returned.")],
  io_in={"uid": "req_know_peer", "context": "attr_cursor"},
  io_out={"mid": "know", "from_uid": "observed", "target_uid": "observed", "target_gid": "observed", "content": "observed", "content_type": "observed"}, conf=0.6)
A(API + "/bot/group/{gid}/messages", "GET", akey="bot_read_group_history", name="Bot reads recent group messages", business="bot_read_group_history", crud="Read",
  subject="bot", obj=OBJ("entity", "message_list", "Message", "Group history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[bot_authed(), req("knowledge", FACT("Know", B_, REF("GroupID", ENT("group", "Group", "target"))), "Bot names the group id.")],
  gen=[eff(FACT("Know", B_, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Message ids returned.")],
  io_in={"gid": "req_know_group", "context": "attr_cursor", "user_id": "attr_ref_user"},
  io_out={"mid": "know", "from_uid": "observed", "target_uid": "observed", "target_gid": "observed", "content": "observed", "content_type": "observed"}, conf=0.6)
A(API + "/bot/secret", "GET", akey="bot_read_secret", name="Bot reads its webhook secret", business="bot_read_secret", crud="Read",
  subject="bot", obj=OBJ("entity", "bot", "Bot", "Bot account", "Bot", "target", "subject", "", "BotSecret(bot)", attribute="secret", state_field="secret"),
  req_facts=[bot_authed()],
  gen=[eff(FACT("Know", B_, REF("BotSecret", ENT("bot", "Bot", "target"))), "io_reference", "Secret returned.")],
  io_out={"bot_secret": "know"}, conf=0.6)
A(API + "/bot/secret", "PUT", akey="bot_set_secret", name="Bot sets its webhook secret", business="bot_set_secret", crud="Update",
  subject="bot", obj=OBJ("entity", "bot", "Bot", "Bot account", "Bot", "target", "subject", "", "BotSecret(bot)", attribute="secret", state_field="secret"),
  req_facts=[bot_authed()],
  kill=[eff(FACT("State", ENT("bot", "Bot", "target"), "secret", "previous"), "state_transition", "Old secret invalidated.")],
  gen=[eff(FACT("State", ENT("bot", "Bot", "target"), "secret", "updated"), "state_transition", "New webhook secret stored.")],
  io_in={"bot_secret": "attr_cred"}, conf=0.6)
A(API + "/bot/send_mail", "POST", akey="bot_send_mail", name="Bot sends an e-mail", business="bot_send_mail", crud="Create",
  subject="bot", obj=OBJ("entity", "mail", "Mail", "Outgoing e-mail", "Mail", "created", "request", "", "EmailRecipient(mail)"),
  req_facts=[bot_authed()],
  gen=[eff(FACT("Exists", ENT("mail", "Mail", "created")), "action_semantics", "An e-mail is dispatched via SMTP.")],
  io_in={"mail_to": "attr", "mail_subject": "attr", "mail_content": "attr"}, conf=0.6)

# ---- user (session) ---------------------------------------------------------
A(API + "/user/{uid}/command", "GET", akey="user_read_user_commands", name="Read a bot user's commands", business="read_user_commands", crud="Read",
  subject="user", obj=OBJ("entity", "command_list", "BotCommand", "Bot commands of a user", "BotCommand", "target", "response", "command_id", "BotCommandID(bot_command)"),
  participants=[ENT("bot", "User", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", ENT("bot", "User", "target"))), "Caller names the bot uid.")],
  gen=[eff(FACT("Know", U, REF("BotCommandID", ENT("command", "BotCommand", "target"))), "io_reference", "Command ids returned.")],
  io_in={"uid": "req_know"}, io_out={"command_id": "know", "command": "observed", "command_desc": "observed"}, conf=0.6)
A(API + "/user/avo", "GET", akey="user_read_own_avatar_params", name="Read own avatar (Avo) params", business="read_own_avatar_params", crud="Read",
  subject="user", obj=OBJ("state", "actor_user", "User", "Own avatar parameters", "User", "target", "subject", "", "UserID(user)", attribute="avo_params", state_field="avo_params"),
  req_facts=[authed()], io_out={"avo_params": "observed"}, conf=0.65)
A(API + "/user/avo", "PUT", akey="user_update_own_avatar_params", name="Update own avatar (Avo) params", business="update_own_avatar_params", crud="Update",
  subject="user", obj=OBJ("state", "actor_user", "User", "Own avatar parameters", "User", "target", "subject", "", "UserID(user)", attribute="avo_params", state_field="avo_params"),
  req_facts=[authed()],
  kill=[eff(FACT("State", ENT("actor_user", "User", "target"), "avo_params", "previous"), "state_transition", "Old avatar params replaced.")],
  gen=[eff(FACT("State", ENT("actor_user", "User", "target"), "avo_params", "updated"), "state_transition", "Generative avatar parameters updated.")],
  io_in={"avo_name": "attr_state", "avo_variant": "attr_state", "avo_hue": "attr_state", "avo_style": "attr_state", "avo_energy": "attr_state"},
  io_out={"avo_params": "observed"}, conf=0.65)
A(API + "/user/contacts/search", "POST", akey="user_search_contacts", name="Search within contacts", business="search_contacts", crud="Read",
  subject="user", obj=OBJ("entity", "user", "User", "Contact", "User", "target", "response", "uid", "UserID(user)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("user", "User", "target"))), "io_reference", "Matched uid returned.")],
  io_in={"keyword": "attr"}, io_out={"uid": "know", "email": "observed", "name": "observed", "is_admin": "observed"}, conf=0.65)
A(API + "/user/send_mail", "POST", akey="user_send_mail_to_user", name="Send mail to another user", business="send_mail_to_user", crud="Create",
  subject="user", obj=OBJ("entity", "mail", "Mail", "Outgoing e-mail", "Mail", "created", "request", "", "EmailRecipient(mail)"),
  participants=[PRIN("recipient", "User", "recipient", "PEER")],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", PRIN("recipient", "User", "recipient", "PEER"))), "Caller names the recipient uid.")],
  gen=[eff(FACT("Exists", ENT("mail", "Mail", "created")), "action_semantics", "A mail is dispatched to another in-server user.")],
  io_in={"to_uid": "req_know_recipient", "mail_subject": "attr", "mail_content": "attr"}, conf=0.6)
A(API + "/user/update_conv", "POST", akey="user_update_conversation_comment", name="Update a conversation comment", business="update_conversation_comment", crud="Update",
  subject="user", obj=OBJ("state", "conv_setting", "ConversationSetting", "Conversation setting", "ConversationSetting", "target", "subject", "", "SystemSetting(server)", attribute="comment", state_field="comment"),
  req_facts=[authed()],
  gen=[eff(FACT("State", ENT("conv_setting", "ConversationSetting", "target"), "comment", "updated"), "state_transition", "Conversation comment stored.")],
  io_in={"conv_target_uid": "attr_ref_user", "conv_target_gid": "attr_ref_group", "conv_comment": "attr_state"}, conf=0.6)
A(API + "/user/events_ws", "GET", akey="user_subscribe_user_events_ws", name="Subscribe events over WebSocket", business="subscribe_user_events_ws", crud="Read",
  subject="user", obj=OBJ("entity", "event_stream", "EventStream", "WebSocket event stream", "EventStream", "target", "subject", "", "AccessToken(session)"),
  participants=[ENT("other_user", "User", "target"), ENT("group", "Group", "target"), ENT("message", "Message", "target")],
  req_facts=[authed("Session", "Token presented (api-key query param) for the WebSocket upgrade.")],
  gen=[eff(FACT("Know", U, REF("UserID", ENT("other_user", "User", "target"))), "io_reference", "Stream exposes user ids."),
       eff(FACT("Know", U, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Stream exposes group ids."),
       eff(FACT("Know", U, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Stream exposes message ids.")],
  io_in={"api-key": "attr_cred", "after_mid": "attr_cursor", "users_version": "attr_cursor"},
  io_out={"events_uid": "know", "events_gid": "know", "events_mid": "know", "events": "observed"}, conf=0.6,
  reasoning="WebSocket (HTTP 101) variant of /user/events; carries the same reference-bearing event stream.")
A(API + "/voice/avo/events_ws", "GET", akey="user_subscribe_voice_events_ws", name="Subscribe voice/Avo room events over WebSocket",
  business="subscribe_voice_events_ws", crud="Read", subject="user",
  obj=OBJ("entity", "voice_room", "VoiceRoom", "Voice/Avo room", "VoiceRoom", "target", "request", "room_id", "GroupID(group)"),
  req_facts=[authed("Session", "Token presented for the WebSocket upgrade.")],
  io_in={"room_type": "attr", "room_id": "attr_ref_group"}, io_out={"events": "observed"}, conf=0.55,
  reasoning="Voice/Avo realtime channel under /api/voice (part of the OpenAPI service).")

# ---- token ------------------------------------------------------------------
A(API + "/token/parse_tokens", "POST", akey="anonymous_parse_tokens", name="Introspect a token pair", business="parse_tokens", crud="Read",
  subject="anon", obj=OBJ("entity", "session", "Session", "Token pair", "Session", "target", "request", "token", "AccessToken(session)"),
  req_facts=[req("knowledge", FACT("Know", U, REF("AccessToken", ENT("session", "Session", "target"))), "Caller supplies the token(s) to decode.")],
  io_in={"token": "req_know", "refresh_token": "attr_cred"}, io_out={"parse_result": "observed"}, conf=0.6,
  reasoning="Unauthenticated token-introspection endpoint; decodes supplied access/refresh tokens.")

# ---- admin ------------------------------------------------------------------
A(API + "/admin/system/update_webclient", "GET", akey="admin_update_webclient", name="Update the bundled web client", business="update_webclient", crud="Update",
  subject="admin", obj=OBJ("state", "server", "Server", "Bundled web client", "Server", "target", "implicit", "", "WebClientVersion(server)", attribute="webclient", state_field="webclient"),
  req_facts=[authed()],
  gen=[eff(FACT("State", ENT("server", "Server", "target"), "webclient", "updated"), "state_transition", "Server fetches and installs a newer web client bundle.")],
  conf=0.6)
A(API + "/admin/vocespace/enabled", "GET", akey="user_read_vocespace_enabled", name="Read VoceSpace enabled flag", business="read_vocespace_enabled", crud="Read",
  subject="user", obj=OBJ("state", "server", "Server", "VoceSpace enabled flag", "Server", "target", "implicit", "", "FeatureEnabled(server)", attribute="vocespace_enabled", state_field="vocespace_enabled"),
  req_facts=[authed()], io_out={"enabled": "observed"}, conf=0.65)
A(API + "/admin/agora/channel_event_callback", "POST", akey="anonymous_ingest_agora_channel_event", name="Ingest an Agora channel event",
  business="ingest_agora_channel_event", crud="Create", subject="anon",
  obj=OBJ("entity", "agora_event", "AgoraChannelEvent", "Agora RTC channel event", "AgoraChannelEvent", "created", "request", "", "AgoraChannelEvent(call)"),
  gen=[eff(FACT("Exists", ENT("agora_event", "AgoraChannelEvent", "created")), "action_semantics", "An inbound Agora channel event is ingested server-side.")],
  io_in={"agora_event": "attr"}, conf=0.55,
  reasoning="Public webhook invoked by Agora's RTC service; unauthenticated event ingestion.")
A(API + "/admin/agora/channel/user/property/{uid}/{channel_name}", "GET", akey="user_read_voice_channel_user_property",
  name="Read a user's property in a voice channel", business="read_voice_channel_user_property", crud="Read", subject="user",
  obj=OBJ("state", "call_user", "User", "User property in a voice channel", "User", "target", "request", "uid", "UserID(user)", attribute="channel_property", state_field="channel_property"),
  participants=[ENT("call", "CallChannel", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", U, REF("UserID", ENT("call_user", "User", "target"))), "Caller names the uid."),
             req("knowledge", FACT("Know", U, REF("AgoraChannelName", ENT("call", "CallChannel", "target"))), "Caller supplies the channel name.")],
  io_in={"uid": "req_know", "channel_name": "req_know_callname"}, io_out={"agora_user_property": "observed", "bool_result": "observed"}, conf=0.55)
