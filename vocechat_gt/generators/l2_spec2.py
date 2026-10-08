"""L2 cores, part 2: group, message, resource, favorite, license, admin, bot, and frontend-only endpoints."""
from l2lib import *
from l2_spec import A, OBJ, O_group, O_message, authed, U, API, BASE

GU = SUBJ()
def know_group(role="target"):
    return req("knowledge", FACT("Know", GU, REF("GroupID", ENT("group", "Group", role))), "Caller must know the group id.")
def exists_group(role="target"):
    return req("existence", FACT("Exists", ENT("group", "Group", role)), "Unknown gid returns 404.")
def know_msg(role="target"):
    return req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", role))), "Caller must know the message id.")
def exists_msg(role="target"):
    return req("existence", FACT("Exists", ENT("message", "Message", role)), "Unknown mid returns 404.")
def member_rel():
    return req("relation", FACT("Relation", GU, ENT("group", "Group", "target"), "Member"), "Caller must belong to the (private) group.")
def can(crud):
    return req("authorization", FACT("Can", GU, crud, ENT("group", "Group", "target")), "Owner/admin privilege over the group required.")

# =============================================================================
#  GROUP
# =============================================================================
A(API + "/group", "POST", selector=("is_public", [False]), akey="user_create_private_group_group",
  name="Create a private group", business="create_group", crud="Create",
  obj=OBJ("entity", "group", "Group", "New private group (channel)", "Group", "created", "response", "gid", "GroupID(group)"),
  participants=[PRIN("member", "User", "member", "PEER")],
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("group", "Group", "created")), "action_semantics", "A new private group row is created."),
       eff(FACT("Relation", GU, ENT("group", "Group", "created"), "Owner"), "relation_transition", "Creator becomes the owner of a private group."),
       eff(FACT("Relation", GU, ENT("group", "Group", "created"), "Member"), "relation_transition", "Creator is added as a member."),
       eff(FACT("Relation", PRIN("member", "User", "member", "PEER"), ENT("group", "Group", "created"), "Member"), "relation_transition", "Any uids in members[] are added as members."),
       eff(FACT("Know", GU, REF("GroupID", ENT("group", "Group", "created"))), "io_reference", "New gid returned.")],
  io_in={"group_name": "attr", "description": "attr", "is_public": "attr_state", "members": "attr_ref_user"},
  io_out={"gid": "know"}, reasoning="is_public=false branch: owner=creator, creator+members[] added to group_user (group.rs:150-212).")
A(API + "/group", "POST", selector=("is_public", [True]), akey="admin_create_public_group_group",
  name="Create a public group", business="create_group", crud="Create", subject="admin",
  obj=OBJ("entity", "group", "Group", "New public group (channel)", "Group", "created", "response", "gid", "GroupID(group)"),
  req_facts=[authed(), req("authorization", FACT("Can", GU, "Create", ENT("group", "Group", "created")), "Only an administrator may create a public group (group.rs:140-143).")],
  gen=[eff(FACT("Exists", ENT("group", "Group", "created")), "action_semantics", "A new public group row is created with owner=None and no explicit membership rows."),
       eff(FACT("Know", GU, REF("GroupID", ENT("group", "Group", "created"))), "io_reference", "New gid returned.")],
  io_in={"group_name": "attr", "description": "attr", "is_public": "attr_state"},
  io_out={"gid": "know"},
  reasoning="is_public=true branch: admin-only, owner=None, members[] must be empty, no group_user rows (group.rs:140-170).")

A(API + "/group", "GET", akey="user_list_related_groups", name="List related groups", business="list_related_groups", crud="Read",
  obj=OBJ("collection", "group_list", "Group", "Related groups", "Group", "target", "response", "gid", "GroupID(group)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", GU, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Group ids returned."),
       eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Pinned message ids returned.")],
  io_out={"gid": "know", "pinned_mid": "know", "owner": "observed", "group_name": "observed", "description": "observed",
          "members": "observed", "is_public": "observed", "pinned_content": "observed"})

A(API + "/group/{gid}", "GET", akey="anonymous_read_group", name="Read a group by id", business="read_group", crud="Read",
  obj=O_group(), req_facts=[know_group(), exists_group()],
  gen=[eff(FACT("Know", GU, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Returns the gid."),
       eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Returns pinned message ids.")],
  io_in={"gid": "req_know"},
  io_out={"gid": "know", "pinned_mid": "know", "owner": "observed", "group_name": "observed", "description": "observed",
          "members": "observed", "is_public": "observed", "pinned_content": "observed"},
  reasoning="No Token: anonymous read of any group incl. private member lists (group.rs:682-692).")

A(API + "/group/{gid}", "PUT", akey="user_update_group_group", name="Update a group", business="update_group", crud="Update",
  obj=OBJ("entity", "group", "Group", "Group (channel)", "Group", "target", "request", "gid", "GroupID(group)", state_field="name"),
  req_facts=[authed(), know_group(), exists_group(), can("Update")],
  kill=[eff(FACT("State", ENT("group", "Group", "target"), "name", "previous"), "state_transition", "Old name/description/owner replaced.")],
  gen=[eff(FACT("State", ENT("group", "Group", "target"), "name", "updated"), "state_transition", "Name/description/owner updated.")],
  io_in={"gid": "req_know", "group_name": "attr_state", "description": "attr_state", "owner": "attr_ref_user"})

A(API + "/group/{gid}", "DELETE", akey="user_delete_group_group", name="Delete a group", business="delete_group", crud="Delete",
  obj=O_group(), req_facts=[authed(), know_group(), exists_group(), can("Delete")],
  kill=[eff(FACT("Exists", ENT("group", "Group", "target")), "action_semantics", "Group row deleted and members kicked.")],
  io_in={"gid": "req_know"})

A(API + "/group/{gid}/change_type", "POST", akey="user_change_group_visibility", name="Change group public/private",
  business="change_group_visibility", crud="Update",
  obj=OBJ("entity", "group", "Group", "Group (channel)", "Group", "target", "request", "gid", "GroupID(group)", state_field="is_public"),
  req_facts=[authed(), know_group(), exists_group(), can("Update")],
  kill=[eff(FACT("State", ENT("group", "Group", "target"), "is_public", "previous"), "state_transition", "Previous visibility replaced.")],
  gen=[eff(FACT("State", ENT("group", "Group", "target"), "is_public", "updated"), "state_transition", "Group visibility toggled; membership rebuilt.")],
  io_in={"gid": "req_know", "is_public": "attr_state", "members": "attr_ref_user"})

A(API + "/group/{gid}/avatar", "POST", akey="user_upload_group_avatar", name="Upload group avatar", business="upload_group_avatar", crud="Update",
  obj=OBJ("entity", "group", "Group", "Group avatar", "Group", "target", "request", "gid", "GroupID(group)", state_field="avatar"),
  req_facts=[authed(), know_group(), can("Update")],
  gen=[eff(FACT("State", ENT("group", "Group", "target"), "avatar", "updated"), "state_transition", "Group avatar replaced.")],
  io_in={"gid": "req_know", "group_avatar": "attr_state"})

A(API + "/group/{gid}/leave", "GET", akey="user_leave_group", name="Leave a group", business="leave_group", crud="Delete",
  obj=OBJ("relation", "membership", "GroupMembership", "Own membership", "GroupMembership", "target", "request", "gid", "GroupID(group)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), exists_group(), member_rel()],
  kill=[eff(FACT("Relation", GU, ENT("group", "Group", "target"), "Member"), "relation_transition", "Caller removed from the group.")],
  io_in={"gid": "req_know"})

A(API + "/group/{gid}/members/add", "POST", akey="user_add_group_members", name="Add members to a group",
  business="add_group_members", crud="Create",
  obj=OBJ("relation", "membership", "GroupMembership", "Group membership", "GroupMembership", "created", "request", "gid", "GroupID(group)"),
  participants=[ENT("group", "Group", "target"), PRIN("member", "User", "member", "PEER")],
  req_facts=[authed(), know_group(), exists_group(), member_rel(),
             req("knowledge", FACT("Know", GU, REF("UserID", PRIN("member", "User", "member", "PEER"))), "Caller names the uids to add.")],
  gen=[eff(FACT("Relation", PRIN("member", "User", "member", "PEER"), ENT("group", "Group", "target"), "Member"), "relation_transition", "Named users added to the group.")],
  io_in={"gid": "req_know", "members": "req_know_member"},
  reasoning="Any member (not only owner) may add members to a private group (group.rs:731-737).")

A(API + "/group/{gid}/members/remove", "POST", akey="user_remove_group_members", name="Remove members from a group",
  business="remove_group_members", crud="Delete",
  obj=OBJ("relation", "membership", "GroupMembership", "Group membership", "GroupMembership", "target", "request", "gid", "GroupID(group)"),
  participants=[ENT("group", "Group", "target"), PRIN("member", "User", "member", "PEER")],
  req_facts=[authed(), know_group(), exists_group(), can("Update"),
             req("knowledge", FACT("Know", GU, REF("UserID", PRIN("member", "User", "member", "PEER"))), "Caller names the uids to remove.")],
  kill=[eff(FACT("Relation", PRIN("member", "User", "member", "PEER"), ENT("group", "Group", "target"), "Member"), "relation_transition", "Named users removed.")],
  io_in={"gid": "req_know", "members": "req_know_member"})

A(API + "/group/{gid}/send", "POST", akey="user_send_group_message_message", name="Send a group message",
  business="send_group_message", crud="Create",
  obj=OBJ("entity", "message", "Message", "Group message", "Message", "created", "response", "", "MessageID(message)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), exists_group(), member_rel()],
  gen=[eff(FACT("Exists", ENT("message", "Message", "created")), "action_semantics", "A new group message is stored and broadcast."),
       eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "created"))), "io_reference", "New mid returned.")],
  io_in={"gid": "req_know", "content": "attr"}, io_out={"mid": "know"})

A(API + "/group/{gid}/history", "GET", akey="user_read_group_message_history", name="Read group history",
  business="read_group_message_history", crud="Read",
  obj=OBJ("collection", "message_list", "Message", "Group history", "Message", "target", "response", "mid", "MessageID(message)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), exists_group(), member_rel()],
  gen=[eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Message ids returned.")],
  io_in={"gid": "req_know", "before": "attr_cursor"},
  io_out={"mid": "know", "from_uid": "observed", "target_uid": "observed", "target_gid": "observed", "content": "observed", "ref_mid": "observed"})

A(API + "/group/create_reg_magic_link", "GET", akey="user_create_invite_link", name="Create a registration invite link",
  business="create_invite_link", crud="Create",
  obj=OBJ("entity", "invite", "MagicLink", "Registration invite link", "MagicLink", "created", "response", "", "MagicLinkURL(magic_link)"),
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("invite", "MagicLink", "created")), "action_semantics", "A signed invite token is created."),
       eff(FACT("Know", GU, REF("MagicLinkURL", ENT("invite", "MagicLink", "created"))), "io_reference", "Invite URL returned.")],
  io_in={"gid": "attr_ref_group"}, io_out={"magic_link": "know"})

A(API + "/group/create_invite_private_magic_link", "GET", akey="user_create_private_invite_link",
  name="Create a private-group invite link", business="create_private_group_invite_link", crud="Create",
  obj=OBJ("entity", "invite", "MagicLink", "Private invite link", "MagicLink", "created", "response", "", "MagicLinkURL(magic_link)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group()],
  gen=[eff(FACT("Exists", ENT("invite", "MagicLink", "created")), "action_semantics", "A private-group invite token is created."),
       eff(FACT("Know", GU, REF("MagicLinkURL", ENT("invite", "MagicLink", "created"))), "io_reference", "Invite URL returned.")],
  io_in={"gid": "req_know"}, io_out={"magic_link": "know"}, conf=0.75)

A(API + "/group/{gid}/agora_token", "GET", akey="user_create_group_call_token", name="Get a group call token",
  business="create_group_call_token", crud="Create",
  obj=OBJ("entity", "call_token", "CallToken", "Agora RTC token", "CallToken", "created", "response", "", "AgoraToken(call)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), member_rel()],
  gen=[eff(FACT("Know", GU, REF("AgoraToken", ENT("call_token", "CallToken", "created"))), "io_reference", "RTC token returned.")],
  io_in={"gid": "req_know"}, io_out={"agora_token": "know", "app_id": "observed", "uid": "observed", "channel_name": "observed"},
  conf=0.8)

A(API + "/group/{gid}/pin", "POST", akey="user_pin_group_message", name="Pin a message", business="pin_group_message", crud="Update",
  obj=OBJ("entity", "group", "Group", "Group pinned set", "Group", "target", "request", "gid", "GroupID(group)", state_field="pinned_messages"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[authed(), know_group(), can("Update"),
             req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller names the message to pin."),
             exists_msg()],
  gen=[eff(FACT("State", ENT("group", "Group", "target"), "pinned_messages", "updated"), "state_transition", "Message added to the pinned set.")],
  io_in={"gid": "req_know", "mid": "req_know_msg"})

A(API + "/group/{gid}/unpin", "POST", akey="user_unpin_group_message", name="Unpin a message", business="unpin_group_message", crud="Update",
  obj=OBJ("entity", "group", "Group", "Group pinned set", "Group", "target", "request", "gid", "GroupID(group)", state_field="pinned_messages"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[authed(), know_group(), can("Update"),
             req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller names the pinned message.")],
  kill=[eff(FACT("State", ENT("group", "Group", "target"), "pinned_messages", "previous"), "state_transition", "Message removed from the pinned set.")],
  io_in={"gid": "req_know", "mid": "req_know_msg"})

A(API + "/group/{gid}/clear", "DELETE", akey="user_clear_group_messages", name="Clear group messages",
  business="clear_group_messages", crud="Delete",
  obj=OBJ("collection", "message_list", "Message", "Group messages", "Message", "target", "request", "gid", "GroupID(group)"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), can("Delete")],
  kill=[eff(FACT("Exists", ENT("message", "Message", "target")), "action_semantics", "All messages in the group are removed.")],
  io_in={"gid": "req_know"}, conf=0.7)

A(API + "/group/{gid}/announcement", "GET", akey="user_read_group_announcement", name="Read group announcement",
  business="read_group_announcement", crud="Read",
  obj=OBJ("state", "group", "Group", "Group announcement", "Group", "target", "request", "gid", "GroupID(group)",
          attribute="announcement", state_field="announcement"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group()],
  gen=[eff(FACT("Know", GU, REF("GroupID", ENT("group", "Group", "target"))), "io_reference", "Announcement carries its gid.")],
  io_in={"gid": "req_know"}, io_out={"gid": "know", "announcement": "observed", "created_by": "observed"}, conf=0.8)

A(API + "/group/{gid}/announcement", "POST", akey="user_upsert_group_announcement", name="Set group announcement",
  business="upsert_group_announcement", crud="Update",
  obj=OBJ("state", "group", "Group", "Group announcement", "Group", "target", "request", "gid", "GroupID(group)",
          attribute="announcement", state_field="announcement"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), can("Update")],
  gen=[eff(FACT("State", ENT("group", "Group", "target"), "announcement", "updated"), "state_transition", "Announcement text set.")],
  io_in={"gid": "req_know", "announcement": "attr_state"},
  io_out={"gid": "observed", "announcement": "observed", "created_by": "observed"}, conf=0.8)

A(API + "/group/{gid}/announcement", "DELETE", akey="user_delete_group_announcement", name="Delete group announcement",
  business="delete_group_announcement", crud="Delete",
  obj=OBJ("state", "group", "Group", "Group announcement", "Group", "target", "request", "gid", "GroupID(group)",
          attribute="announcement", state_field="announcement"),
  participants=[ENT("group", "Group", "target")],
  req_facts=[authed(), know_group(), can("Update")],
  kill=[eff(FACT("State", ENT("group", "Group", "target"), "announcement", "previous"), "state_transition", "Announcement cleared.")],
  io_in={"gid": "req_know"}, conf=0.8)

# =============================================================================
#  MESSAGE (append-only reaction overlays)
# =============================================================================
A(API + "/message/{mid}/edit", "PUT", akey="user_edit_message", name="Edit a message", business="edit_message", crud="Update",
  obj=OBJ("entity", "message", "Message", "Chat message", "Message", "target", "request", "mid", "MessageID(message)", state_field="content"),
  req_facts=[authed(), know_msg(), exists_msg(),
             req("authorization", FACT("Can", GU, "Update", ENT("message", "Message", "target")), "Only the original sender may edit (can_reaction Edit, message.rs:171).")],
  kill=[eff(FACT("State", ENT("message", "Message", "target"), "content", "previous"), "state_transition", "Prior content superseded in the merged view.")],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "content", "updated"), "state_transition", "New content applied via an appended Edit-reaction record.")],
  io_in={"mid": "req_know", "content": "attr_state"}, io_out={"mid": "observed"},
  reasoning="Implemented as an appended reaction, not an in-place row update (message_api.rs:45).")

A(API + "/message/{mid}/like", "PUT", akey="user_react_to_message", name="React to a message", business="react_to_message", crud="Update",
  obj=OBJ("entity", "message", "Message", "Chat message", "Message", "target", "request", "mid", "MessageID(message)", state_field="reactions"),
  req_facts=[authed(), know_msg(), exists_msg()],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "reactions", "updated"), "state_transition", "An emoji reaction record is appended.")],
  io_in={"mid": "req_know", "action": "attr_state"}, io_out={"mid": "observed"},
  reasoning="Any user may react; no membership check on the target conversation (message.rs:172).")

A(API + "/message/{mid}", "DELETE", akey="user_delete_message", name="Delete a message", business="delete_message", crud="Delete",
  obj=O_message(),
  req_facts=[authed(), know_msg(), exists_msg(),
             req("authorization", FACT("Can", GU, "Delete", ENT("message", "Message", "target")), "Sender or an admin may delete (message.rs:173).")],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "visibility", "deleted"), "state_transition", "A Delete-reaction tombstone is appended, establishing the message's deleted/hidden state in the merged view.")],
  io_in={"mid": "req_know"}, io_out={"mid": "observed"},
  reasoning="Append-only delete overlay rather than row removal: GEN the resulting deleted state (not KILL it); /history still returns the original payload (message_api.rs:85; see annotation_issues issue-002).")

A(API + "/message/{mid}/reply", "POST", akey="user_reply_to_message_message", name="Reply to a message", business="reply_to_message", crud="Create",
  obj=OBJ("entity", "reply", "Message", "Reply message", "Message", "created", "response", "", "MessageID(message)"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller names the message replied to."),
             exists_msg()],
  gen=[eff(FACT("Exists", ENT("reply", "Message", "created")), "action_semantics", "A new reply message is stored."),
       eff(FACT("Know", GU, REF("MessageID", ENT("reply", "Message", "created"))), "io_reference", "New reply mid returned.")],
  io_in={"mid": "req_know_msg", "content": "attr"}, io_out={"mid": "know"})

A(API + "/message/bulk/{mids}", "DELETE", akey="user_bulk_delete_messages", name="Bulk delete messages",
  business="bulk_delete_messages", crud="Delete",
  obj=OBJ("collection", "message_list", "Message", "Chat messages", "Message", "target", "request", "mids", "MessageID(message)"),
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller lists the message ids.")],
  gen=[eff(FACT("State", ENT("message", "Message", "target"), "visibility", "deleted"), "state_transition", "Each listed message gets a delete overlay establishing its deleted state.")],
  io_in={"mids": "req_know_msg"}, io_out={"count_result": "observed"}, conf=0.75)

# =============================================================================
#  RESOURCE / FILE / ARCHIVE
# =============================================================================
A(API + "/resource/file/prepare", "POST", akey="user_prepare_file_upload", name="Prepare a file upload",
  business="prepare_file_upload", crud="Create",
  obj=OBJ("entity", "upload", "Upload", "Pending upload", "Upload", "created", "response", "", "UploadID(upload)"),
  req_facts=[authed()],
  gen=[eff(FACT("Exists", ENT("upload", "Upload", "created")), "action_semantics", "A temp file + meta are created."),
       eff(FACT("Know", GU, REF("UploadID", ENT("upload", "Upload", "created"))), "io_reference", "Upload UUID returned.")],
  io_in={"filename": "attr"}, io_out={"file_id": "know"})

A(API + "/resource/file/upload", "POST", akey="user_upload_file_chunk", name="Upload a file chunk",
  business="upload_file_chunk", crud="Update",
  obj=OBJ("entity", "upload", "Upload", "Pending upload", "Upload", "target", "request", "file_id", "UploadID(upload)", state_field="bytes"),
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("UploadID", ENT("upload", "Upload", "target"))), "Caller supplies the upload id."),
             req("existence", FACT("Exists", ENT("upload", "Upload", "target")), "Unknown/absent upload id returns 400.")],
  gen=[eff(FACT("State", ENT("upload", "Upload", "target"), "bytes", "appended"), "state_transition", "Chunk appended; last chunk finalises a stored file."),
       eff(FACT("Exists", ENT("file", "File", "created")), "action_semantics", "The last chunk materialises a stored file (consumed by GET /resource/file)."),
       eff(FACT("Know", GU, REF("FilePath", ENT("file", "File", "created"))), "io_reference", "Final chunk returns the stored file path.")],
  participants=[ENT("file", "File", "created")],
  io_in={"file_id": "req_know", "chunk_data": "attr_state"}, io_out={"path": "know", "hash": "observed"},
  reasoning="file_id is used as a filesystem path without validation (resource.rs:206).")

A(API + "/resource/file", "GET", akey="anonymous_download_file", name="Download a file", business="download_file", crud="Read",
  obj=OBJ("entity", "file", "File", "Stored file", "File", "target", "request", "file_path", "FilePath(file)"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("FilePath", ENT("file", "File", "target"))), "Caller must know the file path."),
             req("existence", FACT("Exists", ENT("file", "File", "target")), "Unknown path returns 404.")],
  io_in={"file_path": "req_know"}, io_out={"file_bytes": "observed"},
  reasoning="No auth: path-bearer download (resource.rs:341).")

A(API + "/resource/archive", "POST", akey="user_create_message_archive", name="Archive messages", business="create_message_archive", crud="Create",
  obj=OBJ("entity", "archive", "Archive", "Message archive", "Archive", "created", "response", "", "ArchivePath(archive)"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller lists the message ids to archive.")],
  gen=[eff(FACT("Exists", ENT("archive", "Archive", "created")), "action_semantics", "An archive blob is written."),
       eff(FACT("Know", GU, REF("ArchivePath", ENT("archive", "Archive", "created"))), "io_reference", "Archive path returned.")],
  io_in={"mid_list": "req_know_msg"}, io_out={"archive_path": "know"})

A(API + "/resource/archive", "GET", akey="anonymous_read_message_archive", name="Read a message archive", business="read_message_archive", crud="Read",
  obj=OBJ("entity", "archive", "Archive", "Message archive", "Archive", "target", "request", "file_path", "ArchivePath(archive)"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("ArchivePath", ENT("archive", "Archive", "target"))), "Caller must know the archive path."),
             req("existence", FACT("Exists", ENT("archive", "Archive", "target")), "Unknown path returns 404.")],
  gen=[eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Archive rows expose original message ids."),
       eff(FACT("Know", GU, REF("ArchiveAttachmentID", ENT("att", "ArchiveAttachment", "target"))), "io_reference", "Archive rows expose attachment ids.")],
  participants=[ENT("message", "Message", "target"), ENT("att", "ArchiveAttachment", "target")],
  io_in={"file_path": "req_know"},
  io_out={"archive_mid": "know", "archive_file_id": "know", "archive_user_name": "observed", "archive_source_uid": "observed",
          "archive_source_gid": "observed", "archive_content": "observed"},
  reasoning="No auth on archive read (resource.rs:414).")

A(API + "/resource/archive/attachment", "GET", akey="anonymous_download_archive_attachment", name="Download an archive attachment",
  business="download_archive_attachment", crud="Read",
  obj=OBJ("entity", "att", "ArchiveAttachment", "Archive attachment", "ArchiveAttachment", "target", "request", "attachment_id", "ArchiveAttachmentID(archive_attachment)"),
  participants=[ENT("archive", "Archive", "target")],
  req_facts=[req("knowledge", FACT("Know", GU, REF("ArchivePath", ENT("archive", "Archive", "target"))), "Caller must know the archive path."),
             req("knowledge", FACT("Know", GU, REF("ArchiveAttachmentID", ENT("att", "ArchiveAttachment", "target"))), "Caller supplies the attachment index.")],
  io_in={"file_path": "req_know_archive", "attachment_id": "req_know"}, io_out={"attachment_bytes": "observed"})

A(API + "/resource/open_graphic_parse", "GET", akey="anonymous_fetch_url_preview", name="Fetch an Open-Graph preview",
  business="fetch_url_preview", crud="Read",
  obj=OBJ("entity", "url", "ExternalURL", "External URL", "ExternalURL", "target", "request", "url", "ExternalURL(url)"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("ExternalURL", ENT("url", "ExternalURL", "target"))), "Caller supplies the URL to fetch.")],
  io_in={"url": "req_know"},
  reasoning="Unauthenticated server-side fetch (SSRF primitive, resource.rs:467).")

A(API + "/resource/organization/logo", "GET", akey="anonymous_read_organization_logo", name="Read organization logo",
  business="read_organization_logo", crud="Read",
  obj=OBJ("state", "server", "Server", "Organization logo", "Server", "target", "implicit", "", "OrganizationLogo(server)", attribute="logo", state_field="logo"),
  io_out={})
A(API + "/resource/avatar", "GET", akey="anonymous_read_user_avatar", name="Read a user avatar", business="read_user_avatar", crud="Read",
  obj=OBJ("state", "user", "User", "User avatar", "User", "target", "request", "uid", "UserID(user)", attribute="avatar", state_field="avatar"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("UserID", ENT("user", "User", "target"))), "Caller supplies the uid.")],
  io_in={"uid": "req_know"})
A(API + "/resource/group_avatar", "GET", akey="anonymous_read_group_avatar", name="Read a group avatar", business="read_group_avatar", crud="Read",
  obj=OBJ("state", "group", "Group", "Group avatar", "Group", "target", "request", "gid", "GroupID(group)", attribute="avatar", state_field="avatar"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("GroupID", ENT("group", "Group", "target"))), "Caller supplies the gid.")],
  io_in={"gid": "req_know"})
A(API + "/resource/widget-extra.css", "GET", akey="anonymous_read_widget_css", name="Read widget CSS", business="read_widget_css", crud="Read",
  obj=OBJ("state", "server", "Server", "Widget CSS", "Server", "target", "implicit", "", "WidgetCSS(server)", attribute="widget_css", state_field="widget_css"),
  io_out={"css": "observed"})
A(API + "/resource/widget-extra.css", "PUT", akey="admin_update_widget_css", name="Update widget CSS", business="update_widget_css", crud="Update",
  subject="admin", obj=OBJ("state", "server", "Server", "Widget CSS", "Server", "target", "implicit", "", "WidgetCSS(server)", attribute="widget_css", state_field="widget_css"),
  req_facts=[authed()], gen=[eff(FACT("State", ENT("server", "Server", "target"), "widget_css", "updated"), "state_transition", "Widget CSS replaced.")],
  io_in={"css": "attr_state"}, io_out={"bool_result": "observed"}, conf=0.7)
A(API + "/resource/file/delete", "DELETE", akey="admin_delete_all_files", name="Delete all files", business="admin_delete_all_files", crud="Delete",
  subject="admin", obj=OBJ("collection", "file_list", "File", "All stored files", "File", "target", "implicit", "", "FilePath(file)"),
  req_facts=[authed()], kill=[eff(FACT("Exists", ENT("file", "File", "target")), "action_semantics", "All stored files removed.")], conf=0.65)

# =============================================================================
#  FAVORITE
# =============================================================================
A(API + "/favorite", "POST", akey="user_create_favorite_archive", name="Create a favorite archive", business="create_favorite_archive", crud="Create",
  obj=OBJ("entity", "favorite", "Favorite", "Favorite archive", "Favorite", "created", "response", "favorite_id", "FavoriteID(favorite)"),
  participants=[ENT("message", "Message", "target")],
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "Caller lists message ids to favourite.")],
  gen=[eff(FACT("Exists", ENT("favorite", "Favorite", "created")), "action_semantics", "A favorite archive is written for the caller."),
       eff(FACT("Know", GU, REF("FavoriteID", ENT("favorite", "Favorite", "created"))), "io_reference", "Favorite UUID returned.")],
  io_in={"mid_list": "req_know_msg"}, io_out={"favorite_id": "know"})
A(API + "/favorite", "GET", akey="user_list_favorites", name="List favorites", business="list_favorites", crud="Read",
  obj=OBJ("collection", "favorite_list", "Favorite", "Own favorites", "Favorite", "target", "response", "favorite_id", "FavoriteID(favorite)"),
  req_facts=[authed()],
  gen=[eff(FACT("Know", GU, REF("FavoriteID", ENT("favorite", "Favorite", "target"))), "io_reference", "Favorite ids returned.")],
  io_out={"favorite_id": "know"})
A(API + "/favorite/{id}", "GET", akey="user_read_favorite", name="Read a favorite", business="read_favorite", crud="Read",
  obj=OBJ("entity", "favorite", "Favorite", "Favorite archive", "Favorite", "target", "request", "id", "FavoriteID(favorite)"),
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("FavoriteID", ENT("favorite", "Favorite", "target"))), "Caller names the favorite id."),
             req("existence", FACT("Exists", ENT("favorite", "Favorite", "target")), "Unknown id returns 404.")],
  gen=[eff(FACT("Know", GU, REF("MessageID", ENT("message", "Message", "target"))), "io_reference", "Archived message ids exposed."),
       eff(FACT("Know", GU, REF("ArchiveAttachmentID", ENT("att", "ArchiveAttachment", "target"))), "io_reference", "Attachment ids exposed.")],
  participants=[ENT("message", "Message", "target"), ENT("att", "ArchiveAttachment", "target")],
  io_in={"id": "req_know"},
  io_out={"archive_mid": "know", "archive_file_id": "know", "archive_user_name": "observed", "archive_source_uid": "observed",
          "archive_source_gid": "observed", "archive_content": "observed"})
A(API + "/favorite/{id}", "DELETE", akey="user_delete_favorite", name="Delete a favorite", business="delete_favorite", crud="Delete",
  obj=OBJ("entity", "favorite", "Favorite", "Favorite archive", "Favorite", "target", "request", "id", "FavoriteID(favorite)"),
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("FavoriteID", ENT("favorite", "Favorite", "target"))), "Caller names the favorite id."),
             req("existence", FACT("Exists", ENT("favorite", "Favorite", "target")), "Unknown id returns 404.")],
  kill=[eff(FACT("Exists", ENT("favorite", "Favorite", "target")), "action_semantics", "Favorite archive deleted.")],
  io_in={"id": "req_know"})
A(API + "/favorite/attachment/{uid}/{id}/{attachment_id}", "GET", akey="anonymous_download_favorite_attachment",
  name="Download a favorite attachment", business="download_favorite_attachment", crud="Read",
  obj=OBJ("entity", "att", "ArchiveAttachment", "Favorite attachment", "ArchiveAttachment", "target", "request", "attachment_id", "ArchiveAttachmentID(archive_attachment)"),
  participants=[ENT("favorite", "Favorite", "target")],
  req_facts=[req("knowledge", FACT("Know", GU, REF("FavoriteID", ENT("favorite", "Favorite", "target"))), "Caller supplies owner uid + favorite id."),
             req("knowledge", FACT("Know", GU, REF("ArchiveAttachmentID", ENT("att", "ArchiveAttachment", "target"))), "Caller supplies the attachment index.")],
  io_in={"id": "req_know_fav", "uid": "attr_ref_user", "attachment_id": "req_know"}, io_out={"attachment_bytes": "observed"},
  reasoning="No auth; owner uid is a caller-supplied path segment (favorite.rs:149).")

# =============================================================================
#  LICENSE
# =============================================================================
A(API + "/license/check", "POST", akey="anonymous_check_license", name="Validate a license blob", business="check_license", crud="Read",
  obj=OBJ("entity", "license", "License", "License blob", "License", "target", "request", "license", "LicenseBlob(license)"),
  req_facts=[req("knowledge", FACT("Know", GU, REF("LicenseBlob", ENT("license", "License", "target"))), "Caller supplies the license blob.")],
  io_in={"license": "req_know"}, io_out={"license_domains": "observed", "user_limit": "observed", "sign": "observed", "base58": "observed"})
A(API + "/license", "GET", akey="anonymous_read_license", name="Read the installed license", business="read_license", crud="Read",
  obj=OBJ("entity", "license", "License", "Installed license", "License", "target", "implicit", "", "LicenseBlob(license)"),
  io_out={"license_domains": "observed", "user_limit": "observed", "sign": "observed", "base58": "observed"},
  reasoning="Unauthenticated read of the license incl. its blob (license.rs:87).")
A(API + "/license", "PUT", akey="user_save_license", name="Install a license", business="save_license", crud="Update",
  obj=OBJ("entity", "license", "License", "Installed license", "License", "target", "request", "license", "LicenseBlob(license)", state_field="license"),
  req_facts=[authed(), req("knowledge", FACT("Know", GU, REF("LicenseBlob", ENT("license", "License", "target"))), "Caller supplies the license blob.")],
  gen=[eff(FACT("State", ENT("license", "License", "target"), "license", "updated"), "state_transition", "License file written (admin, or any user when no license exists).")],
  io_in={"license": "req_know"}, io_out={"bool_result": "observed"},
  reasoning="Returns 200 true even for non-admins; effect only applies if admin or no license file (license.rs:68).")
