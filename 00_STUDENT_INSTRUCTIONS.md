# Pengent-Compatible Web Ground Truth — Student Instructions (v1)

Use this schema for ALL traditional Web-application annotations.

DO NOT add/remove/rename schema fields on your own.
If a real case cannot be represented, add it to `annotation_issues.yaml` with evidence and ask before changing the schema.

The goal is:
1. human GT can contain MORE evidence/metadata than Pengent;
2. human GT must contain AT LEAST everything Pengent needs for its current L1 and Action-L2 v3;
3. the GT can be exported to Pengent's `layer1` / `layer2` JSON format for later experiments.

Files to produce for each environment:

- `environment.yaml`
- `l1_gt.yaml`
- `l2_gt.yaml`
- `annotation_issues.yaml`

Use source code / internal evidence to build the reference GT. Also run the deployed target whenever possible to verify routes, IO, statuses, identities, and effects.

---

# 1. Scope

Annotate the ACTUAL benchmark deployment.

Primary GT includes:
- routes/interactions registered in the deployed target;
- API/page/static nodes that belong to the in-scope application;
- routes that are unlinked/hidden but still registered and callable in the deployment;
- role/state dependent routes if the needed state can exist in the deployed target.

Do NOT put these in the primary GT:
- dead code;
- test-only routes not in the benchmark deployment;
- routes behind a feature/component that is not mounted/enabled in the benchmark deployment;
- scoring/CTF harness endpoints outside the intended application;
- unrelated third-party services.

Put such cases in `excluded_items` or `annotation_issues.yaml`.

---

# 2. L1 definition: Pengent InteractionGraph

L1 is the deployed Web interaction graph.

## 2.1 L1 node unit

ONE L1 NODE = ONE normalized endpoint identity in Pengent:

`normalized origin + normalized path`

Query-string values do NOT create separate nodes.
Query parameter NAMES go into `params`.

Examples:

Concrete:
`https://app.test/api/orders/17?expand=items`

L1 key:
`https://app.test/api/orders/{order_id}`

`params`:
`["expand"]`

Different legitimate HTTP methods on the SAME normalized route stay in the SAME L1 node.
Method-specific IO belongs in separate `io_variants`.

## 2.2 L1 kind

Exactly one of:
- `api`
- `page`
- `static`

Only `api` nodes with non-empty `io_variants` are candidates that Pengent requires Action-L2 coverage for.

## 2.3 L1 core fields

The following fields are Pengent fields and MUST be present:

- `key`
- `kind`
- `methods`
- `statuses`
- `content_types`
- `params`
- `inputs`
- `outputs`
- `input_spec`
- `io_variants`
- `operation_semantic`
- `semantic_inputs`
- `semantic_outputs`
- `semantic_input_decisions`
- `semantic_output_decisions`
- `samples`
- `sources`
- `referrers`
- `resource_types`
- `js_sources`
- `identity_statuses`
- `route_confirmed`
- `runtime_api_prefixes`

Human-GT-only metadata goes under `gt`.

## 2.4 `params`, `inputs`, and `outputs`

`params`
- query parameter names observed/supported by the route.
- query VALUES are not stored here.

`inputs`
- union of business-data request field names used by the L1 IO contracts.

`outputs`
- union of business-data response field names used by the L1 IO contracts.

For manual GT, derive `inputs` and `outputs` from the `flow: true` fields in `io_variants`.

Do not put protocol/noise fields into semantic flow merely because they appear in JSON/HTTP.

## 2.5 `io_variants`

This is REQUIRED for each API endpoint that should enter Pengent L2.

Keep contracts METHOD-SPECIFIC.

Each variant contains:
- method
- content_types
- inputs
- outputs
- input
- request
- response
- reason
- evidence

Request field:
- `name`
- `location`: path | query | header | body
- `path`: nested path when needed
- `type`
- `required`
- `flow`
- `description`

Response:
- `format`: json | scalar | raw | empty | unknown
- structured responses use `fields`
- scalar/raw/root-array responses may use:
  - `value_name`
  - `value_type`
  - `value_flow`
  - `value_description`

Response field:
- `name`
- `path`
- `type`
- `flow`
- `description`

RULE:
`flow: true` means this is business data relevant to semantic data flow.
Protocol metadata / presentation-only noise should be `flow: false`.

## 2.6 `operation_semantic`

Required for meaningful non-error API nodes.

Use stable `verb_object` form:
- `create_order`
- `read_user_profile`
- `delete_project`
- `send_message_to_user`

This is an endpoint-level semantic hint, NOT the final L2 Action.

## 2.7 Semantic IO decisions

Every relevant business-data input/output field, plus nested `flow:true` stable references, must receive a decision.

Each decision has EXACTLY:

- `raw_field`
- `resource`
- `mergeable`
- `value_kind`
- `reference_capable`
- `reference_fields`
- `reason`

`resource` format:
`ResourceName(scope)`

Examples:
- `OrderID(order)`
- `UserID(user)`
- `SessionToken(session)`
- `MessageContent(message)`

Allowed `value_kind`:
- identifier
- locator
- credential
- content
- state
- attribute
- collection
- summary
- opaque

`mergeable=true`
means this value can be normalized as the same business resource across endpoints.

IMPORTANT:
`mergeable=true` DOES NOT automatically mean "object reference".

`reference_capable=true`
ONLY when the value is a stable reference that can identify/locate an object and can plausibly be passed to another API.

Normally only:
- identifier
- locator

may be `reference_capable=true`.

If `reference_capable=true`, `reference_fields` MUST contain the real request/response field path(s) supporting it.

Collections, summaries, arbitrary content, and ordinary attributes are NOT object references.

`semantic_inputs` and `semantic_outputs`
must contain ONLY the resource names whose decision has `mergeable=true`.

## 2.8 Samples and identity evidence

`samples` store representative runtime request/response evidence.

Keep identity explicit.

`identity_statuses` must be identity-scoped, e.g.:

```yaml
identity_statuses:
  anonymous: [401]
  user: [200]
  admin: [200]
```

Do NOT collapse statuses across identities.

## 2.9 L1 edges

L1 edges are real observed/supported navigation/request transitions:

- `src`
- `dst`
- `methods`
- `triggers`

Typical triggers:
- link
- form
- xhr
- fetch
- redirect
- referrer
- script
- other

Do not invent an L1 edge just because two routes operate on the same object.

---

# 3. L2 definition: Pengent Action-L2 v3

Pengent's current L2 action is:

`A = <Subject, Operation, Object, Req, Eff>`

Human GT MUST use the same representation.

Do NOT manually create semantic L2 edges.
Pengent derives them deterministically from Req / GEN / KILL typed facts.

## 3.1 L2 coverage rule

Every in-scope L1 node satisfying BOTH:
- `kind: api`
- non-empty `io_variants`

must be bound to at least one L2 Action unless Pengent's explicit L2-exemption logic excludes it.

For our annotation task, assume it needs L2 coverage unless we explicitly approve an exemption.

L1 <-> L2 is MANY-TO-MANY.

One Action may bind multiple L1 endpoints.

One L1 endpoint may map to multiple Actions when a discriminator changes the business operation, e.g.:
- `action=approve`
- `action=reject`

Use `l1_bindings[].selector`.

## 3.2 One L2 Action = one business action

Do NOT combine unrelated CRUD operations into one Action.

WRONG:
`project.lifecycle = list + create + rename + delete`

RIGHT:
- `user_read_project_project`
- `user_create_project_project`
- `user_update_project_project`
- `user_delete_project_project`

If permissions/Subject differ, they are also different Actions.

## 3.3 `action_key`

Stable snake_case identifier.

Use:
`<subject-role>_<business-operation>_<object>`

Examples:
- `user_create_order_order`
- `admin_delete_user_account`
- `user_send_direct_message_message`

Reuse the same naming convention across environments.

## 3.4 Subject

Exactly one security actor performs the Action.

Fields:
- `id`
- `identity`
- `role`
- `auth_context`

Recommended stable values:

identity:
- Anonymous
- CurrentUser
- Administrator
- ServiceAccount

role:
- Guest
- User
- Admin
- Service

auth_context:
- Anonymous
- Session
- APIToken
- ServiceCredential

Do NOT use a concrete email/username as the semantic Subject identity.

Other users are participants/principals under Object, not extra Subjects.

## 3.5 Operation

Fields:
- `business`: snake_case business verb
- `crud`: EXACTLY Create | Read | Update | Delete

Examples:
- login => `Create(Session)`
- logout => `Delete(Session)`
- approve order => `Update(Order.status)`
- grant role => `Create(RoleBinding)`

## 3.6 Object

Object is the semantic target/created stateful business instance.
It is NOT an HTTP parameter.

Allowed `kind`:
- entity
- state
- relation

Required fields:
- kind
- id
- type
- name
- entity
- role
- attribute
- state_field
- binding
- participants
- constraints

Binding:
- `source`: request | response | subject | semantic | implicit
- `field`
- `resource`

Participants can be:

principal:
- id
- type
- role
- relative_role
- binding

entity:
- id
- type
- role
- binding

Allowed principal relative roles:
- SELF
- SUPERIOR
- SUBORDINATE
- PEER
- UNRELATED

Object constraints:
- same
- distinct

Example:
recipient user cannot be the current actor:
```yaml
constraints:
  - kind: distinct
    left: recipient
    right: actor
```

## 3.7 Typed terms

Fact arguments use typed terms.

Subject:
```yaml
{kind: subject, id: actor, type: User, relative_role: SELF}
```

Principal:
```yaml
{kind: principal, id: recipient, type: User, role: recipient, relative_role: PEER}
```

Entity:
```yaml
{kind: entity, id: message, type: Message, role: created}
```

Reference:
```yaml
kind: reference
type: MessageID
target:
  kind: entity
  id: message
  type: Message
  role: target
```

Every entity/principal referenced in a fact MUST be declared as:
- Subject,
- Object,
- or Object participant.

Do not introduce undeclared variables inside facts.

## 3.8 Closed fact language

Use ONLY:

1. `Exists(O)`
2. `Know(S, Ref(O))`
3. `State(O, field, value)`
4. `Relation(O1, O2, relation)`
5. `Can(S, CRUD, O)`
6. `Authenticated(S[, context])`

No new predicates.

### Exists

Only Entity can occupy Exists target position.

Do NOT write:
`Exists(target_user:User[PEER])`

If user-account existence is needed, create a separate Entity participant:
`target_account:Account`
and connect principal/account with Relation if necessary.

### Know

Second argument must be a Reference term.

Use Know for a stable object reference actually known/required by the Subject.

### State

Exactly:
`State(entity, field, value)`

Never collapse different fields into generic `Updated/Old`.

### Relation

Exactly:
`Relation(term1, term2, relation_name)`

Must refer to concrete declared instances.

### Can

Exactly:
`Can(subject/principal, CRUD, entity)`

CRUD must be:
Create | Read | Update | Delete

### Authenticated

Use:
`Authenticated(subject)`
or
`Authenticated(subject, context)`

## 3.9 Req

`requirements` are facts that MUST already hold for the action to succeed and produce the intended effect.

Requirement `type` is one of:
- existence
- knowledge
- state
- relation
- authorization
- authentication

Typical rules:

- Stable object-ID input:
  usually => `Know(actor, ObjectID(target))`
- If runtime evidence shows nonexistent IDs produce 404/410 and the request carries a reference-capable object identifier:
  also include `Exists(target)`
- Login/session requirement:
  `Authenticated(actor, Session)`
- Required object state:
  `State(target, status, pending)`
- Required membership:
  `Relation(actor, project, Member)`
- Required permission:
  `Can(actor, Update, target)`

Inputs that are NEW CONTENT for this action are NOT pre-existing object references.

Example:
`new_name`, `message_content`, `description`

These belong to the Object/update payload and should be marked in `io_accounting` as `object_attribute`, not invented as `Know(...)` requirements.

## 3.10 Eff

`effects.gen`
= facts made true by the Action.

`effects.kill`
= facts made false / invalid / removed by the Action.

Allowed effect `basis`:
- io_reference
- action_semantics
- auth_transition
- implicit_context
- state_transition
- relation_transition
- unspecified

For human GT, avoid `unspecified` unless truly necessary.

Rules:

### Create
Usually GEN at least one:
- `Exists(created_object)`
- Relation(...)
- State(...)

If response produces a stable reference:
GEN `Know(actor, ObjectID(created_object))`
with basis `io_reference`.

### Read
Pengent keeps only GEN `Know(...)` effects for Read.

Do NOT put observed Exists/State/Relation/Can/Authenticated into Read GEN.
If merely observed, account for it as `observed_only`.

### Update
Normally:
- KILL old `State(...)` / `Relation(...)`
- GEN new `State(...)` / `Relation(...)`

### Delete
Normally:
- KILL `Exists(target)`
or remove the relevant Relation/State.

### Login
Typically:
GEN `Authenticated(actor, Session)`

### Logout
Typically:
KILL `Authenticated(actor, Session)`

## 3.11 `io_accounting`

Every relevant `flow:true` / semantic IO field used by the bound method(s) must be accounted for.

Input disposition:
- `req`
- `object_attribute`

Output disposition:
- `gen`
- `observed_only`

If disposition = `req`
- `facts` must point to fact(s) present in `requirements`.

If disposition = `gen`
- `facts` must point to fact(s) present in `effects.gen`.

If no semantic fact is appropriate:
- input => `object_attribute`
- output => `observed_only`
- explain in `ignored_reason`.

Do NOT silently omit a relevant flow field.

## 3.12 L1 bindings

Each binding:
- exact `l1_key`
- allowed `methods`
- optional selector

Example:
```yaml
l1_bindings:
  - l1_key: "https://app.test/api/message"
    methods: ["POST"]
    selector:
      field: "action"
      values: ["send"]
```

Do NOT bind the same Action across different permission contexts when the Subject differs.
For example Admin action and User action must be separate.

---

# 4. Human-GT extensions

These fields are OUR additions and must not replace Pengent fields.

Store them under `gt`.

## 4.1 Visibility

`gt.visibility.minimum`:

### black_box
Can be identified using only externally exposed behavior and the access explicitly supplied to the benchmark tester.

Still BLACK-BOX:
- logging in with a supplied account;
- navigating role-specific UI with supplied credentials;
- directory/endpoint guessing;
- inspecting HTML/JS/network traffic;
- sending arbitrary Web requests.

### grey_box
Needs additional internal artifacts not available in the black-box profile, e.g.:
- server logs;
- database contents/schema;
- deployment metadata;
- internal route inventory;
- internal configuration not exposed externally.

### white_box
Needs:
- source code;
- implementation-level internals.

IMPORTANT:
visibility is the MINIMUM access needed to identify/understand the item.
It is NOT the evidence source the human annotator happened to use.

You may use source code to CONFIRM a black-box-visible endpoint.

## 4.2 Black-box reachability

`gt.black_box_reachable=true`

means:
once the item is known, it can be exercised end-to-end against the deployed benchmark using ONLY the benchmark's black-box interface/profile, after satisfying stated authentication/state/workflow preconditions.

Visibility and reachability are independent.

Example:
- hidden route only visible from source
- but direct request works

=> visibility = white_box
=> black_box_reachable = true

## 4.3 Evidence

Record evidence for every nontrivial GT claim.

Allowed evidence types:
- runtime
- source
- config
- db
- log
- documentation

Each evidence row:
- type
- ref
- supports

Prefer file:line / request ID / concrete runtime observation.

---

# 5. Required annotation workflow

For each environment:

1. Freeze exact deployment and source revision.
2. Fill `environment.yaml`.
3. Enumerate complete deployed L1 from source/internal evidence.
4. Validate L1 against runtime where possible.
5. Fill exact method-specific `io_variants`.
6. Fill L1 semantic IO decisions.
7. Confirm every `api + io_variants` L1 candidate has L2 coverage.
8. Build Action-L2 nodes using Subject / Operation / Object / Req / Eff.
9. Complete `io_accounting`.
10. Add human GT visibility/reachability/evidence.
11. Run `validate_gt.py`.
12. Run `export_to_pengent.py`.
13. If a real case does not fit, record it in `annotation_issues.yaml`. DO NOT modify the schema yourself.

---

# 6. Completion criteria for one environment

An environment is NOT complete until:

- all in-scope deployed routes/interactions have L1 records;
- all relevant methods are represented;
- query params and method-specific IO contracts are represented;
- L1 semantic input/output decisions are complete;
- identity-scoped runtime status evidence is recorded where testable;
- all L2-candidate API nodes are covered by at least one Action;
- every L2 Action has valid Subject/Operation/Object;
- Req/Eff use only the closed typed fact language;
- every fact variable is declared;
- relevant IO fields are accounted for;
- visibility/reachability are labeled separately;
- evidence is sufficient for another annotator/reviewer to verify the claim;
- validator passes.

Do not optimize for annotation speed by merging different business Actions or skipping uncertain fields.
If uncertain, record the ambiguity and evidence; do not invent semantics.
