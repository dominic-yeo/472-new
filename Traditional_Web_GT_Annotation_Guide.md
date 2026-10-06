# Traditional Web Ground-Truth Annotation Guide

## 1. Scope

This project uses two separate annotation schemas:

1. Traditional Web applications — use the Pengent-compatible Web GT schema.
2. Agentic / AI systems — use a separate schema guided by Mingfei.

For now, work only on the Traditional Web side. Do not mix agent/tool/MCP-specific fields into the Web schema.

The Web schema is fixed for this phase. Do not add, remove, or rename fields yourself. If a real case cannot be represented, record it in `annotation_issues.yaml` with supporting evidence and raise it for discussion.

---

## 2. Goal

The goal is to build human-annotated ground truth that can be used directly in later Pengent experiments.

The human GT may contain more evidence and metadata than Pengent, but it must not contain less than what Pengent needs for:

- L1: InteractionGraph
- L2: Action-L2 v3

Use source code and internal evidence to construct the reference GT, and verify against the deployed application whenever possible.

---

## 3. Applications to Complete First

Complete the following four Traditional Web applications before moving on to additional environments.

### 3.1 VoceChat

Backend/server:
https://github.com/Privoce/vocechat-server-rust

Web frontend:
https://github.com/Privoce/vocechat-web

Treat the server and Web frontend together as one deployed Web application when reconstructing the GT.

### 3.2 MediaCMS

https://github.com/mediacms-io/mediacms

### 3.3 WriteFreely

https://github.com/writefreely/writefreely

### 3.4 Uptrace

https://github.com/uptrace/uptrace

---

## 4. Required Files for Each Environment

For each application, submit:

- `environment.yaml`
- `l1_gt.yaml`
- `l2_gt.yaml`
- `annotation_issues.yaml`

Use the provided Pengent-compatible Web GT templates directly.

---

## 5. L1 Annotation

L1 represents the deployed Web interaction graph.

For each in-scope interaction, annotate the complete Pengent-compatible L1 record, including:

- normalized route / endpoint identity
- kind
- HTTP methods
- observed statuses and content types
- query parameters
- method-specific request / response IO contracts
- semantic inputs / outputs
- semantic IO decisions
- runtime samples and identity-specific observations
- sources / referrers / JS sources where applicable
- L1 transition edges
- GT visibility
- black-box reachability
- evidence

Important rules:

- Do not create duplicate L1 nodes for different concrete IDs or query values.
- Keep different methods on the same normalized route in the same L1 node, with method-specific `io_variants`.
- For API nodes that participate in L2, `io_variants` must be complete.
- `reference_capable=true` should only be used for stable identifiers or locators that can identify an object across interactions.
- Do not treat display-only values, summaries, counts, or ordinary content as object references.
- L1 edges represent actual navigation/request transitions, not semantic relationships inferred from shared objects.

---

## 6. L2 Annotation

L2 follows Pengent Action-L2 v3:

`A = <Subject, Operation, Object, Req, Eff>`

Every in-scope L1 API node with a non-empty IO contract should have corresponding L2 coverage unless an exemption is explicitly approved.

Important rules:

- One L2 Action must represent one semantically distinct business action.
- Do not merge unrelated CRUD actions into one L2 record.
- Different Subjects or permission contexts should be represented as different Actions.
- Use the closed Pengent fact language only:
  - `Exists`
  - `Know`
  - `State`
  - `Relation`
  - `Can`
  - `Authenticated`
- Requirements must describe facts that hold before the Action succeeds.
- Effects must describe facts generated or killed by the Action.
- For Update, represent meaningful state transitions with KILL old state + GEN new state where applicable.
- For Delete, normally KILL the target `Exists(...)` or the relevant relation/state.
- For Read, generated semantic effects should be `Know(...)`.
- Account for relevant semantic IO fields through `io_accounting`.
- Do not manually create Pengent L2 semantic dependency edges. Pengent will derive them from Req/Eff.

If one endpoint supports multiple distinct actions through a discriminator such as `action`, `type`, or `op`, use separate L2 Actions and bind them using the selector field.

---

## 7. Visibility vs. Reachability

These are separate annotations.

### Black-box

The item can be identified using only externally exposed behavior and the access explicitly provided to the tester.

Still considered black-box:

- logging in with a provided account
- navigating role-specific UI
- inspecting HTML / JavaScript / network traffic
- endpoint or directory guessing
- sending arbitrary Web requests

### Grey-box

The item requires additional internal information that is not part of the black-box profile, such as:

- server logs
- database contents or schema
- internal deployment metadata
- internal endpoint inventory
- non-public configuration information

### White-box

The item requires source code or equivalent implementation-level internals.

Important: visibility describes the minimum information needed to identify or understand the item. It is not the same as the evidence source used by the annotator.

You may use source code to confirm an endpoint that is still black-box observable.

### Black-box reachability

`black_box_reachable=true` means that once the interaction or Action is known, it can be exercised end-to-end against the deployed target using only the benchmark's black-box interface/profile after satisfying stated authentication/state/workflow preconditions.

Visibility and reachability must be annotated independently.

---

## 8. Evidence

Use source code and internal/runtime evidence to verify the GT.

Allowed evidence types include:

- runtime
- source
- config
- database
- logs
- documentation

For every nontrivial claim, record evidence that another reviewer can check.

Prefer concrete references such as:

- source file and line
- request/response observation
- runtime trace
- database observation
- configuration entry

Do not infer semantics without evidence.

---

## 9. Annotation Workflow

For each application:

1. Freeze the exact application version / commit and deployment configuration.
2. Fill `environment.yaml`.
3. Enumerate the complete deployed L1 surface using source/internal evidence.
4. Verify L1 interactions against runtime behavior where possible.
5. Complete method-specific `io_variants`.
6. Complete semantic IO decisions.
7. Build L2 Actions from the L1 contracts.
8. Check that every L2-candidate L1 API node has L2 coverage.
9. Add visibility, reachability, and evidence.
10. Record unresolved cases in `annotation_issues.yaml`.
11. Run `validate_gt.py`.
12. Run `export_to_pengent.py`.
13. Submit the four files only after the validator passes.

Do not change the schema to make a difficult case easier to annotate.

---

## 10. Completion Standard

An environment is complete only when:

- all deployed in-scope L1 interactions are represented
- methods and IO contracts are complete
- semantic input/output decisions are complete
- runtime evidence is recorded where testable
- all L2-candidate L1 API nodes have L2 coverage
- L2 Actions use the correct Subject / Operation / Object / Req / Eff representation
- all relevant semantic IO fields are accounted for
- visibility and black-box reachability are separately labeled
- evidence is sufficient to verify the annotation
- `validate_gt.py` passes
- `export_to_pengent.py` succeeds

If uncertain, record the ambiguity and supporting evidence. Do not invent a semantic interpretation.

---

## 11. Current Task

Complete the full L1 + L2 GT annotation for:

1. VoceChat
2. MediaCMS
3. WriteFreely
4. Uptrace

Finish these four before moving on to additional Traditional Web environments.
