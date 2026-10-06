# Per-environment review checklist

Before submitting an annotated environment, check ALL items.

## Environment
- [ ] exact application version/commit recorded
- [ ] deployment profile recorded
- [ ] in-scope/out-of-scope components recorded
- [ ] black-box profile/accounts recorded
- [ ] reset/initial state recorded

## L1 completeness
- [ ] every deployed in-scope route has one normalized L1 node
- [ ] query strings do not create duplicate L1 nodes
- [ ] all supported methods are present
- [ ] statuses/content types are evidenced
- [ ] query parameter names are in params
- [ ] each API candidate has non-empty io_variants
- [ ] inputs/outputs match flow=true business-data fields
- [ ] operation_semantic is filled
- [ ] every relevant IO field has semantic decision
- [ ] semantic_inputs/outputs equal mergeable=true resources
- [ ] reference_capable only used for stable identifiers/locators
- [ ] reference_fields point to real fields
- [ ] identity_statuses are identity-scoped
- [ ] L1 edges are real navigation/request transitions
- [ ] human GT visibility/reachability/evidence are filled

## L2 completeness
- [ ] every api + io_variants L1 candidate has at least one L2 binding
- [ ] no CRUD family is improperly merged into one Action
- [ ] different Subjects/permission contexts are separate Actions
- [ ] action_key is stable snake_case
- [ ] Subject is semantic, not a concrete account/email
- [ ] Object is a business object/state/relation, not an HTTP parameter
- [ ] every fact variable is declared in Subject/Object/participants
- [ ] only six allowed predicates are used
- [ ] Exists target is an Entity, never a principal
- [ ] Know second argument is a Reference
- [ ] State has entity, field, value
- [ ] Req contains only true preconditions
- [ ] new content/update values are object_attribute, not fake Know requirements
- [ ] Create/Delete/Update have appropriate semantic effects
- [ ] Read GEN contains only Know effects
- [ ] effect basis is valid and evidenced
- [ ] all relevant flow fields appear in io_accounting
- [ ] req/gen io_accounting facts match accepted Req/GEN facts
- [ ] l1_bindings use exact L1 keys/methods
- [ ] selectors are used when one endpoint encodes multiple actions
- [ ] human GT visibility/reachability/evidence are filled
- [ ] no manual semantic edges were invented

## Submission
- [ ] validate_gt.py passes
- [ ] export_to_pengent.py succeeds
- [ ] unresolved cases are in annotation_issues.yaml
