# -*- coding: utf-8 -*-
"""Builders for the agentic attack-surface GT.

Companion to the root Agentic_attack_surface_schema.yaml. Each builder returns a
dict with every schema field, filling safe defaults so the data module
(agentic_data.py) stays readable. build_agentic.py validates referential
integrity + lineage + enums and emits agentic_gt.yaml.

Reusable across apps: copy this file, keep the builders, replace agentic_data.py.
"""

# ---- shared defaults -------------------------------------------------------

EVIDENCE_DEFAULT = "source_confirmed"   # static source pass; runtime (E) upgrades to "observed"
VIS_DEFAULT = "white_box_required"


def reach(status="black_box_reachable", notes=""):
    return {"status": status, "notes": notes}


def writer(principal, l1_id=None):
    return {"principal": principal, "l1_id": l1_id}


# ---- record builders -------------------------------------------------------

def agent(id, name, component, agent_kind, purpose, *,
          invocation_surfaces=None, model_config=None, instruction_sources=None,
          tool_binding_ids=None, context_source_ids=None, memory_ids=None,
          output_sink_ids=None, control_ids=None, resource_limits=None,
          authority_context=None, related_l2_ids=None,
          visibility=VIS_DEFAULT, reachability=None, source_ref="",
          evidence_status=EVIDENCE_DEFAULT, notes=""):
    return {
        "id": id, "name": name, "component": component, "agent_kind": agent_kind,
        "purpose": purpose,
        "invocation_surfaces": invocation_surfaces or [],
        "model_config": model_config or {},
        "instruction_sources": instruction_sources or [],
        "tool_binding_ids": tool_binding_ids or [],
        "context_source_ids": context_source_ids or [],
        "memory_ids": memory_ids or [],
        "output_sink_ids": output_sink_ids or [],
        "control_ids": control_ids or [],
        "resource_limits": resource_limits,
        "authority_context": authority_context or {},
        "related_l2_ids": related_l2_ids or [],
        "visibility": visibility, "reachability": reachability or reach(),
        "source_ref": source_ref, "evidence_status": evidence_status, "notes": notes,
    }


def tool(id, agent_id, tool_name, tool_source, effect_class, *,
         l1_ids=None, server_or_provider=None, schema_ref=None,
         description_source=None, capabilities=None, execution_identity=None,
         argument_handling=None, output_ids=None, execution_environment=None,
         approval_required="unknown", control_ids=None, related_l2_ids=None,
         visibility=VIS_DEFAULT, reachability=None, evidence_status=EVIDENCE_DEFAULT,
         source_ref="", notes=""):
    return {
        "id": id, "agent_id": agent_id, "l1_ids": l1_ids or [],
        "tool_name": tool_name, "tool_source": tool_source,
        "server_or_provider": server_or_provider, "schema_ref": schema_ref,
        "description_source": description_source,
        "capabilities": capabilities or [],
        "execution_identity": execution_identity or {},
        "argument_handling": argument_handling or {},
        "output_ids": output_ids or [],
        "execution_environment": execution_environment,
        "effect_class": effect_class, "approval_required": approval_required,
        "control_ids": control_ids or [], "related_l2_ids": related_l2_ids or [],
        "visibility": visibility, "reachability": reachability or reach(),
        "evidence_status": evidence_status, "source_ref": source_ref, "notes": notes,
    }


def ctx(id, source_kind, trust_class, *, source_ref="", writers=None,
        destination_agent_ids=None, destination_channel="unknown", provenance="",
        transformation="", persistence_scope="unknown", related_l2_ids=None,
        visibility=VIS_DEFAULT, reachability=None, evidence_status=EVIDENCE_DEFAULT,
        notes=""):
    return {
        "id": id, "source_kind": source_kind, "source_ref": source_ref,
        "writers": writers or [], "destination_agent_ids": destination_agent_ids or [],
        "destination_channel": destination_channel, "provenance": provenance,
        "trust_class": trust_class, "transformation": transformation,
        "persistence_scope": persistence_scope, "related_l2_ids": related_l2_ids or [],
        "visibility": visibility, "reachability": reachability or reach(),
        "evidence_status": evidence_status, "notes": notes,
    }


def mem(id, store_kind, owner_component, scope, *, readers=None, writers=None,
        isolation_enforcement="", write_provenance="", read_path="",
        retention_and_deletion="", related_l2_ids=None,
        visibility=VIS_DEFAULT, reachability=None, evidence_status=EVIDENCE_DEFAULT,
        source_ref="", notes=""):
    return {
        "id": id, "store_kind": store_kind, "owner_component": owner_component,
        "readers": readers or [], "writers": writers or [], "scope": scope,
        "isolation_enforcement": isolation_enforcement,
        "write_provenance": write_provenance, "read_path": read_path,
        "retention_and_deletion": retention_and_deletion,
        "related_l2_ids": related_l2_ids or [], "evidence_status": evidence_status,
        "visibility": visibility, "reachability": reachability or reach(),
        "source_ref": source_ref, "notes": notes,
    }


def sink(id, sink_kind, *, producer_ids=None, audience="", delivery="",
         transformation="", render_side_effects=None, becomes_context_source_ids=None,
         related_l1_ids=None, related_l2_ids=None, visibility=VIS_DEFAULT,
         reachability=None, evidence_status=EVIDENCE_DEFAULT, source_ref="", notes=""):
    return {
        "id": id, "sink_kind": sink_kind, "producer_ids": producer_ids or [],
        "audience": audience, "delivery": delivery, "transformation": transformation,
        "render_side_effects": render_side_effects,
        "becomes_context_source_ids": becomes_context_source_ids or [],
        "related_l1_ids": related_l1_ids or [], "related_l2_ids": related_l2_ids or [],
        "visibility": visibility, "reachability": reachability or reach(),
        "evidence_status": evidence_status, "source_ref": source_ref, "notes": notes,
    }


def edge(id, decision_maker, *, source=None, destination=None, condition="",
         input_source_ids=None, argument_sources="", payload="", output_ids=None,
         control_ids=None, validation_or_approval="", execution_mode="synchronous",
         loop_bound=None, failure_behavior="unknown", related_l1_ids=None,
         related_l2_steps=None, visibility=VIS_DEFAULT, reachability=None,
         evidence_status=EVIDENCE_DEFAULT, source_ref="", notes=""):
    return {
        "id": id,
        "source": source or {"agent_id": None, "step": None, "external_trigger": None},
        "destination": destination or {},
        "decision_maker": decision_maker, "condition": condition,
        "input_source_ids": input_source_ids or [], "argument_sources": argument_sources,
        "payload": payload, "output_ids": output_ids or [],
        "control_ids": control_ids or [], "validation_or_approval": validation_or_approval,
        "execution_mode": execution_mode, "loop_bound": loop_bound,
        "failure_behavior": failure_behavior, "related_l1_ids": related_l1_ids or [],
        "related_l2_steps": related_l2_steps or [], "visibility": visibility,
        "reachability": reachability or reach(), "evidence_status": evidence_status,
        "source_ref": source_ref, "notes": notes,
    }


def ctl(id, control_kind, applies_at, enforcement_mode, implementation, *,
        failure_mode="unknown", applies_to_agent_ids=None,
        applies_to_tool_binding_ids=None, related_l1_ids=None, related_l2_ids=None,
        evidence_status=EVIDENCE_DEFAULT, source_ref="", visibility=VIS_DEFAULT,
        reachability=None, notes=""):
    return {
        "id": id, "control_kind": control_kind, "applies_at": applies_at,
        "enforcement_mode": enforcement_mode, "implementation": implementation,
        "failure_mode": failure_mode, "applies_to_agent_ids": applies_to_agent_ids or [],
        "applies_to_tool_binding_ids": applies_to_tool_binding_ids or [],
        "related_l1_ids": related_l1_ids or [], "related_l2_ids": related_l2_ids or [],
        "evidence_status": evidence_status, "source_ref": source_ref,
        "visibility": visibility, "reachability": reachability or reach(), "notes": notes,
    }
