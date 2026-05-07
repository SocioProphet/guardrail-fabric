from guardrail_fabric.event_capability_policy import (
    annotate_event_capability_record,
    context_from_event_capability_record,
    evaluate_event_capability_record,
)


def base_record(effect_class="low_risk_actuation", action="set_fan_speed", approval_mode="notify"):
    return {
        "record_id": "record:cool-room-with-fan",
        "event": {
            "event_id": "event:sensor:living-room-temp-high",
            "target_node_id": "node:living-room-fan-01",
            "payload": {"requested_action": action},
        },
        "capability": {
            "capability_id": "capability:cool-room-with-fan",
            "effect_class": effect_class,
            "approval_mode": approval_mode,
        },
        "reaction": {
            "reaction_id": "reaction:cool-room-with-fan",
            "receipt_refs": ["receipt:event:living-room-temp-high"],
        },
        "evidence_refs": [],
    }


def test_context_from_event_capability_record():
    context = context_from_event_capability_record(base_record())

    assert context["event_id"] == "event:sensor:living-room-temp-high"
    assert context["subject_node_id"] == "node:living-room-fan-01"
    assert context["action_type"] == "set_fan_speed"
    assert context["capability_class"] == "low_risk_actuation"


def test_low_risk_record_generates_allowed_outcome():
    decision = evaluate_event_capability_record(base_record())

    assert decision["outcome"] == "allowed"


def test_high_risk_record_generates_requires_approval():
    record = base_record(effect_class="high_risk_actuation", action="arm_alarm", approval_mode="explicit_user_approval")
    decision = evaluate_event_capability_record(record)

    assert decision["outcome"] == "requires_approval"


def test_camera_media_release_generates_denied_outcome():
    record = base_record(effect_class="high_risk_actuation", action="export_raw_video", approval_mode="explicit_user_approval")
    decision = evaluate_event_capability_record(record)

    assert decision["outcome"] == "denied"


def test_annotation_updates_reaction_and_capability():
    annotated = annotate_event_capability_record(base_record(effect_class="high_risk_actuation", action="arm_alarm", approval_mode="explicit_user_approval"))

    assert annotated["policy_decision"]["outcome"] == "requires_approval"
    assert annotated["reaction"]["policy_outcome"] == "requires_approval"
    assert annotated["reaction"]["dead_letter_on_failure"] is True
    assert annotated["capability"]["required_policy_outcome"] == "requires_approval"
    assert "receipt:event:living-room-temp-high" in annotated["evidence_refs"]
