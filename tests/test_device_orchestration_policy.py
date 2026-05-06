from guardrail_fabric.device_orchestration_policy import evaluate_orchestration_action


def test_low_risk_appliance_action_allowed():
    decision = evaluate_orchestration_action(
        {
            "subject_node_id": "node:living-room-fan-01",
            "action_type": "set_fan_speed",
            "capability_class": "low_risk_actuation",
            "adapter_health": "healthy",
            "approval_mode": "notify",
            "event_id": "event:sensor:living-room-temp-high",
            "routine_id": "routine:cool-living-room-when-hot",
        }
    )

    assert decision["outcome"] == "allowed"
    assert decision["subject_node_id"] == "node:living-room-fan-01"
    assert decision["routine_id"] == "routine:cool-living-room-when-hot"


def test_high_risk_security_action_requires_approval_when_mode_is_explicit():
    decision = evaluate_orchestration_action(
        {
            "subject_node_id": "node:security-system-01",
            "action_type": "arm_alarm",
            "capability_class": "high_risk_actuation",
            "adapter_health": "healthy",
            "approval_mode": "explicit_user_approval",
            "event_id": "event:agent:propose-arm-security",
        }
    )

    assert decision["outcome"] == "requires_approval"
    assert any("High-risk" in reason for reason in decision["reasons"])


def test_high_risk_security_action_denied_without_approval_mode():
    decision = evaluate_orchestration_action(
        {
            "subject_node_id": "node:security-system-01",
            "action_type": "disarm_alarm",
            "capability_class": "high_risk_actuation",
            "adapter_health": "healthy",
            "approval_mode": "none",
            "event_id": "event:agent:unsafe-disarm",
        }
    )

    assert decision["outcome"] == "denied"
    assert any("lacked" in reason for reason in decision["reasons"])


def test_raw_camera_export_denied_by_default():
    decision = evaluate_orchestration_action(
        {
            "subject_node_id": "node:front-door-camera-01",
            "action_type": "export_raw_video",
            "capability_class": "high_risk_actuation",
            "adapter_health": "healthy",
            "approval_mode": "explicit_user_approval",
            "event_id": "event:agent:request-raw-camera-export",
        }
    )

    assert decision["outcome"] == "denied"
    assert any("Raw camera" in reason for reason in decision["reasons"])


def test_degraded_adapter_yields_degraded_decision():
    decision = evaluate_orchestration_action(
        {
            "subject_node_id": "node:front-door-camera-01",
            "action_type": "observe",
            "capability_class": "observe",
            "adapter_health": "degraded",
            "approval_mode": "none",
            "event_id": "event:adapter:google-home-degraded",
        }
    )

    assert decision["outcome"] == "degraded"
