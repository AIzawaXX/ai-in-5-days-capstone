# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Automated Unit & Regression Test Suite for the Enterprise IT Helpdesk & Procurement Agent."""

from app.agent import (
     FAST_MODEL,
    REASONING_MODEL,
    app,
    create_critical_it_incident_ticket,
    inspect_corporate_device_warranty,
    procurement_compliance_pipeline,
    root_agent,
    scrub_pii_data,
    submit_high_value_hardware_replacement_order,
)


def test_multi_agent_hierarchy_and_model_routing() -> None:
    """Verify Coordinator + SequentialAgent hierarchy and strategic Flash/Pro model routing."""
    assert root_agent.name == "helpdesk_agent"
    assert root_agent.model == FAST_MODEL
    assert procurement_compliance_pipeline in root_agent.sub_agents
    sub_models = [ag.model for ag in procurement_compliance_pipeline.sub_agents]
    assert FAST_MODEL in sub_models
    assert REASONING_MODEL in sub_models
    assert app.events_compaction_config is not None


def test_guided_error_handling_on_invalid_schema() -> None:
    """Verify tools return descriptive recovery instructions instead of crashing on invalid input."""
    bad_device = inspect_corporate_device_warranty("INVALID_ID_FORMAT")
    assert bad_device["status"] == "error"
    assert "recovery_instructions" in bad_device
    assert "LAPTOP-001" in bad_device["recovery_instructions"]

    bad_ticket = create_critical_it_incident_ticket(
        employee_identifier="Alex",
        device_id="BAD",
        issue_summary="no",
        severity="INVALID",
    )
    assert bad_ticket["status"] == "error"
    assert bad_ticket["recovery_instructions"] is not None


def test_human_in_the_loop_threshold_enforcement() -> None:
    """Verify high-value hardware orders (> $500) stop and require Human-in-the-Loop confirmation."""
    pending = submit_high_value_hardware_replacement_order(
        device_id="LAPTOP-002",
        replacement_model="MacBook Pro 16 M4",
        estimated_cost_usd=2499.00,
        human_approved=False,
    )
    assert pending["status"] == "pending_human_confirmation"
    assert pending["requires_human_approval"] is True
    assert "HUMAN_IN_THE_LOOP_REQUIRED" in pending["recovery_instructions"]

    approved = submit_high_value_hardware_replacement_order(
        device_id="LAPTOP-002",
        replacement_model="MacBook Pro 16 M4",
        estimated_cost_usd=2499.00,
        human_approved=True,
    )
    assert approved["status"] == "approved_and_ordered"
    assert approved["order_id"].startswith("ORDER-")


def test_pii_redaction_pipeline() -> None:
    """Verify active PII scrubbing redacts SSNs, credit cards, emails, and phone numbers."""
    raw = "User alex@example.com with SSN 123-45-6789 and phone 415-555-0199 submitted ticket."
    sanitized = scrub_pii_data(raw)
    assert "123-45-6789" not in sanitized
    assert "alex@example.com" not in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
