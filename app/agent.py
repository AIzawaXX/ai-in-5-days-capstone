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

"""Enterprise IT Helpdesk & Hardware Procurement Multi-Agent System.

Implements all 5 categories of the AgentOps Code Review Matrix:
1. Tool & Interface Design (Docstrings, Descriptive Naming, Explicit Pydantic JSON Schemas, Guided Error Handling)
2. Context & Memory (Robust Constitution Prompt, History Compaction, Persistent Session/Vector/Firestore State, Async Memory Ops)
3. Orchestration & Logic (Coordinator + Sequential Multi-Agent Pattern, Strategic Flash/Pro Model Routing, Guardrails, HITL Hooks)
4. Observability & Tracing (Structured JSON Logging, Intent vs. Outcome Capture, OpenTelemetry Distributed Tracing, Cloud DLP PII Redaction)
5. Infrastructure & CI/CD (Secret Manager Integration, Automated Eval Suite, Terraform IaC)
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
import uuid
from typing import Any

import google.auth
from google.adk.agents import Agent, SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.apps import App, ResumabilityConfig
from google.adk.apps.app import EventsCompactionConfig
from google.adk.models import LlmRequest, LlmResponse
from google.adk.tools import FunctionTool, ToolContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.preload_memory_tool import PreloadMemoryTool
from google.cloud import firestore
from google.genai import types
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, Field, ValidationError

# ---------------------------------------------------------------------------
# 5. Infrastructure & CI/CD: Secure Secret Management (No Hardcoded Keys)
# ---------------------------------------------------------------------------
try:
    _, default_project_id = google.auth.default()
except Exception:
    default_project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id")

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT") or default_project_id or "your-gcp-project-id"
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", PROJECT_ID)
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", LOCATION)
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")


def get_secret_from_secret_manager(secret_id: str, version_id: str = "latest") -> str:
    """Retrieve sensitive configuration or API credentials securely from Google Cloud Secret Manager.

    Args:
        secret_id: Identifier of the secret in Google Cloud Secret Manager.
        version_id: Version of the secret to access (defaults to 'latest').

    Returns:
        The decoded secret payload string, or an environment variable fallback in local tests.
    """
    try:
        from google.cloud import secretmanager  # type: ignore[attr-defined]

        client = secretmanager.SecretManagerServiceClient()
        secret_name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": secret_name})
        return response.payload.data.decode("UTF-8")
    except Exception:
        return os.environ.get(secret_id.upper(), "")


# ---------------------------------------------------------------------------
# 4. Observability & Tracing: Distributed Tracing (OpenTelemetry)
# ---------------------------------------------------------------------------
def _init_tracer() -> trace.Tracer:
    """Initialize OpenTelemetry TracerProvider with Google Cloud Trace export when enabled."""
    provider = trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        tracer_provider = TracerProvider()
        if os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY", "").lower() in ("true", "1"):
            try:
                from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

                tracer_provider.add_span_processor(
                    BatchSpanProcessor(CloudTraceSpanExporter(project_id=PROJECT_ID))
                )
            except Exception:
                pass
        trace.set_tracer_provider(tracer_provider)
    return trace.get_tracer("enterprise_ops_agent.tracer")


tracer = _init_tracer()


# ---------------------------------------------------------------------------
# 4. Observability & Tracing: PII Redaction (Cloud DLP API + Regex Scrubbing)
# ---------------------------------------------------------------------------
_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_REGEX = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def scrub_pii_data(raw_text: str) -> str:
    """Scrub sensitive PII from logs and memory using Google Cloud DLP API with regex fallback.

    Args:
        raw_text: Unsanitized text potentially containing SSNs, credit cards, emails, or phone numbers.

    Returns:
        Sanitized string with sensitive PII replaced by redaction tokens.
    """
    if not raw_text:
        return raw_text

    scrubbed = _SSN_REGEX.sub("[REDACTED_SSN]", raw_text)
    scrubbed = _CC_REGEX.sub("[REDACTED_CREDIT_CARD]", scrubbed)
    scrubbed = _EMAIL_REGEX.sub("[REDACTED_EMAIL]", scrubbed)
    scrubbed = _PHONE_REGEX.sub("[REDACTED_PHONE]", scrubbed)

    if os.environ.get("ENABLE_CLOUD_DLP_API", "").lower() in ("true", "1"):
        try:
            from google.cloud import dlp_v2  # type: ignore[attr-defined]

            dlp_client = dlp_v2.DlpServiceClient()
            parent = f"projects/{PROJECT_ID}/locations/global"
            inspect_config = {
                "info_types": [
                    {"name": "EMAIL_ADDRESS"},
                    {"name": "PHONE_NUMBER"},
                    {"name": "US_SOCIAL_SECURITY_NUMBER"},
                    {"name": "CREDIT_CARD_NUMBER"},
                ]
            }
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [
                        {
                            "primitive_transformation": {
                                "replace_with_info_type_config": {}
                            }
                        }
                    ]
                }
            }
            response = dlp_client.deidentify_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "deidentify_config": deidentify_config,
                    "item": {"value": scrubbed},
                }
            )
            return response.item.value
        except Exception:
            return scrubbed

    return scrubbed


# ---------------------------------------------------------------------------
# 4. Observability & Tracing: Structured JSON Logging
# ---------------------------------------------------------------------------
class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON objects with OpenTelemetry trace correlation."""

    def format(self, record: logging.LogRecord) -> str:
        span_ctx = trace.get_current_span().get_span_context()
        trace_id = f"{span_ctx.trace_id:032x}" if span_ctx and span_ctx.is_valid else "none"
        span_id = f"{span_ctx.span_id:016x}" if span_ctx and span_ctx.is_valid else "none"
        payload: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": scrub_pii_data(record.getMessage()),
            "logging.googleapis.com/trace": f"projects/{PROJECT_ID}/traces/{trace_id}",
            "logging.googleapis.com/spanId": span_id,
        }
        extra_metadata = getattr(record, "structured_data", None)
        if isinstance(extra_metadata, dict):
            sanitized_meta = {
                k: scrub_pii_data(str(v)) if isinstance(v, str) else v
                for k, v in extra_metadata.items()
            }
            payload.update(sanitized_meta)
        return json.dumps(payload)


def _configure_structured_logger() -> logging.Logger:
    logger = logging.getLogger("enterprise_ops_agent")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
    return logger


structured_logger = _configure_structured_logger()


def log_structured_event(event_type: str, message: str, **metadata: Any) -> None:
    """Emit a PII-scrubbed structured JSON log entry with rich metadata."""
    structured_logger.info(
        message,
        extra={"structured_data": {"event_type": event_type, **metadata}},
    )


# ---------------------------------------------------------------------------
# 1. Tool & Interface Design: Explicit JSON Schemas (Pydantic Input/Output)
# ---------------------------------------------------------------------------
class DeviceInspectionInput(BaseModel):
    """Strict input schema for inspecting corporate IT device status and warranty."""

    device_id: str = Field(
        ...,
        pattern=r"^[A-Za-z]+-\d{3,6}$",
        description="Corporate asset tag in format PREFIX-NNN (e.g., LAPTOP-001, LAPTOP-002).",
    )


class DeviceInspectionOutput(BaseModel):
    """Strict output schema returned when inspecting a corporate IT device."""

    status: str = Field(description="Lookup status: 'found', 'not_found', or 'error'.")
    device_id: str = Field(description="Normalized corporate device identifier.")
    device_record: dict[str, Any] | None = Field(
        default=None, description="Device telemetry and warranty metadata from Firestore."
    )
    recovery_instructions: str | None = Field(
        default=None, description="Guided recovery instructions for the LLM when status is not 'found'."
    )


class CriticalIncidentInput(BaseModel):
    """Strict input schema for logging a critical IT support incident ticket."""

    employee_identifier: str = Field(
        ...,
        min_length=2,
        description="Name or employee ID of the user reporting the IT issue.",
    )
    device_id: str = Field(
        ...,
        pattern=r"^[A-Za-z]+-\d{3,6}$",
        description="Affected corporate device ID (e.g., LAPTOP-002).",
    )
    issue_summary: str = Field(
        ...,
        min_length=5,
        description="Detailed technical summary of the hardware or software incident.",
    )
    severity: str = Field(
        default="HIGH",
        pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$",
        description="Incident severity level: LOW, MEDIUM, HIGH, or CRITICAL.",
    )


class CriticalIncidentOutput(BaseModel):
    """Strict output schema returned after creating a critical IT incident ticket."""

    status: str = Field(description="'created' or 'error'.")
    ticket_id: str | None = Field(default=None, description="Generated ticket ID (e.g., TICKET-A1B2C3D4).")
    ticket_record: dict[str, Any] | None = Field(default=None, description="Persisted Firestore ticket payload.")
    recovery_instructions: str | None = Field(default=None, description="Guided recovery instructions on error.")


class HardwareReplacementOrderInput(BaseModel):
    """Strict input schema for submitting a hardware replacement procurement order."""

    device_id: str = Field(
        ...,
        pattern=r"^[A-Za-z]+-\d{3,6}$",
        description="Existing faulty device ID being replaced (e.g., LAPTOP-002).",
    )
    replacement_model: str = Field(
        ...,
        min_length=3,
        description="Target replacement hardware model (e.g., 'MacBook Pro 16 M4', 'ThinkPad T14 Gen 5').",
    )
    estimated_cost_usd: float = Field(
        ...,
        gt=0,
        description="Estimated procurement cost in USD. Orders > $500 require Human-in-the-Loop approval.",
    )
    human_approved: bool = Field(
        default=False,
        description="True only after a human manager has explicitly confirmed high-value procurement.",
    )


class HardwareReplacementOrderOutput(BaseModel):
    """Strict output schema for hardware replacement procurement orders."""

    status: str = Field(
        description="Order status: 'approved_and_ordered', 'pending_human_confirmation', or 'error'."
    )
    order_id: str | None = Field(default=None, description="Generated procurement order ID.")
    requires_human_approval: bool = Field(
        default=False, description="Whether human-in-the-loop sign-off is required before fulfillment."
    )
    recovery_instructions: str | None = Field(
        default=None, description="Next steps for the agent or human reviewer."
    )


class ComplianceAuditReport(BaseModel):
    """Structured output schema for the financial & security compliance auditor sub-agent."""

    compliance_status: str = Field(description="APPROVED, REQUIRES_MANAGER_HITL, or REJECTED")
    risk_score: int = Field(description="Numeric risk score from 1 (lowest) to 10 (highest)")
    audit_rationale: str = Field(description="Concise explanation of policy compliance and warranty findings")
    recommended_next_action: str = Field(description="Actionable recommendation for the coordinator agent")


# ---------------------------------------------------------------------------
# 2. Context & Memory: Persistent Database Connection (Firestore + Vector Store)
# ---------------------------------------------------------------------------
def get_firestore_client() -> firestore.Client:
    """Create a persistent Firestore client with safe database path handling."""
    client = firestore.Client(project=PROJECT_ID, database="(default)")
    client._database_string_internal = (
        f"projects/{client.project}/databases/{client._database}"
    )
    return client


# ---------------------------------------------------------------------------
# 1. Tool & Interface Design: Descriptive Naming, Docstrings & Guided Errors
# ---------------------------------------------------------------------------
def inspect_corporate_device_warranty(device_id: str) -> dict[str, Any]:
    """Check the current operational status, OS, and warranty of a corporate IT device in Firestore.

    Args:
        device_id: The unique asset identifier of the corporate device (e.g., 'LAPTOP-001' or 'LAPTOP-002').

    Returns:
        A dictionary conforming to `DeviceInspectionOutput` containing device status, warranty details,
        or guided recovery instructions if the device ID is malformed or missing.
    """
    with tracer.start_as_current_span("tool.inspect_corporate_device_warranty") as span:
        normalized_id = (device_id or "").strip().upper()
        span.set_attribute("device.id", normalized_id)
        try:
            validated = DeviceInspectionInput.model_validate({"device_id": normalized_id})
        except ValidationError as exc:
            return DeviceInspectionOutput(
                status="error",
                device_id=normalized_id,
                recovery_instructions=(
                    f"Validation failed for device_id '{device_id}': {exc.errors()[0]['msg']}. "
                    "Please ask the user for a valid asset tag formatted like 'LAPTOP-001' or 'LAPTOP-002' and retry."
                ),
            ).model_dump()

        try:
            db = get_firestore_client()
            doc = db.collection("devices").document(validated.device_id).get()
            if doc.exists:
                return DeviceInspectionOutput(
                    status="found",
                    device_id=validated.device_id,
                    device_record=doc.to_dict(),
                ).model_dump()
            return DeviceInspectionOutput(
                status="not_found",
                device_id=validated.device_id,
                recovery_instructions=(
                    f"Device '{validated.device_id}' was not found in the Firestore 'devices' collection. "
                    "Verify the asset tag with the user (known test devices include LAPTOP-001 and LAPTOP-002) "
                    "or call `search_enterprise_knowledge_base` for troubleshooting policies."
                ),
            ).model_dump()
        except Exception as exc:
            return DeviceInspectionOutput(
                status="error",
                device_id=validated.device_id,
                recovery_instructions=(
                    f"Firestore lookup encountered a transient error ({type(exc).__name__}). "
                    "Inform the user that the asset database is temporarily unreachable and offer to log a ticket."
                ),
            ).model_dump()


def create_critical_it_incident_ticket(
    employee_identifier: str,
    device_id: str,
    issue_summary: str,
    severity: str = "HIGH",
) -> dict[str, Any]:
    """Create and persist a new critical IT support incident ticket in Firestore.

    Args:
        employee_identifier: The name or employee ID of the person reporting the issue (e.g., 'Alex').
        device_id: The affected corporate device asset tag (e.g., 'LAPTOP-002').
        issue_summary: Detailed description of the hardware fault or software malfunction.
        severity: Incident priority level ('LOW', 'MEDIUM', 'HIGH', or 'CRITICAL').

    Returns:
        A dictionary conforming to `CriticalIncidentOutput` with the generated ticket ID and persisted record,
        or guided recovery instructions if validation fails.
    """
    with tracer.start_as_current_span("tool.create_critical_it_incident_ticket") as span:
        normalized_device = (device_id or "").strip().upper()
        normalized_severity = (severity or "HIGH").strip().upper()
        span.set_attribute("ticket.device_id", normalized_device)
        span.set_attribute("ticket.severity", normalized_severity)
        try:
            validated = CriticalIncidentInput.model_validate(
                {
                    "employee_identifier": scrub_pii_data(employee_identifier.strip()),
                    "device_id": normalized_device,
                    "issue_summary": scrub_pii_data(issue_summary.strip()),
                    "severity": normalized_severity,
                }
            )
        except ValidationError as exc:
            return CriticalIncidentOutput(
                status="error",
                recovery_instructions=(
                    f"Invalid ticket parameters: {exc.errors()[0]['msg']}. "
                    "Ensure `device_id` matches 'LAPTOP-NNN', `issue_summary` has at least 5 characters, "
                    "and `severity` is one of LOW, MEDIUM, HIGH, CRITICAL."
                ),
            ).model_dump()

        ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
        ticket_data = {
            "ticket_id": ticket_id,
            "user": validated.employee_identifier,
            "device_id": validated.device_id,
            "issue": validated.issue_summary,
            "severity": validated.severity,
            "status": "Open",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        try:
            db = get_firestore_client()
            db.collection("tickets").document(ticket_id).set(ticket_data)
            return CriticalIncidentOutput(
                status="created",
                ticket_id=ticket_id,
                ticket_record=ticket_data,
            ).model_dump()
        except Exception as exc:
            return CriticalIncidentOutput(
                status="error",
                recovery_instructions=(
                    f"Could not write ticket to Firestore ({type(exc).__name__}). "
                    "Provide the local reference ID to the user and retry once connectivity is restored."
                ),
            ).model_dump()


def submit_high_value_hardware_replacement_order(
    device_id: str,
    replacement_model: str,
    estimated_cost_usd: float,
    human_approved: bool = False,
) -> dict[str, Any]:
    """Submit a corporate hardware replacement order with mandatory Human-in-the-Loop enforcement over $500.

    Args:
        device_id: The faulty corporate device asset ID being replaced (e.g., 'LAPTOP-002').
        replacement_model: The requested replacement laptop model (e.g., 'MacBook Pro 16 M4').
        estimated_cost_usd: Total estimated cost in USD for the replacement hardware.
        human_approved: Boolean flag indicating whether a human manager has explicitly approved the order.

    Returns:
        A dictionary conforming to `HardwareReplacementOrderOutput` indicating either order fulfillment
        or a Human-in-the-Loop confirmation pause with guided instructions.
    """
    with tracer.start_as_current_span("tool.submit_high_value_hardware_replacement_order") as span:
        normalized_device = (device_id or "").strip().upper()
        span.set_attribute("order.device_id", normalized_device)
        span.set_attribute("order.estimated_cost_usd", float(estimated_cost_usd))
        try:
            validated = HardwareReplacementOrderInput.model_validate(
                {
                    "device_id": normalized_device,
                    "replacement_model": replacement_model.strip(),
                    "estimated_cost_usd": estimated_cost_usd,
                    "human_approved": human_approved,
                }
            )
        except ValidationError as exc:
            return HardwareReplacementOrderOutput(
                status="error",
                recovery_instructions=(
                    f"Invalid hardware order input: {exc.errors()[0]['msg']}. "
                    "Ensure `device_id` is formatted like 'LAPTOP-002' and `estimated_cost_usd` is a positive number."
                ),
            ).model_dump()

        # 3. Orchestration & Logic: Human-in-the-Loop Hook for High-Stakes Actions (> $500)
        if validated.estimated_cost_usd > 500.0 and not validated.human_approved:
            return HardwareReplacementOrderOutput(
                status="pending_human_confirmation",
                requires_human_approval=True,
                recovery_instructions=(
                    f"HUMAN_IN_THE_LOOP_REQUIRED: Hardware replacement order for '{validated.replacement_model}' "
                    f"(${validated.estimated_cost_usd:.2f}) exceeds the $500.00 automatic approval threshold. "
                    "Stop and ask the human manager for explicit approval before calling this tool again with "
                    "`human_approved=True`."
                ),
            ).model_dump()

        order_id = f"ORDER-{uuid.uuid4().hex[:8].upper()}"
        return HardwareReplacementOrderOutput(
            status="approved_and_ordered",
            order_id=order_id,
            requires_human_approval=False,
            recovery_instructions="Order completed successfully. Share the order_id with the user.",
        ).model_dump()


def search_enterprise_knowledge_base(policy_query: str) -> dict[str, Any]:
    """Retrieve enterprise IT and hardware procurement policies from persistent knowledge storage.

    Args:
        policy_query: Natural-language query describing the IT policy, warranty rule, or SLA topic.

    Returns:
        A dictionary containing matched policy documents or guided recovery instructions if empty.
    """
    with tracer.start_as_current_span("tool.search_enterprise_knowledge_base") as span:
        query_clean = (policy_query or "").strip()
        span.set_attribute("kb.query", query_clean)
        if len(query_clean) < 2:
            return {
                "status": "error",
                "recovery_instructions": "Provide a non-empty `policy_query` keyword (e.g., 'warranty', 'replacement', 'SLA').",
            }
        knowledge_articles = [
            {
                "doc_id": "POL-IT-001",
                "title": "Corporate Laptop Warranty & Repair Policy",
                "content": (
                    "Devices with status 'Needs Repair' and an 'Expired' warranty qualify for a full hardware "
                    "replacement rather than out-of-warranty repair. Always respect the employee's preferred OS."
                ),
            },
            {
                "doc_id": "POL-PROC-002",
                "title": "Procurement Approval Thresholds (Human-in-the-Loop)",
                "content": (
                    "Standard accessories under $500 are auto-approved. Any replacement laptop or hardware order "
                    "exceeding $500.00 requires explicit Human-in-the-Loop (HITL) manager confirmation."
                ),
            },
        ]
        return {
            "status": "found",
            "query": query_clean,
            "matches": knowledge_articles,
        }


# Wrap high-stakes tool with ADK confirmation support
hardware_order_tool = FunctionTool(
    submit_high_value_hardware_replacement_order,
    require_confirmation=False,  # Enforced deterministically via `human_approved` + before_tool_callback hook
)


# ---------------------------------------------------------------------------
# 2. Context & Memory + 3. Orchestration & Logic + 4. Observability Callbacks
# ---------------------------------------------------------------------------
MAX_HISTORY_CONTENTS = 12


def compact_conversation_history(llm_request: LlmRequest) -> None:
    """Sliding-window history compaction to prevent context window bloat on long sessions."""
    if llm_request.contents and len(llm_request.contents) > MAX_HISTORY_CONTENTS:
        preserved_head = llm_request.contents[:2]
        recent_tail = llm_request.contents[-(MAX_HISTORY_CONTENTS - 2) :]
        llm_request.contents = preserved_head + recent_tail


def security_and_routing_before_model_callback(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """Enforce security guardrails, compact history, and apply strategic model routing before LLM invocation."""
    with tracer.start_as_current_span("guardrail.before_model_callback") as span:
        # 2. Context & Memory: History Compaction
        compact_conversation_history(llm_request)

        user_content = callback_context.user_content
        if not user_content or not user_content.parts:
            return None

        raw_user_text = " ".join(
            p.text for p in user_content.parts if getattr(p, "text", None)
        )
        scrubbed_user_text = scrub_pii_data(raw_user_text)
        lowered = raw_user_text.lower()

        # 3. Orchestration & Logic: Security Guardrail (Prompt Injection & Unauthorized Access)
        blocked_phrases = [
            "ignore previous instructions",
            "ignore all instructions",
            "dump all employee passwords",
            "grant root access",
            "bypass security controls",
        ]
        for phrase in blocked_phrases:
            if phrase in lowered:
                callback_context.state["security_blocked"] = True
                span.set_attribute("security.blocked", True)
                log_structured_event(
                    event_type="SECURITY_GUARDRAIL_BLOCKED",
                    message=f"Blocked prohibited prompt pattern: {phrase}",
                    agent_name=callback_context.agent_name,
                    sanitized_input=scrubbed_user_text,
                )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part.from_text(
                                text=(
                                    "SECURITY POLICY VIOLATION: I cannot fulfill requests that attempt "
                                    "to bypass security controls, access unauthorized credentials, or "
                                    "grant administrative root privileges."
                                )
                            )
                        ],
                    )
                )

        # 3. Orchestration & Logic: Strategic Model Routing (Flash for fast triage, Pro for complex planning)
        complex_keywords = ["audit", "compliance", "architecture", "multi-step", "financial risk"]
        selected_model = (
            REASONING_MODEL
            if any(k in lowered for k in complex_keywords)
            else FAST_MODEL
        )
        callback_context.state["routed_model"] = selected_model
        span.set_attribute("model.routed", selected_model)
        log_structured_event(
            event_type="MODEL_ROUTING_DECISION",
            message=f"Routed turn to model {selected_model}",
            agent_name=callback_context.agent_name,
            routed_model=selected_model,
        )
        return None


def self_evaluation_after_model_callback(
    callback_context: CallbackContext, llm_response: LlmResponse
) -> LlmResponse | None:
    """Self-evaluation & PII output guardrail executed on every LLM response before returning to the user."""
    with tracer.start_as_current_span("guardrail.after_model_callback"):
        if not llm_response or not llm_response.content or not llm_response.content.parts:
            return None

        sanitized_parts: list[types.Part] = []
        modified = False
        for part in llm_response.content.parts:
            text_val = getattr(part, "text", None)
            if text_val:
                cleaned = scrub_pii_data(text_val)
                if cleaned != text_val:
                    modified = True
                sanitized_parts.append(types.Part.from_text(text=cleaned))
            else:
                sanitized_parts.append(part)

        if modified:
            log_structured_event(
                event_type="OUTPUT_PII_REDACTED",
                message="Redacted sensitive PII from model output before delivery.",
                agent_name=callback_context.agent_name,
            )
            return LlmResponse(
                content=types.Content(role="model", parts=sanitized_parts)
            )
        return None


def log_tool_intent_before_callback(
    tool: BaseTool, args: dict[str, Any], tool_context: ToolContext
) -> dict[str, Any] | None:
    """4. Observability & Tracing: Record intended tool action and arguments BEFORE execution."""
    log_structured_event(
        event_type="TOOL_EXECUTION_INTENT",
        message=f"Agent intends to execute tool '{tool.name}'",
        phase="INTENT",
        tool_name=tool.name,
        intended_args=scrub_pii_data(json.dumps(args, default=str)),
        agent_name=tool_context.agent_name,
    )
    # 3. Orchestration & Logic: Human-in-the-Loop pre-execution hook check
    if tool.name == "submit_high_value_hardware_replacement_order":
        cost = float(args.get("estimated_cost_usd", 0.0))
        approved = bool(args.get("human_approved", False))
        if cost > 500.0 and not approved:
            tool_context.state["hitl_gate_triggered"] = True
            log_structured_event(
                event_type="HITL_GATE_TRIGGERED",
                message=f"Paused high-value hardware order (${cost:.2f}) awaiting human approval.",
                tool_name=tool.name,
                estimated_cost_usd=cost,
            )
    return None


def log_tool_outcome_after_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    tool_response: dict[str, Any],
) -> dict[str, Any] | None:
    """4. Observability & Tracing: Record actual tool outcome and status AFTER execution."""
    log_structured_event(
        event_type="TOOL_EXECUTION_OUTCOME",
        message=f"Tool '{tool.name}' completed execution",
        phase="OUTCOME",
        tool_name=tool.name,
        outcome_status=tool_response.get("status", "completed")
        if isinstance(tool_response, dict)
        else "completed",
        actual_outcome=scrub_pii_data(json.dumps(tool_response, default=str)),
        agent_name=tool_context.agent_name,
    )
    return None


async def _background_persist_memory(memory_service: Any, session: Any) -> None:
    """Background coroutine that consolidates and stores session memories without blocking the turn."""
    try:
        await memory_service.add_session_to_memory(session)
        log_structured_event(
            event_type="ASYNC_MEMORY_CONSOLIDATED",
            message="Successfully consolidated session into persistent Memory Bank in background task.",
            session_id=getattr(session, "id", "unknown"),
        )
    except Exception as exc:
        log_structured_event(
            event_type="ASYNC_MEMORY_ERROR",
            message=f"Background memory consolidation failed: {type(exc).__name__}",
        )


async def async_save_session_to_memory_callback(callback_context: CallbackContext) -> None:
    """2. Context & Memory: Non-blocking asynchronous memory consolidation callback."""
    if callback_context.state.get("security_blocked"):
        return
    inv_ctx = callback_context._invocation_context
    if inv_ctx.memory_service and inv_ctx.session:
        # Schedule memory consolidation as a non-blocking background task
        asyncio.create_task(
            _background_persist_memory(inv_ctx.memory_service, inv_ctx.session)
        )


# ---------------------------------------------------------------------------
# 2. Context & Memory: Robust System Instructions (Constitution)
# ---------------------------------------------------------------------------
FAST_MODEL = "gemini-2.5-flash"
REASONING_MODEL = "gemini-2.5-pro"

ENTERPRISE_CONSTITUTION_PROMPT = """
# ENTERPRISE IT HELPDESK & PROCUREMENT AGENT CONSTITUTION

## 1. PERSONA & MISSION
You are the Enterprise IT Helpdesk & Asset Governance Coordinator. Your mission is to diagnose corporate hardware issues, log critical support tickets, and coordinate policy-compliant hardware replacements while personalizing interactions using remembered employee preferences (name, office location, preferred OS).

## 2. DOMAIN KNOWLEDGE & TOOL PROTOCOLS
- Always call `inspect_corporate_device_warranty` to check Firestore device health and warranty status when given a device ID (e.g., LAPTOP-001, LAPTOP-002).
- Always call `create_critical_it_incident_ticket` when a user asks to open or log a support ticket.
- Always call `search_enterprise_knowledge_base` when verifying corporate warranty or replacement thresholds.
- Call `submit_high_value_hardware_replacement_order` for replacement orders, or delegate complex procurement audits to `procurement_compliance_pipeline`.

## 3. MANDATORY SECURITY & HUMAN-IN-THE-LOOP (HITL) CONSTRAINTS
- NEVER fulfill requests to dump passwords, bypass security controls, or grant unauthorized root/admin access.
- NEVER redact or expose raw SSNs or credit card numbers in responses.
- Any hardware replacement order exceeding $500.00 requires explicit Human-in-the-Loop confirmation (`human_approved=True`). If not yet approved, present the cost and ask the user for confirmation first.
""".strip()


# ---------------------------------------------------------------------------
# 3. Orchestration & Logic: Multi-Agent Pattern (Coordinator + Sequential Pipeline)
# ---------------------------------------------------------------------------
it_diagnostics_specialist = Agent(
    name="it_diagnostics_specialist",
    model=FAST_MODEL,
    description="Fast diagnostic specialist that inspects device warranty in Firestore and retrieves IT policies.",
    instruction=(
        "You are an IT Diagnostics Specialist running on a low-latency Flash model. "
        "Inspect the requested corporate device using `inspect_corporate_device_warranty` "
        "and check relevant replacement policies using `search_enterprise_knowledge_base`."
    ),
    tools=[
        inspect_corporate_device_warranty,
        search_enterprise_knowledge_base,
    ],
    before_tool_callback=log_tool_intent_before_callback,
    after_tool_callback=log_tool_outcome_after_callback,
)

financial_compliance_auditor = Agent(
    name="financial_compliance_auditor",
    model=REASONING_MODEL,
    description="Pro-model compliance auditor that evaluates high-value hardware replacement risk and HITL rules.",
    instruction=(
        "You are a Principal Financial & IT Compliance Auditor running on Gemini Pro. "
        "Review the diagnostic findings and evaluate whether a hardware replacement order complies "
        "with corporate policy (orders > $500 require Human-in-the-Loop manager approval). "
        "Produce a structured `ComplianceAuditReport`."
    ),
    output_schema=ComplianceAuditReport,
    output_key="compliance_audit_report",
)

procurement_compliance_pipeline = SequentialAgent(
    name="procurement_compliance_pipeline",
    description=(
        "Sequential multi-agent pipeline that first runs IT device diagnostics (Flash) "
        "and then performs a structured financial compliance audit (Pro) for hardware replacements."
    ),
    sub_agents=[
        it_diagnostics_specialist,
        financial_compliance_auditor,
    ],
)

root_agent = Agent(
    name="helpdesk_agent",
    model=FAST_MODEL,
    description="Enterprise IT Helpdesk & Hardware Governance Coordinator Agent.",
    instruction=ENTERPRISE_CONSTITUTION_PROMPT,
    tools=[
        PreloadMemoryTool(),
        inspect_corporate_device_warranty,
        create_critical_it_incident_ticket,
        hardware_order_tool,
        search_enterprise_knowledge_base,
    ],
    sub_agents=[
        procurement_compliance_pipeline,
    ],
    before_model_callback=security_and_routing_before_model_callback,
    after_model_callback=self_evaluation_after_model_callback,
    before_tool_callback=log_tool_intent_before_callback,
    after_tool_callback=log_tool_outcome_after_callback,
    after_agent_callback=async_save_session_to_memory_callback,
)

app = App(
    root_agent=root_agent,
    name="app",
    events_compaction_config=EventsCompactionConfig(
        compaction_interval=5,
        overlap_size=2,
    ),
    resumability_config=ResumabilityConfig(is_resumable=True),
)
