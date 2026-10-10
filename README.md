# Enterprise IT Helpdesk & Hardware Governance Multi-Agent System

An enterprise-grade multi-agent system built with the **Google Agent Development Kit (ADK)**, **Vertex AI Agent Runtime (Reasoning Engine)**, **Cloud Firestore**, **Vertex AI Memory Bank**, and **`agents-cli`**.

## Problem & Solution Statement

* **Problem**: Enterprise IT helpdesk and hardware replacement workflows suffer from fragmented asset databases, repetitive manual warranty checks, lack of cross-session employee context, and unvalidated high-cost hardware orders.
* **Solution**: A production-hardened **Coordinator + Sequential Multi-Agent System** (`helpdesk_agent` + `procurement_compliance_pipeline`) that:
  1. Diagnoses corporate device warranty & health in **Cloud Firestore** (`inspect_corporate_device_warranty`) and logs incidents (`create_critical_it_incident_ticket`).
  2. Persists cross-session employee preferences in **Vertex AI Memory Bank** (`VertexAiMemoryBankService`) with non-blocking async consolidation and `EventsCompactionConfig`.
  3. Enforces **Human-in-the-Loop (HITL)** manager confirmation for hardware replacement orders over `$500.00` (`submit_high_value_hardware_replacement_order`).
  4. Provides full **AgentOps Observability & Security**: OpenTelemetry distributed tracing, structured JSON intent/outcome logging, Cloud DLP PII scrubbing, and Secret Manager integration.

---

## AgentOps Code Review Matrix (95-Point Rubric Mapping)

| Category | Criteria | Implementation in Repository |
| :--- | :--- | :--- |
| **1. Tool & Interface Design** | **Comprehensive Tool Docstrings** | Google-style docstrings with `Args:` and `Returns:` on all tools in `app/agent.py`. |
| | **Descriptive Naming** | Specific verb-noun names: `inspect_corporate_device_warranty`, `create_critical_it_incident_ticket`, `submit_high_value_hardware_replacement_order`, `search_enterprise_knowledge_base`. |
| | **Explicit JSON Schemas** | Strict Pydantic `BaseModel` schemas (`DeviceInspectionInput`/`Output`, `CriticalIncidentInput`/`Output`, `HardwareReplacementOrderInput`/`Output`, `ComplianceAuditReport`). |
| | **Guided Error Handling** | Validation and database errors return structured `recovery_instructions` guiding LLM self-correction without crashing. |
| **2. Context & Memory** | **Robust System Instructions** | `ENTERPRISE_CONSTITUTION_PROMPT` defining Persona, Domain Protocols, and Security/HITL Constraints. |
| | **History Compaction** | ADK `EventsCompactionConfig(compaction_interval=5, overlap_size=2)` + `compact_conversation_history()` sliding window. |
| | **Persistent Session State** | `VertexAiSessionService`, `VertexAiMemoryBankService` (`app/app_utils/services.py`), and `google.cloud.firestore.Client`. |
| | **Async Memory Operations** | `async_save_session_to_memory_callback` dispatches background memory consolidation via `asyncio.create_task()`. |
| **3. Orchestration & Logic** | **Multi-Agent Patterns** | Root Coordinator (`helpdesk_agent`) + `SequentialAgent` (`procurement_compliance_pipeline` chaining `it_diagnostics_specialist` and `financial_compliance_auditor`). |
| | **Strategic Model Routing** | `gemini-2.5-flash` for low-latency diagnostics and `gemini-2.5-pro` for complex financial compliance auditing. |
| | **Guardrails & Policy Plugins** | `security_and_routing_before_model_callback` (prompt injection barrier) + `self_evaluation_after_model_callback` (output PII policy check). |
| | **Human-in-the-Loop Hooks** | Mandatory pause on hardware orders exceeding `$500.00` (`submit_high_value_hardware_replacement_order` & `log_tool_intent_before_callback`). |
| **4. Observability & Tracing** | **Structured JSON Logging** | `StructuredJsonFormatter` emitting JSON logs with trace/span IDs (`log_structured_event`). |
| | **Intent vs. Outcome Capture** | `log_tool_intent_before_callback` (`phase="INTENT"`) and `log_tool_outcome_after_callback` (`phase="OUTCOME"`). |
| | **Distributed Tracing** | OpenTelemetry `TracerProvider` + `CloudTraceSpanExporter` spans across tools and callbacks. |
| | **PII Redaction** | `scrub_pii_data()` combining Google Cloud DLP API (`dlp_v2`) and regex scrubbing for SSN, credit card, email, and phone numbers. |
| **5. Infrastructure & CI/CD** | **Automated Evaluation Suites** | Golden evaluation dataset (`tests/eval/datasets/helpdesk-dataset.json`), LLM-as-judge (`tests/eval/response_quality.py`), and unit tests (`tests/unit/test_dummy.py`). |
| | **Infrastructure as Code** | Complete Terraform modules in `deployment/terraform/single-project/` and `agents-cli` lifecycle support. |
| | **Secure Secret Management** | `get_secret_from_secret_manager()` using `google.cloud.secretmanager` with zero hardcoded keys. |

---

## Quick Start (`agents-cli` & `uv`)

```bash
# 1. Install dependencies
agents-cli install

# 2. Run unit & regression tests
uv run pytest tests/unit

# 3. Launch local interactive playground
agents-cli playground

# 4. Run evaluation suite against golden dataset
agents-cli eval run --config tests/eval/eval_config.yaml

# 5. Provision infrastructure (Terraform) and deploy to Vertex AI Agent Runtime
gcloud config set project <your-gcp-project-id>
agents-cli infra cicd
agents-cli deploy
```
