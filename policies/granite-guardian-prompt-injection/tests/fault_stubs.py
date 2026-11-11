# Fault-contract stand-ins for the parts of apip_sdk_core a migrated policy uses. Values are
# copied from the SDK literally, the way its own mirror tests do, so a drift fails here too.
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FaultImmediateResponse:
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    body: bytes | None = None
    is_fault: bool = False
    fault: Any = None


@dataclass
class GuardrailDetails:
    intervening_guardrail: str = ""
    action: str = "GUARDRAIL_INTERVENED"
    action_reason: str = ""
    assessments: dict | None = None


@dataclass
class FaultDetails:
    code: str = ""
    type: str = ""
    direction: str = ""
    message: str = ""
    description: str = ""
    jsonrpc: Any = None
    guardrail: GuardrailDetails | None = None


class FaultCode:
    MEDIATION_FAILED = "960000"
    INVALID_REQUEST_BODY = "960001"


class FaultType:
    GUARDRAIL = "guardrail"
    MEDIATION = "mediation"


class GuardrailCode:
    HATE = "906001"
    SEXUAL = "906002"
    SELF_HARM = "906003"
    VIOLENCE = "906004"
    HARASSMENT = "906005"
    DANGEROUS_ACTIVITY = "906006"
    PROFANITY = "906007"
    PROMPT_INJECTION = "906008"
    UNSAFE_CONTENT = "906099"
    PII = "906101"


def with_fault_contract(sdk_module) -> None:
    """Adds the fault contract to a stub SDK module, as a gateway with it would ship."""
    sdk_module.ImmediateResponse = FaultImmediateResponse
    sdk_module.FaultDetails = FaultDetails
    sdk_module.GuardrailDetails = GuardrailDetails
    sdk_module.FaultCode = FaultCode
    sdk_module.FaultType = FaultType
    sdk_module.GuardrailCode = GuardrailCode
