# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
import logging
import math
import re as _re
from dataclasses import dataclass
from typing import Any

import requests as http_client

from apip_sdk_core import (
    BodyProcessingMode,
    ImmediateResponse,
    ProcessingMode,
    RequestPolicy,
    UpstreamRequestModifications,
)

# The fault contract, when the gateway's SDK has it. The Python SDK is the one the gateway
# runtime ships, not one this policy pins, so on a gateway that predates the contract these
# names do not exist; the rejections then go out exactly as before, with no fault fields.
try:
    from apip_sdk_core import FaultCode, FaultDetails, FaultType, GuardrailCode, GuardrailDetails
except ImportError:  # pragma: no cover - exercised on gateways without the fault contract
    FaultDetails = None

LOGGER = logging.getLogger(__name__)

_GUARDRAIL_NAME = "granite-guardian-prompt-injection"

_DEFAULT_RISKS: list[str] = ["jailbreak", "prompt_injection"]
_DEFAULT_JSON_PATH = "$.messages[-1].content"
_DEFAULT_MODEL = "ibm-granite/granite-guardian-3.3-8b"

_PASSTHROUGH: UpstreamRequestModifications | None = None


@dataclass(frozen=True)
class SystemParams:
    endpoint: str
    api_key: str
    model: str
    timeout: int


@dataclass(frozen=True)
class RequestParams:
    json_path: str
    risk_names: list[str]
    threshold: float
    block_status_code: int
    passthrough_on_error: bool
    show_assessment: bool


class GraniteGuardianPromptInjectionPolicy(RequestPolicy):
    """Detects prompt injection and jailbreak attempts via Granite Guardian."""

    def __init__(self, system_params: SystemParams) -> None:
        self._params = system_params

    def mode(self) -> ProcessingMode:
        return ProcessingMode(request_body_mode=BodyProcessingMode.BUFFER)

    def on_request_body(self, execution_ctx, req_ctx, params):
        if not (req_ctx.body and req_ctx.body.present and req_ctx.body.content):
            return _PASSTHROUGH

        req_params = normalize_request_params(params)

        try:
            body_data = json.loads(req_ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH

        text = _resolve_jsonpath(body_data, req_params.json_path)
        if not text or not isinstance(text, str):
            return _PASSTHROUGH

        for risk_name in req_params.risk_names:
            try:
                blocked, assessment = self._call_guardian(text, risk_name, req_params.threshold)
            except Exception as exc:
                LOGGER.warning(
                    "granite-guardian error (risk=%s, request_id=%s): %s",
                    risk_name,
                    getattr(execution_ctx, "request_id", None),
                    exc,
                )
                if req_params.passthrough_on_error:
                    continue
                return ImmediateResponse(
                    status_code=503,
                    headers={"content-type": "application/json"},
                    body=json.dumps({
                        "type": "GRANITE_GUARDIAN_PROMPT_INJECTION",
                        "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Guardrail service unavailable."},
                    }).encode(),
                    **_service_unavailable_fault(risk_name),
                )

            if blocked:
                msg: dict = {
                    "action": "GUARDRAIL_INTERVENED",
                    "interveningGuardrail": "Granite Guardian Prompt Injection",
                    "actionReason": "Prompt injection or jailbreak attempt detected.",
                    "direction": "REQUEST",
                }
                if req_params.show_assessment:
                    msg["assessments"] = {"riskName": risk_name, "verdict": assessment.get("verdict", "")}
                return ImmediateResponse(
                    status_code=req_params.block_status_code,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"type": "GRANITE_GUARDIAN_PROMPT_INJECTION", "message": msg}).encode(),
                    **_intervention_fault(risk_name, msg.get("assessments")),
                )

        return _PASSTHROUGH

    def _call_guardian(self, text: str, risk_name: str, threshold: float) -> tuple[bool, dict]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._params.api_key:
            headers["Authorization"] = f"Bearer {self._params.api_key}"

        # Granite Guardian 3.3 embeds the risk config in a system message.
        # The model replies "Yes" when the risk is detected, "No" when safe.
        payload = {
            "model": self._params.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f'<guardianconfig>{{"risk_name": "{risk_name}"}}'
                        "</guardianconfig>"
                    ),
                },
                {"role": "user", "content": text},
            ],
            "max_tokens": 200,
            "temperature": 0,
            "logprobs": True,
            "top_logprobs": 5,
        }

        response = http_client.post(
            f"{self._params.endpoint}/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=self._params.timeout,
        )
        response.raise_for_status()
        data = response.json()

        raw_verdict: str = data["choices"][0]["message"]["content"].strip()

        # Granite Guardian 3.3 wraps the verdict in <score> tags after a
        # <think> block: "<think>...</think>\n<score> yes </score>"
        # Extract the score tag content when present, otherwise fall back to
        # checking the raw text directly (older model versions).
        score_match = _re.search(r"<score>\s*(\w+)\s*</score>", raw_verdict, _re.IGNORECASE)
        verdict_word = score_match.group(1).lower() if score_match else raw_verdict.lower()

        blocked = verdict_word.startswith("yes")
        confidence: float | None = None

        if blocked and threshold > 0.0:
            logprobs_content = (
                data["choices"][0]
                .get("logprobs", {})
                .get("content", [])
            )
            confidence = _verdict_confidence(logprobs_content, verdict_word.split()[0])
            # Treat missing confidence as non-blocking: if the backend didn't
            # return a logprob we cannot verify the threshold is met.
            if confidence is None or confidence < threshold:
                blocked = False

        assessment: dict = {"risk_name": risk_name, "verdict": verdict_word}
        if confidence is not None:
            assessment["confidence"] = round(confidence, 4)
        return blocked, assessment


def _intervention_fault(risk_name: str, assessments: dict | None) -> dict[str, Any]:
    """The fault fields for a blocked prompt; empty on an SDK without the fault contract."""
    if FaultDetails is None:
        return {}
    return {
        "is_fault": True,
        "fault": FaultDetails(
            code=GuardrailCode.PROMPT_INJECTION,
            type=FaultType.GUARDRAIL,
            direction="Request",
            message="Prompt injection or jailbreak attempt detected.",
            description=f"risk {risk_name} detected",
            guardrail=GuardrailDetails(
                intervening_guardrail=_GUARDRAIL_NAME,
                action_reason="Prompt injection or jailbreak attempt detected.",
                # Only where the operator opted in through showAssessment, as in the body.
                assessments=assessments,
            ),
        ),
    }


def _service_unavailable_fault(risk_name: str) -> dict[str, Any]:
    """The fault fields when the guardian service could not be reached; empty on an SDK
    without the fault contract. Not a guardrail verdict: the gateway failed to reach its own
    dependency."""
    if FaultDetails is None:
        return {}
    return {
        "is_fault": True,
        "fault": FaultDetails(
            code=FaultCode.MEDIATION_FAILED,
            type=FaultType.MEDIATION,
            direction="Request",
            message="Guardrail service unavailable.",
            description=f"granite-guardian call failed while checking risk {risk_name}",
        ),
    }


def get_policy(metadata, params):
    return GraniteGuardianPromptInjectionPolicy(normalize_system_params(params))


def normalize_system_params(params: dict[str, Any] | None) -> SystemParams:
    params = params or {}

    endpoint = params.get("endpoint", "")
    if not isinstance(endpoint, str):
        LOGGER.warning("GraniteGuardian: invalid endpoint %r, using empty string", endpoint)
        endpoint = ""
    endpoint = endpoint.strip().rstrip("/")

    api_key = params.get("apiKey", "")
    if not isinstance(api_key, str):
        api_key = ""

    model = params.get("model", _DEFAULT_MODEL)
    if not isinstance(model, str) or not model.strip():
        LOGGER.warning("GraniteGuardian: invalid model %r, falling back to %s", model, _DEFAULT_MODEL)
        model = _DEFAULT_MODEL
    else:
        model = model.strip()

    timeout = _coerce_int_in_range(params.get("timeout", 10), lo=1, hi=60, default=10)

    return SystemParams(endpoint=endpoint, api_key=api_key, model=model, timeout=timeout)


def normalize_request_params(params: dict[str, Any] | None) -> RequestParams:
    params = params or {}

    json_path = params.get("jsonPath", _DEFAULT_JSON_PATH)
    if not isinstance(json_path, str) or not json_path.strip():
        LOGGER.warning(
            "GraniteGuardian: invalid jsonPath %r, falling back to %s",
            json_path,
            _DEFAULT_JSON_PATH,
        )
        json_path = _DEFAULT_JSON_PATH
    else:
        json_path = json_path.strip()

    raw_risks = params.get("riskNames", list(_DEFAULT_RISKS))
    if not isinstance(raw_risks, list):
        LOGGER.warning("GraniteGuardian: riskNames must be a list, got %s", type(raw_risks).__name__)
        raw_risks = list(_DEFAULT_RISKS)
    risk_names = [r for r in raw_risks if isinstance(r, str) and r.strip()]

    threshold = _coerce_float_clamped(params.get("threshold", 0.5), lo=0.0, hi=1.0, default=0.5)
    block_status_code = _coerce_int_in_range(params.get("blockStatusCode", 400), lo=400, hi=599, default=400)
    passthrough_on_error = _coerce_bool(params.get("passthroughOnError"), default=False)
    show_assessment = _coerce_bool(params.get("showAssessment"), default=False)

    return RequestParams(
        json_path=json_path,
        risk_names=risk_names,
        threshold=threshold,
        block_status_code=block_status_code,
        passthrough_on_error=passthrough_on_error,
        show_assessment=show_assessment,
    )


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    if isinstance(value, int):
        return bool(value)
    return default


def _coerce_int_in_range(value: Any, lo: int, hi: int, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and lo <= value <= hi:
        return value
    if isinstance(value, float) and value.is_integer() and lo <= int(value) <= hi:
        return int(value)
    if isinstance(value, str):
        try:
            f = float(value)
            if f.is_integer() and lo <= int(f) <= hi:
                return int(f)
        except ValueError:
            pass
    return default


def _coerce_float_clamped(value: Any, lo: float, hi: float, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return max(lo, min(hi, float(value)))
    if isinstance(value, str):
        try:
            return max(lo, min(hi, float(value)))
        except ValueError:
            pass
    return default


def _verdict_confidence(logprobs_content: list, verdict_word: str) -> float | None:
    # vLLM returns per-token logprobs; the verdict token appears near the end, inside <score>.
    # Searching in reverse finds it without tracking character offsets.
    target = verdict_word.strip().lower()
    for token_data in reversed(logprobs_content):
        if token_data.get("token", "").strip().lower() == target:
            lp = token_data.get("logprob")
            if lp is not None:
                return math.exp(lp)
    return None


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Resolve a simple dotted JSONPath expression against *data*.

    Handles the patterns used throughout this codebase, e.g.:
      ``$.messages[-1].content``  →  data["messages"][-1]["content"]
      ``$.content``               →  data["content"]
    """
    if not path or path == "$":
        return data

    path = path.lstrip("$").lstrip(".")

    segments: list[str | int] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "[":
            if buf:
                segments.append(buf)
                buf = ""
            try:
                j = path.index("]", i)
            except ValueError:
                return None
            try:
                segments.append(int(path[i + 1 : j]))
            except ValueError:
                return None
            i = j + 1
            if i < len(path) and path[i] == ".":
                i += 1
        elif ch == ".":
            if buf:
                segments.append(buf)
                buf = ""
            i += 1
        else:
            buf += ch
            i += 1
    if buf:
        segments.append(buf)

    current = data
    for seg in segments:
        if current is None:
            return None
        if isinstance(seg, int):
            if isinstance(current, list) and -len(current) <= seg < len(current):
                current = current[seg]
            else:
                return None
        else:
            current = current.get(seg) if isinstance(current, dict) else None
    return current
