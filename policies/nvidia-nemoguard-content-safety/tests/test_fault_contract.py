"""The policy on a gateway whose SDK has the fault contract: rejections declare the fault and
describe it, and the body the client receives is the same as without the contract."""
from __future__ import annotations

import importlib
import sys
import types
import unittest

from . import test_policy as base
from .fault_stubs import FaultImmediateResponse, with_fault_contract


def load_with_fault_contract():
    """Imports a second copy of the policy against an SDK stub that has the fault contract.

    Only the SDK module is swapped, and only for the import: the shared ``requests`` stub and
    the original SDK stub stay in place, so the base tests in test_policy are unaffected."""
    original_sdk = sys.modules["apip_sdk_core"]
    sdk = types.ModuleType("apip_sdk_core")
    sdk.__dict__.update({k: v for k, v in vars(original_sdk).items() if not k.startswith("__")})
    with_fault_contract(sdk)
    sys.modules["apip_sdk_core"] = sdk
    try:
        sys.modules.pop("nvidia_nemoguard_content_safety_v0", None)
        sys.modules.pop("nvidia_nemoguard_content_safety_v0.policy", None)
        return importlib.import_module("nvidia_nemoguard_content_safety_v0.policy")
    finally:
        sys.modules["apip_sdk_core"] = original_sdk

policy = load_with_fault_contract()
REQUEST = {"messages": [{"role": "user", "content": "some text"}]}
RESPONSE = {"choices": [{"message": {"content": "some reply"}}]}


def make(module):
    return module.get_policy(metadata={}, params={"endpoint": base.ENDPOINT})


class FaultContractTest(unittest.TestCase):

    def block_request(self, module, categories: str, params: dict | None = None):
        base.FakeRequests.reset(response=base.nemoguard_response("unsafe", categories=categories))
        return make(module).on_request_body(None, base.request_context(REQUEST), params or {})

    def test_request_block_maps_the_category_to_a_guardrail_code(self) -> None:
        for category, code in (("Violence", "906004"), ("Hate/Identity Hate", "906001"),
                               ("PII/Privacy", "906101"), ("Malware", "906006"),
                               ("Other", "906099")):
            result = self.block_request(policy, category)
            self.assertIsInstance(result, FaultImmediateResponse)
            self.assertTrue(result.is_fault, category)
            self.assertEqual(code, result.fault.code, category)
            self.assertEqual("guardrail", result.fault.type)
            self.assertEqual("Request", result.fault.direction)
            self.assertEqual("nvidia-nemoguard-content-safety",
                             result.fault.guardrail.intervening_guardrail)

    def test_mixed_verdict_reports_the_blocked_category(self) -> None:
        params = {"categories": {"violence": False, "profanity": True}}
        result = self.block_request(policy, "Violence, Profanity", {"request": params})
        self.assertTrue(result.is_fault)
        self.assertEqual("906007", result.fault.code, "violence is not blocked, so it did not cause this")

        base.FakeRequests.reset(response=base.nemoguard_response(
            "safe", response_safety="unsafe", categories="Violence, Profanity"))
        ctx = base.response_context(response_payload=RESPONSE, request_payload=REQUEST)
        result = make(policy).on_response_body(None, ctx, {"response": {"enabled": True, **params}})
        self.assertTrue(result.is_fault)
        self.assertEqual("906007", result.fault.code)

    def test_response_block_is_a_fault_despite_its_200(self) -> None:
        base.FakeRequests.reset(response=base.nemoguard_response(
            "safe", response_safety="unsafe", categories="Violence"))
        ctx = base.response_context(response_payload=RESPONSE, request_payload=REQUEST)
        result = make(policy).on_response_body(None, ctx, {"response": {"enabled": True}})

        self.assertEqual(200, result.status_code)
        self.assertTrue(result.is_fault, "the status cannot say so, so the policy must")
        self.assertEqual("906004", result.fault.code)
        self.assertEqual("Response", result.fault.direction)

    def test_service_unavailable_is_the_gateways_failure(self) -> None:
        base.FakeRequests.reset(error=ConnectionError("Connection refused"))
        result = make(policy).on_request_body(None, base.request_context(REQUEST), {})

        self.assertEqual(503, result.status_code)
        self.assertTrue(result.is_fault)
        self.assertEqual("960000", result.fault.code)
        self.assertEqual("mediation", result.fault.type)
        self.assertEqual("Request", result.fault.direction)

    def test_response_service_unavailable_is_a_response_fault(self) -> None:
        base.FakeRequests.reset(error=ConnectionError("Connection refused"))
        ctx = base.response_context(response_payload=RESPONSE, request_payload=REQUEST)
        result = make(policy).on_response_body(None, ctx, {"response": {"enabled": True}})

        self.assertEqual(503, result.status_code)
        self.assertTrue(result.is_fault)
        self.assertEqual("960000", result.fault.code)
        self.assertEqual("mediation", result.fault.type)
        self.assertEqual("Response", result.fault.direction)

    def test_client_body_is_unchanged_by_the_contract(self) -> None:
        for params in ({}, {"request": {"showAssessment": True}}):
            with_contract = self.block_request(policy, "Violence", params)
            without = self.block_request(base.policy, "Violence", params)
            self.assertEqual(without.body, with_contract.body)
            self.assertEqual(without.headers, with_contract.headers)
            self.assertEqual(without.status_code, with_contract.status_code)


if __name__ == "__main__":
    unittest.main()
