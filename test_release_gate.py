"""Unit tests for the deterministic release-gate policy."""

import copy
import unittest

from policy import evaluate

PINNED_SHA = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"
assert len(PINNED_SHA) == 40


def valid_preview():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/gate",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "docker",
                    "name": "login-action",
                    "ref": PINNED_SHA,
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def valid_production():
    payload = valid_preview()
    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True
    return payload


class ReleaseGateTests(unittest.TestCase):
    def assert_promote(self, payload):
        result = evaluate(payload)
        self.assertEqual(result["decision"], "promote")
        self.assertEqual(result["violations"], [])

    def assert_codes(self, payload, *codes):
        result = evaluate(payload)
        self.assertEqual(result["decision"], "block")
        self.assertCountEqual(result["violations"], list(codes))

    def test_safe_preview_promotes(self):
        self.assert_promote(valid_preview())

    def test_safe_preview_buildkit_secret_promotes(self):
        payload = valid_preview()
        payload["image"]["secretMode"] = "buildkit"
        self.assert_promote(payload)

    def test_safe_production_promotes(self):
        self.assert_promote(valid_production())

    def test_excess_permission_extra_scope(self):
        payload = valid_preview()
        payload["workflow"]["permissions"]["actions"] = "read"
        self.assert_codes(payload, "EXCESS_PERMISSION")

    def test_excess_permission_contents_write(self):
        payload = valid_preview()
        payload["workflow"]["permissions"]["contents"] = "write"
        self.assert_codes(payload, "EXCESS_PERMISSION")

    def test_excess_permission_id_token_write(self):
        payload = valid_preview()
        payload["workflow"]["permissions"]["id-token"] = "write"
        self.assert_codes(payload, "EXCESS_PERMISSION")

    def test_unsafe_pr_trigger(self):
        payload = valid_preview()
        payload["workflow"]["trigger"] = "pull_request_target"
        self.assert_codes(payload, "UNSAFE_PR_TRIGGER")

    def test_pr_event_must_use_pull_request_trigger(self):
        payload = valid_preview()
        payload["workflow"]["trigger"] = "push"
        self.assert_codes(payload, "UNSAFE_PR_TRIGGER")

    def test_tests_incomplete_failed_tests(self):
        payload = valid_preview()
        payload["workflow"]["testsPassed"] = False
        self.assert_codes(payload, "TESTS_INCOMPLETE")

    def test_tests_incomplete_matrix(self):
        payload = valid_preview()
        payload["workflow"]["matrixComplete"] = False
        self.assert_codes(payload, "TESTS_INCOMPLETE")

    def test_tests_incomplete_fail_fast(self):
        payload = valid_preview()
        payload["workflow"]["failFast"] = True
        self.assert_codes(payload, "TESTS_INCOMPLETE")

    def test_mutable_third_party_tag(self):
        payload = valid_preview()
        payload["workflow"]["actions"][1]["ref"] = "v3"
        self.assert_codes(payload, "MUTABLE_ACTION")

    def test_mutable_third_party_uppercase_sha(self):
        payload = valid_preview()
        payload["workflow"]["actions"][1]["ref"] = PINNED_SHA.upper()
        self.assert_codes(payload, "MUTABLE_ACTION")

    def test_mutable_short_sha(self):
        payload = valid_preview()
        payload["workflow"]["actions"][1]["ref"] = "b2c3d4e5f6a7"
        self.assert_codes(payload, "MUTABLE_ACTION")

    def test_first_party_tag_allowed(self):
        payload = valid_preview()
        payload["workflow"]["actions"] = [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "actions", "name": "setup-python", "ref": "v5"},
        ]
        self.assert_promote(payload)

    def test_first_party_owner_is_case_insensitive(self):
        payload = valid_preview()
        payload["workflow"]["actions"] = [
            {"owner": "Actions", "name": "checkout", "ref": "v4"},
        ]
        self.assert_promote(payload)

    def test_single_stage_image(self):
        payload = valid_preview()
        payload["image"]["multiStage"] = False
        self.assert_codes(payload, "SINGLE_STAGE_IMAGE")

    def test_root_runtime(self):
        payload = valid_preview()
        payload["image"]["runsAsRoot"] = True
        self.assert_codes(payload, "ROOT_RUNTIME")

    def test_secret_in_layer_arg(self):
        payload = valid_preview()
        payload["image"]["secretMode"] = "arg"
        self.assert_codes(payload, "SECRET_IN_LAYER")

    def test_secret_in_layer_copy(self):
        payload = valid_preview()
        payload["image"]["secretMode"] = "copy"
        self.assert_codes(payload, "SECRET_IN_LAYER")

    def test_critical_cve(self):
        payload = valid_preview()
        payload["image"]["criticalVulnerabilities"] = 2
        self.assert_codes(payload, "CRITICAL_CVE")

    def test_unpinned_image(self):
        payload = valid_preview()
        payload["image"]["digestPinned"] = False
        self.assert_codes(payload, "UNPINNED_IMAGE")

    def test_invalid_production_ref_branch(self):
        payload = valid_production()
        payload["ref"] = "refs/heads/release"
        self.assert_codes(payload, "INVALID_PRODUCTION_REF")

    def test_invalid_production_event(self):
        payload = valid_production()
        payload["event"] = "pull_request"
        payload["workflow"]["trigger"] = "pull_request"
        self.assert_codes(payload, "INVALID_PRODUCTION_REF")

    def test_approval_required(self):
        payload = valid_production()
        payload["workflow"]["environmentApproval"] = False
        self.assert_codes(payload, "APPROVAL_REQUIRED")

    def test_approval_missing_on_production(self):
        payload = valid_production()
        del payload["workflow"]["environmentApproval"]
        self.assert_codes(payload, "APPROVAL_REQUIRED")

    def test_preview_does_not_require_approval(self):
        payload = valid_preview()
        self.assertNotIn("environmentApproval", payload["workflow"])
        self.assert_promote(payload)

    def test_multi_failure_payload(self):
        payload = valid_preview()
        payload["workflow"]["permissions"]["packages"] = "read"
        payload["workflow"]["trigger"] = "pull_request_target"
        payload["workflow"]["testsPassed"] = False
        payload["workflow"]["failFast"] = True
        payload["workflow"]["actions"][1]["ref"] = "main"
        payload["image"]["multiStage"] = False
        payload["image"]["runsAsRoot"] = True
        payload["image"]["secretMode"] = "arg"
        payload["image"]["criticalVulnerabilities"] = 4
        payload["image"]["digestPinned"] = False
        payload["target"] = "production"
        payload["event"] = "pull_request"
        payload["ref"] = "refs/heads/feature/gate"
        self.assert_codes(
            payload,
            "EXCESS_PERMISSION",
            "UNSAFE_PR_TRIGGER",
            "TESTS_INCOMPLETE",
            "MUTABLE_ACTION",
            "SINGLE_STAGE_IMAGE",
            "ROOT_RUNTIME",
            "SECRET_IN_LAYER",
            "CRITICAL_CVE",
            "UNPINNED_IMAGE",
            "INVALID_PRODUCTION_REF",
            "APPROVAL_REQUIRED",
        )

    def test_copy_does_not_mutate_input(self):
        payload = valid_preview()
        original = copy.deepcopy(payload)
        evaluate(payload)
        self.assertEqual(payload, original)


if __name__ == "__main__":
    unittest.main()
