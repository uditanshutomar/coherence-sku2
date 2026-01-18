"""
Test 3: Binding Tests
- 5-field match enforced (aud, tenant_id, subject.action_id, subject.action_digest, policy.policy_digest)
- Any mismatch denies
- gate_receipt_id binding required
- Top-level vs nested field paths validated
"""
import pytest
import copy
from tests.conftest import load_vector, sign_payload


class TestFiveFieldMatch:
    def test_matching_binding_passes(self, verifier, private_key):
        """CDR with matching 5 fields + gate_receipt_id must pass."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is True

    def test_aud_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched aud must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["aud"] = "other-service"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False

    def test_tenant_id_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched tenant_id must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["tenant_id"] = "other-tenant"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False

    def test_action_id_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched subject.action_id must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["subject"]["action_id"] = "other-action"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False

    def test_action_digest_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched subject.action_digest must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["subject"]["action_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False

    def test_policy_digest_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched policy.policy_digest must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["policy"]["policy_digest"] = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False


class TestGateReceiptIdBinding:
    def test_gate_receipt_id_mismatch_denied(self, verifier, private_key):
        """CDR with mismatched gate_receipt_id must fail binding."""
        cgr = load_vector("unsigned_cgr.json")
        cgr_signed = sign_payload(cgr, private_key)
        
        cdr = load_vector("unsigned_cdr.json")
        cdr["gate_receipt_id"] = "cgr-other-id"
        cdr_signed = sign_payload(cdr, private_key)
        
        assert verifier.verify_decision_receipt(cdr_signed, cgr_signed) is False
