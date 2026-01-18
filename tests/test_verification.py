"""
Test 2: Verification Tests
- Valid signature verifies correctly
- Tampered payload detected
- Wrong key detected
- Decoded signature = 64 bytes enforced
- Algorithm mismatch rejected
- Signature exclusion rule applied correctly
"""
import pytest
import copy
from cryptography.hazmat.primitives.asymmetric import ed25519
from coherence.verification import Verifier
from coherence.registry import InMemoryKeyRegistry
from coherence.replay import RedisReplayGuard
from coherence.security import base64url_decode_nopad_strict
from tests.conftest import load_vector, sign_payload, MockRedis, PUB_KEY, KID


class TestValidSignature:
    def test_valid_gate_receipt_verifies(self, verifier, private_key):
        """Valid signature on valid payload must verify."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        assert verifier.verify_gate_receipt(signed) is True


class TestTamperedPayload:
    def test_tampered_verdict_detected(self, verifier, private_key):
        """Tampered payload must fail verification."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        signed["verdict"] = "HALT"  # Tamper after signing
        assert verifier.verify_gate_receipt(signed) is False

    def test_tampered_tenant_id_detected(self, verifier, private_key):
        """Tampered tenant_id must fail verification."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        signed["tenant_id"] = "other-tenant"
        assert verifier.verify_gate_receipt(signed) is False


class TestWrongKey:
    def test_wrong_key_rejected(self, private_key):
        """Verification with wrong key must fail."""
        # Create a different key pair
        wrong_key = ed25519.Ed25519PrivateKey.generate()
        wrong_pub = wrong_key.public_key()
        
        registry = InMemoryKeyRegistry()
        registry.add_key(KID, "tenant-1", "service-a", wrong_pub)
        verifier = Verifier(registry, RedisReplayGuard(MockRedis()))
        
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)  # Signed with correct key
        
        # Verify with wrong key in registry
        assert verifier.verify_gate_receipt(signed) is False


class TestSignatureLength:
    def test_short_signature_rejected(self, verifier, private_key):
        """Signature that decodes to != 64 bytes must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        # Truncate signature (makes it invalid base64 length too, but tests the check)
        signed["signature"]["sig"] = signed["signature"]["sig"][:80]
        assert verifier.verify_gate_receipt(signed) is False


class TestAlgorithmMismatch:
    def test_wrong_algorithm_rejected(self, verifier, private_key):
        """Algorithm other than ed25519-sha256 must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        signed["signature"]["alg"] = "rs256"
        assert verifier.verify_gate_receipt(signed) is False


class TestReplayProtection:
    def test_replay_detected(self, verifier, private_key):
        """Second submission of same receipt must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        
        # First time -> True
        assert verifier.verify_gate_receipt(signed) is True
        # Second time -> False (Replay detected)
        assert verifier.verify_gate_receipt(signed) is False

    def test_different_receipts_both_pass(self, verifier, private_key):
        """Different receipts should both pass (no false replay)."""
        receipt1 = load_vector("unsigned_cgr.json")
        receipt1["gate_receipt_id"] = "cgr-test-001"
        signed1 = sign_payload(receipt1, private_key)
        
        receipt2 = load_vector("unsigned_cgr.json")
        receipt2["gate_receipt_id"] = "cgr-test-002"
        receipt2["decider"]["nonce"] = "Q0hFQ0stTk9OQ0UtMjJjaB"  # Different nonce (22 chars)
        signed2 = sign_payload(receipt2, private_key)
        
        assert verifier.verify_gate_receipt(signed1) is True
        assert verifier.verify_gate_receipt(signed2) is True
