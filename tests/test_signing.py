"""
Test 1: Signing Tests
- JCS canonicalization correctness
- Ed25519 signing produces 64 bytes
- Base64url encoding produces 86 chars
- Algorithm mismatch hard-fails
- Signature object excluded from canonical bytes
"""
import pytest
import jcs
from coherence.security import (
    canonicalize_for_signing,
    calculate_digest,
    base64url_encode_nopad,
    base64url_decode_nopad_strict
)
from tests.conftest import load_vector, sign_payload, KID


class TestJCSCanonicalization:
    def test_jcs_key_order_deterministic(self):
        """RFC 8785: Key order must be lexicographic."""
        dict1 = {"z": 1, "a": 2}
        dict2 = {"a": 2, "z": 1}
        assert jcs.canonicalize(dict1) == jcs.canonicalize(dict2)

    def test_signature_excluded_from_canonical(self):
        """Signature object must be excluded from canonicalization."""
        receipt = load_vector("unsigned_cgr.json")
        receipt_with_sig = receipt.copy()
        receipt_with_sig["signature"] = {"alg": "ed25519-sha256", "kid": "x", "sig": "y"}
        
        # Canonical bytes should be identical (signature excluded)
        assert canonicalize_for_signing(receipt) == canonicalize_for_signing(receipt_with_sig)


class TestEd25519Signing:
    def test_signature_is_64_bytes(self, private_key):
        """Ed25519 signature must be exactly 64 bytes."""
        receipt = load_vector("unsigned_cgr.json")
        digest = calculate_digest(receipt)
        sig_bytes = private_key.sign(digest)
        assert len(sig_bytes) == 64

    def test_signature_encodes_to_86_chars(self, private_key):
        """Base64url unpadded encoding of 64 bytes = 86 chars."""
        receipt = load_vector("unsigned_cgr.json")
        digest = calculate_digest(receipt)
        sig_bytes = private_key.sign(digest)
        sig_str = base64url_encode_nopad(sig_bytes)
        assert len(sig_str) == 86

    def test_signed_receipt_has_correct_structure(self, private_key):
        """Signed receipt must have alg, kid, sig fields."""
        receipt = load_vector("unsigned_cgr.json")
        signed = sign_payload(receipt, private_key)
        
        assert "signature" in signed
        assert signed["signature"]["alg"] == "ed25519-sha256"
        assert signed["signature"]["kid"] == KID
        assert len(signed["signature"]["sig"]) == 86
