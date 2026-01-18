"""
Test 4: Timestamp Tests
- Strict YYYY-MM-DDTHH:MM:SSZ format
- Milliseconds rejected
- Missing Z rejected
- Time window uses exclusive upper bound: issued_at <= now_utc < expires_at
"""
import pytest
from pydantic import ValidationError
from coherence.schemas import GateReceipt
from tests.conftest import load_vector


class TestTimestampFormat:
    def test_valid_timestamp_accepted(self):
        """Strict YYYY-MM-DDTHH:MM:SSZ format must be accepted."""
        receipt = load_vector("unsigned_cgr.json")
        receipt["signature"] = {"alg": "ed25519-sha256", "kid": "k", "sig": "A" * 86}
        # Should not raise
        GateReceipt.model_validate(receipt)

    def test_milliseconds_rejected(self):
        """Timestamps with milliseconds must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        receipt["signature"] = {"alg": "ed25519-sha256", "kid": "k", "sig": "A" * 86}
        receipt["issued_at"] = "2026-01-15T10:00:00.000Z"
        
        with pytest.raises(ValidationError):
            GateReceipt.model_validate(receipt)

    def test_missing_z_rejected(self):
        """Timestamps without trailing Z must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        receipt["signature"] = {"alg": "ed25519-sha256", "kid": "k", "sig": "A" * 86}
        receipt["issued_at"] = "2026-01-15T10:00:00"
        
        with pytest.raises(ValidationError):
            GateReceipt.model_validate(receipt)

    def test_timezone_offset_rejected(self):
        """Timestamps with timezone offset instead of Z must be rejected."""
        receipt = load_vector("unsigned_cgr.json")
        receipt["signature"] = {"alg": "ed25519-sha256", "kid": "k", "sig": "A" * 86}
        receipt["issued_at"] = "2026-01-15T10:00:00+00:00"
        
        with pytest.raises(ValidationError):
            GateReceipt.model_validate(receipt)


class TestTimeWindow:
    def test_expired_receipt_rejected(self, verifier, private_key):
        """Receipt past expires_at must be rejected."""
        from tests.conftest import sign_payload
        receipt = load_vector("unsigned_cgr.json")
        receipt["expires_at"] = "2020-01-01T00:00:00Z"  # In the past
        signed = sign_payload(receipt, private_key)
        
        assert verifier.verify_gate_receipt(signed) is False

    def test_future_issued_rejected(self, verifier, private_key):
        """Receipt with future issued_at must be rejected."""
        from tests.conftest import sign_payload
        receipt = load_vector("unsigned_cgr.json")
        receipt["issued_at"] = "2099-01-01T00:00:00Z"  # In the future
        signed = sign_payload(receipt, private_key)
        
        assert verifier.verify_gate_receipt(signed) is False
