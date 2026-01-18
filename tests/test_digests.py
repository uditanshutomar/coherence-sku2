"""
Test 5: Digest Tests
- Pattern ^sha256:[a-f0-9]{64}$ enforced
- Partial digests rejected
- Uppercase hex rejected
"""
import pytest
from pydantic import ValidationError
from coherence.schemas import Subject, PolicyCGR


class TestDigestPattern:
    def test_valid_digest_accepted(self):
        """Valid sha256:[64 hex chars] must be accepted."""
        subject = Subject(
            action_id="act-1",
            action_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert subject.action_digest.startswith("sha256:")

    def test_partial_digest_rejected(self):
        """Partial digest (< 64 hex chars) must be rejected."""
        with pytest.raises(ValidationError):
            Subject(action_id="act-1", action_digest="sha256:abc123")

    def test_uppercase_hex_rejected(self):
        """Uppercase hex characters must be rejected."""
        with pytest.raises(ValidationError):
            Subject(
                action_id="act-1",
                action_digest="sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            )

    def test_missing_prefix_rejected(self):
        """Digest without sha256: prefix must be rejected."""
        with pytest.raises(ValidationError):
            Subject(
                action_id="act-1",
                action_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )

    def test_wrong_hash_type_rejected(self):
        """Digest with wrong hash type (e.g., sha512:) must be rejected."""
        with pytest.raises(ValidationError):
            Subject(
                action_id="act-1",
                action_digest="sha512:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )

    def test_policy_digest_same_rules(self):
        """Policy digest follows same pattern rules."""
        with pytest.raises(ValidationError):
            PolicyCGR(policy_id="pol-1", policy_digest="sha256:SHORT")
