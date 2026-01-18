"""
Test 6: Role Slug Tests
- Pattern ^[a-z][a-z0-9_]*(_[a-z0-9_]+)*$ enforced
- Uppercase rejected
- Hyphens rejected
- Spaces rejected
"""
import pytest
from pydantic import ValidationError
from coherence.schemas import Approver


class TestRoleSlugPattern:
    def test_valid_simple_role_accepted(self):
        """Simple lowercase role must be accepted."""
        approver = Approver(user_id="user@example.com", role="admin")
        assert approver.role == "admin"

    def test_valid_role_with_underscore_accepted(self):
        """Role with underscores must be accepted."""
        approver = Approver(user_id="user@example.com", role="ops_engineer")
        assert approver.role == "ops_engineer"

    def test_valid_role_with_numbers_accepted(self):
        """Role with numbers must be accepted."""
        approver = Approver(user_id="user@example.com", role="tier_2_support")
        assert approver.role == "tier_2_support"

    def test_uppercase_rejected(self):
        """Uppercase characters must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="Admin")

    def test_mixed_case_rejected(self):
        """Mixed case must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="opsEngineer")

    def test_hyphens_rejected(self):
        """Hyphens must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="ops-engineer")

    def test_spaces_rejected(self):
        """Spaces must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="ops engineer")

    def test_starting_with_number_rejected(self):
        """Role starting with number must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="2nd_tier")

    def test_starting_with_underscore_rejected(self):
        """Role starting with underscore must be rejected."""
        with pytest.raises(ValidationError):
            Approver(user_id="user@example.com", role="_admin")
