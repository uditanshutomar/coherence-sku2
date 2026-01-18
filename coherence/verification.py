from datetime import datetime, timezone
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from coherence.schemas import GateReceipt, DecisionReceipt
from coherence.registry import KeyRegistry, lookup_key_strict, KeyNotFoundError, get_rotation_keys
from coherence.replay import ReplayGuard, calculate_ttl
from coherence.security import (
    base64url_decode_nopad_strict,
    canonicalize_for_signing,
    calculate_digest
)

class Verifier:
    def __init__(self, registry: KeyRegistry, replay_guard: ReplayGuard):
        self.registry = registry
        self.replay_guard = replay_guard

    def verify_gate_receipt(self, receipt_dict: Dict[str, Any], fallback_enabled: bool = False) -> bool:
        """
        Complete verification flow for GateReceipt.
        """
        try:
            # 1. Structural validation (Pydantic)
            try:
                model = GateReceipt.model_validate(receipt_dict) # Strict schema check
            except ValidationError:
                return False

            if receipt_dict.get("version") != "cgr-1.2":
                return False

            # 2. Time window check (exclusive upper bound)
            now_utc = datetime.now(timezone.utc)
            issued_at = datetime.fromisoformat(model.issued_at.replace('Z', '+00:00'))
            expires_at = datetime.fromisoformat(model.expires_at.replace('Z', '+00:00'))

            if not (issued_at <= now_utc < expires_at):
                # Expired or future issued
                return False

            # 3. Signature verification
            if "_verified_key" in receipt_dict:
                 # Optimization/Testing hook if needed, but normally we verify
                 pass
            
            if not self._verify_signature_flow(receipt_dict, fallback_enabled):
                return False

            # 4. Replay check
            ttl = calculate_ttl(model.expires_at)
            # GateReceipt key: replay:{gate_receipt_id}:{decider.nonce}
            if not self.replay_guard.check_and_mark_replay(
                model.gate_receipt_id,
                model.decider.nonce,
                ttl
            ):
                return False

            return True

        except Exception:
            return False

    def verify_decision_receipt(
        self, 
        decision_dict: Dict[str, Any], 
        gate_dict: Dict[str, Any],
        fallback_enabled: bool = False
    ) -> bool:
        """
        Complete verification flow for DecisionReceipt with binding validation.
        """
        try:
            # 1. Structural validation
            try:
                cdr_model = DecisionReceipt.model_validate(decision_dict)
                cgr_model = GateReceipt.model_validate(gate_dict)
            except ValidationError:
                return False
            
            if cdr_model.version != "cdr-1.2":
                return False

            # 2. Time window check
            now_utc = datetime.now(timezone.utc)
            issued_at = datetime.fromisoformat(cdr_model.issued_at.replace('Z', '+00:00'))
            expires_at = datetime.fromisoformat(cdr_model.expires_at.replace('Z', '+00:00'))

            if not (issued_at <= now_utc < expires_at):
                return False

            # 3. Signature verification
            if not self._verify_signature_flow(decision_dict, fallback_enabled):
                return False

            # 4. Replay check (decision uses ID only)
            ttl = calculate_ttl(cdr_model.expires_at)
            if not self.replay_guard.check_and_mark_replay_decision(
                cdr_model.decision_receipt_id,
                ttl
            ):
                return False

            # 5. Binding validation (if APPROVE)
            if cdr_model.decision == "APPROVE":
                # Verify gate_receipt_id reference
                if cdr_model.gate_receipt_id != cgr_model.gate_receipt_id:
                    return False

                # Verify 5-field match (exact paths)
                # Using model fields ensures we are comparing the right things
                if cdr_model.aud != cgr_model.aud: return False
                if cdr_model.tenant_id != cgr_model.tenant_id: return False
                if cdr_model.subject.action_id != cgr_model.subject.action_id: return False
                if cdr_model.subject.action_digest != cgr_model.subject.action_digest: return False
                if cdr_model.policy.policy_digest != cgr_model.policy.policy_digest: return False

            return True

        except Exception:
            return False

    def _verify_signature_flow(self, receipt_dict: Dict[str, Any], fallback_enabled: bool) -> bool:
        """Helper to handle strict lookup + optional fallback."""
        sig_obj = receipt_dict.get("signature", {})
        kid = sig_obj.get("kid")
        if not kid:
            return False
            
        tenant_id = receipt_dict.get("tenant_id")
        aud = receipt_dict.get("aud")

        # 1. Try kid hint first (strict lookup)
        try:
            key = lookup_key_strict(self.registry, kid, tenant_id, aud)
            if self._verify_ed25519(receipt_dict, key):
                return True
        except KeyNotFoundError:
            if not fallback_enabled:
                return False
            # Proceed to fallback

        # 2. Bounded fallback (Rotation Only)
        if fallback_enabled:
            rotation_keys = get_rotation_keys(self.registry, tenant_id, aud)
            for key in rotation_keys:
                if self._verify_ed25519(receipt_dict, key):
                     # In a real app: Log KID_FALLBACK_ACCEPTED
                    return True

        return False

    def _verify_ed25519(self, receipt_dict: Dict[str, Any], key: Ed25519PublicKey) -> bool:
        """Core signature verification using JCS and strict decoding."""
        try:
            sig_obj = receipt_dict["signature"]
            if sig_obj.get("alg") != "ed25519-sha256":
                return False
            
            sig_str = sig_obj.get("sig")
            # Strict decode
            sig_bytes = base64url_decode_nopad_strict(sig_str)
            
            # Check length 64 bytes
            if len(sig_bytes) != 64:
                return False

            # Canonicalize (exclude signature object)
            canonical_bytes = canonicalize_for_signing(receipt_dict)
            
            # SHA256 Digest
            digest = calculate_digest(receipt_dict)
            
            key.verify(sig_bytes, digest)
            return True
        except Exception:
            return False
