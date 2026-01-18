from abc import ABC, abstractmethod
from typing import Optional, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class KeyRegistry(ABC):
    """Registry interface for kid lookup."""
    
    @abstractmethod
    def get_key(self, kid: str, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        """Get specific key by kid (strict)."""
        pass

    @abstractmethod
    def get_active_key(self, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        """Get current active signing key for tenant."""
        pass

    @abstractmethod
    def get_previous_key(self, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        """Get previous signing key for tenant (rotation support)."""
        pass

class InMemoryKeyRegistry(KeyRegistry):
    """Simple in-memory registry for testing."""
    
    def __init__(self):
        self._keys = {} # (tenant, aud, kid) -> key
        self._active = {} # (tenant, aud) -> kid
        self._previous = {} # (tenant, aud) -> kid

    def add_key(self, kid: str, tenant_id: str, aud: str, key: Ed25519PublicKey):
        self._keys[(tenant_id, aud, kid)] = key

    def set_active(self, tenant_id: str, aud: str, kid: str):
        self._active[(tenant_id, aud)] = kid
    
    def set_previous(self, tenant_id: str, aud: str, kid: str):
        self._previous[(tenant_id, aud)] = kid

    def get_key(self, kid: str, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        return self._keys.get((tenant_id, aud, kid))

    def get_active_key(self, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        kid = self._active.get((tenant_id, aud))
        if kid:
            return self.get_key(kid, tenant_id, aud)
        return None

    def get_previous_key(self, tenant_id: str, aud: str) -> Optional[Ed25519PublicKey]:
        kid = self._previous.get((tenant_id, aud))
        if kid:
            return self.get_key(kid, tenant_id, aud)
        return None

class KeyNotFoundError(Exception):
    pass

def lookup_key_strict(registry: KeyRegistry, kid: str, tenant_id: str, aud: str) -> Ed25519PublicKey:
    """
    Lookup public key by key identifier (strict mode).
    Raises KeyNotFoundError if kid unknown.
    """
    key = registry.get_key(kid, tenant_id=tenant_id, aud=aud)
    if key is None:
        # In a real app, log telemetry here
        raise KeyNotFoundError(f"kid {kid} unknown or revoked")
    return key

def get_rotation_keys(registry: KeyRegistry, tenant_id: str, aud: str) -> List[Ed25519PublicKey]:
    """Get registry-approved rotation keys (active + previous only)."""
    keys = []
    active = registry.get_active_key(tenant_id, aud)
    if active:
        keys.append(active)
    
    previous = registry.get_previous_key(tenant_id, aud)
    if previous:
        keys.append(previous)
    
    return keys[:2]
