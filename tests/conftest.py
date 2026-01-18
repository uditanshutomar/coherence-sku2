"""
Test fixtures.
"""
import pytest
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from coherence.verification import Verifier
from coherence.registry import InMemoryKeyRegistry
from coherence.replay import RedisReplayGuard
from coherence.security import base64url_decode_nopad_strict, base64url_encode_nopad, calculate_digest

# Test Keys (deterministic for reproducibility)
PRIV_KEY = "AjSEN1kUNr43y91Yu15fugJehnN21R35DyaAKlWMlXY"
PUB_KEY = "KvtQBZ-pICIRTQxqmp1clojeJhg6vO0nrpJpVfU90f0"
KID = "test-key-01"

# Vectors directory relative to this file
VECTORS_DIR = Path(__file__).parent.parent / "vectors"

class MockRedis:
    """In-memory mock for Redis replay protection."""
    def __init__(self):
        self.store = {}
    def set(self, key, value, nx=False, ex=0):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

@pytest.fixture
def private_key():
    priv_bytes = base64url_decode_nopad_strict(PRIV_KEY)
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

@pytest.fixture
def public_key():
    pub_bytes = base64url_decode_nopad_strict(PUB_KEY)
    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

@pytest.fixture
def registry(public_key):
    reg = InMemoryKeyRegistry()
    reg.add_key(KID, "tenant-1", "service-a", public_key)
    return reg

@pytest.fixture
def mock_redis():
    return MockRedis()

@pytest.fixture
def replay_guard(mock_redis):
    return RedisReplayGuard(mock_redis)

@pytest.fixture
def verifier(registry, replay_guard):
    return Verifier(registry, replay_guard)

def load_vector(name: str) -> dict:
    """Load a test vector JSON file."""
    with open(VECTORS_DIR / name, "r") as f:
        return json.load(f)

def sign_payload(payload: dict, private_key) -> dict:
    """Sign a payload and return with signature attached."""
    import copy
    r = copy.deepcopy(payload)
    digest = calculate_digest(r)
    sig_bytes = private_key.sign(digest)
    sig_str = base64url_encode_nopad(sig_bytes)
    r["signature"] = {
        "alg": "ed25519-sha256",
        "kid": KID,
        "sig": sig_str
    }
    return r
