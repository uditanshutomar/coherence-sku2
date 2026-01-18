import argparse
import json
import sys
import base64
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from coherence.security import (
    base64url_encode_nopad,
    calculate_digest,
    base64url_decode_nopad_strict
)
from coherence.registry import InMemoryKeyRegistry
from coherence.verification import Verifier
from coherence.replay import RedisReplayGuard

class MockRedis:
    def __init__(self):
        self.store = {}
    def set(self, key, value, nx=False, ex=0):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    print(f"Private (b64url): {base64url_encode_nopad(priv_bytes)}")
    print(f"Public (b64url):  {base64url_encode_nopad(pub_bytes)}")

def sign_receipt(json_path: str, private_key_b64: str, kid: str):
    with open(json_path, 'r') as f:
        receipt = json.load(f)
    
    # Decode private key
    priv_bytes = base64url_decode_nopad_strict(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    
    # Calculate digest (JCS + SHA256)
    digest = calculate_digest(receipt)
    
    # Sign digest
    sig_bytes = private_key.sign(digest) # Ed25519 sign
    sig_str = base64url_encode_nopad(sig_bytes)
    
    # Construct signature object
    sig_obj = {
        "alg": "ed25519-sha256",
        "kid": kid,
        "sig": sig_str
    }
    
    receipt["signature"] = sig_obj
    print(json.dumps(receipt, indent=2))

def verify_receipt(json_path: str, public_key_b64: str):
    with open(json_path, 'r') as f:
        receipt = json.load(f)
        
    pub_bytes = base64url_decode_nopad_strict(public_key_b64)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    
    registry = InMemoryKeyRegistry()
    # Pre-populate registry with the provided key for the kid in receipt
    kid = receipt.get("signature", {}).get("kid")
    if kid:
        registry.add_key(kid, receipt.get("tenant_id"), receipt.get("aud"), public_key)
    
    verifier = Verifier(registry, RedisReplayGuard(MockRedis()))
    
    if "decision_receipt_id" in receipt:
        print("CDR verification requires CGR. Skipping binding check.")
        valid = verifier.verify_decision_receipt(receipt, {}, fallback_enabled=False)
    else:
        valid = verifier.verify_gate_receipt(receipt, fallback_enabled=False)
        
    if valid:
        print("VERIFIED: OK")
        sys.exit(0)
    else:
        print("VERIFICATION FAILED")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Coherence CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("keygen")
    
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("file", help="Input JSON file")
    sign_parser.add_argument("--key", required=True, help="Private key (base64url)")
    sign_parser.add_argument("--kid", required=True, help="Key ID")
    
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("file", help="Receipt JSON file")
    verify_parser.add_argument("--pub", required=True, help="Public key (base64url)")
    
    args = parser.parse_args()
    
    if args.command == "keygen":
        generate_keypair()
    elif args.command == "sign":
        sign_receipt(args.file, args.key, args.kid)
    elif args.command == "verify":
        verify_receipt(args.file, args.pub)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
