import json
import os
import copy
from coherence.security import base64url_decode_nopad_strict
from coherence.registry import InMemoryKeyRegistry
from cli import sign_receipt

# Hardcoded keys (from previous step)
PRIV_KEY = "AjSEN1kUNr43y91Yu15fugJehnN21R35DyaAKlWMlXY"
PUB_KEY = "KvtQBZ-pICIRTQxqmp1clojeJhg6vO0nrpJpVfU90f0"
KID = "test-key-01"

INPUT_DIR = "sku2_cdp/vectors"
OUTPUT_DIR = "sku2_cdp/vectors"

def main():
    # 1. Sign Valid CGR
    print("Generating valid_gate_receipt.json...")
    with open(f"{INPUT_DIR}/unsigned_cgr.json", "r") as f:
        cgr = json.load(f)
    
    from coherence.security import canonicalize_for_signing, calculate_digest, base64url_encode_nopad
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    priv_bytes = base64url_decode_nopad_strict(PRIV_KEY)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    def sign(receipt):
        r = copy.deepcopy(receipt)
        digest = calculate_digest(r)
        sig_bytes = private_key.sign(digest)
        sig_str = base64url_encode_nopad(sig_bytes)
        r["signature"] = {
            "alg": "ed25519-sha256",
            "kid": KID,
            "sig": sig_str
        }
        return r

    valid_cgr = sign(cgr)
    with open(f"{OUTPUT_DIR}/valid_gate_receipt.json", "w") as f:
        json.dump(valid_cgr, f, indent=2)

    # 2. Sign Valid CDR
    print("Generating valid_decision_receipt.json...")
    with open(f"{INPUT_DIR}/unsigned_cdr.json", "r") as f:
        cdr = json.load(f)
    valid_cdr = sign(cdr)
    with open(f"{OUTPUT_DIR}/valid_decision_receipt.json", "w") as f:
        json.dump(valid_cdr, f, indent=2)

    # 3. Invalid Signature CGR
    print("Generating invalid_sig_gate_receipt.json...")
    inv_sig = copy.deepcopy(valid_cgr)
    # Mutate FIRST char of signature to guarantee byte change
    orig_sig = inv_sig["signature"]["sig"]
    new_sig = ('A' if orig_sig[0] != 'A' else 'B') + orig_sig[1:]
    inv_sig["signature"]["sig"] = new_sig
    with open(f"{OUTPUT_DIR}/invalid_sig_gate_receipt.json", "w") as f:
        json.dump(inv_sig, f, indent=2)

    # 4. Invalid Algo CGR
    print("Generating invalid_algo_gate_receipt.json...")
    inv_algo = copy.deepcopy(valid_cgr)
    inv_algo["signature"]["alg"] = "rs256" # Wrong algo
    with open(f"{OUTPUT_DIR}/invalid_algo_gate_receipt.json", "w") as f:
        json.dump(inv_algo, f, indent=2)

    # 5. Invalid Payload CGR (Tampered)
    print("Generating invalid_payload_gate_receipt.json...")
    inv_pay = copy.deepcopy(valid_cgr)
    inv_pay["verdict"] = "STOP" # Was ADMIT, but signature is for ADMIT
    # Keep signature same -> verification should fail
    with open(f"{OUTPUT_DIR}/invalid_payload_gate_receipt.json", "w") as f:
        json.dump(inv_pay, f, indent=2)

    # 6. Invalid Binding CDR
    print("Generating invalid_binding_decision_receipt.json...")
    inv_binding = copy.deepcopy(valid_cdr)
    inv_binding["gate_receipt_id"] = "cgr-other-id" # Mismatch
    # Signature is valid for THIS json, but binding logic checks against CGR
    inv_binding_signed = sign(inv_binding)
    with open(f"{OUTPUT_DIR}/invalid_binding_decision_receipt.json", "w") as f:
        json.dump(inv_binding_signed, f, indent=2)

if __name__ == "__main__":
    main()
