import base64
import re
import jcs
import hashlib
from typing import Dict, Any

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

def base64url_decode_nopad_strict(s: str) -> bytes:
    """Strict base64url decoder with character validation."""
    if not isinstance(s, str) or not s or not _B64URL_RE.match(s):
        raise ValueError("BAD_B64URL_CHARS")

    # Add padding to multiple of 4
    pad = (-len(s)) % 4
    s_padded = s + ("=" * pad)

    # Strict decode with altchars
    return base64.b64decode(s_padded, altchars=b"-_", validate=True)

def base64url_encode_nopad(data: bytes) -> str:
    """Encodes bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def canonicalize_for_signing(receipt: Dict[str, Any]) -> bytes:
    """
    Canonicalizes receipt using RFC 8785 JCS, EXCLUDING the signature object.
    """
    # Create copy to avoid mutating original
    data = receipt.copy()
    if "signature" in data:
        del data["signature"]
    
    return jcs.canonicalize(data)

def calculate_digest(receipt: Dict[str, Any]) -> bytes:
    """Calculates SHA256 digest of JCS canonicalized payload (minus signature)."""
    canonical_bytes = canonicalize_for_signing(receipt)
    return hashlib.sha256(canonical_bytes).digest()
