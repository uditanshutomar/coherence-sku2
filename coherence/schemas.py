import re
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator

# Regex Patterns
TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
ROLE_PATTERN = r"^[a-z][a-z0-9_]*(_[a-z0-9_]+)*$"
NONCE_PATTERN = r"^[A-Za-z0-9_-]{22}$"
SIG_PATTERN = r"^[A-Za-z0-9_-]{86}$"

class Signature(BaseModel, extra="forbid"):
    alg: Literal["ed25519-sha256"]
    kid: str
    sig: str = Field(pattern=SIG_PATTERN)

class Subject(BaseModel, extra="forbid"):
    action_id: str
    action_digest: str = Field(pattern=DIGEST_PATTERN)

class PolicyCGR(BaseModel, extra="forbid"):
    policy_id: str
    policy_digest: str = Field(pattern=DIGEST_PATTERN)

class Decider(BaseModel, extra="forbid"):
    identity: str
    version: str
    nonce: str = Field(pattern=NONCE_PATTERN)

class GateReceipt(BaseModel, extra="forbid"):
    version: Literal["cgr-1.2"]
    gate_receipt_id: str
    verdict: Literal["ADMIT", "ESCALATE", "STOP"]
    aud: str
    tenant_id: str
    subject: Subject
    policy: PolicyCGR
    decider: Decider
    issued_at: str = Field(pattern=TIMESTAMP_PATTERN)
    expires_at: str = Field(pattern=TIMESTAMP_PATTERN)
    signature: Signature

class PolicyCDR(BaseModel, extra="forbid"):
    policy_digest: str = Field(pattern=DIGEST_PATTERN)

class Approver(BaseModel, extra="forbid"):
    user_id: str
    role: str = Field(pattern=ROLE_PATTERN)

class DecisionReceipt(BaseModel, extra="forbid"):
    version: Literal["cdr-1.2"]
    decision_receipt_id: str
    gate_receipt_id: str
    aud: str
    tenant_id: str
    subject: Subject
    policy: PolicyCDR
    decision: Literal["ADMIT", "ESCALATE", "STOP"]
    approver: Approver
    rationale: Optional[str] = None
    issued_at: str = Field(pattern=TIMESTAMP_PATTERN)
    expires_at: str = Field(pattern=TIMESTAMP_PATTERN)
    signature: Signature
