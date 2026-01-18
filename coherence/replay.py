from abc import ABC, abstractmethod
from datetime import datetime, timezone
import redis

class ReplayGuard(ABC):
    @abstractmethod
    def check_and_mark_replay(self, receipt_id: str, nonce: str, ttl_seconds: int) -> bool:
        """Returns True if allowed (first time), False if replay."""
        pass

    @abstractmethod
    def check_and_mark_replay_decision(self, decision_receipt_id: str, ttl_seconds: int) -> bool:
        """Returns True if allowed (first time), False if replay."""
        pass

class RedisReplayGuard(ReplayGuard):
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def check_and_mark_replay(self, receipt_id: str, nonce: str, ttl_seconds: int) -> bool:
        key = f"replay:{receipt_id}:{nonce}"
        # SET NX (set if not exists) with expiry
        # Redis set returns True if set happened, None if not
        if ttl_seconds <= 0:
            return False # Expired or invalid TTL
            
        result = self.redis.set(key, "1", nx=True, ex=ttl_seconds)
        return result is not None

    def check_and_mark_replay_decision(self, decision_receipt_id: str, ttl_seconds: int) -> bool:
        key = f"replay_decision:{decision_receipt_id}"
        if ttl_seconds <= 0:
            return False
            
        result = self.redis.set(key, "1", nx=True, ex=ttl_seconds)
        return result is not None

def calculate_ttl(expires_at_str: str) -> int:
    """
    Calculate TTL in seconds from expires_at timestamp.
    Time window uses exclusive upper bound: issued_at <= now_utc < expires_at
    """
    expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
    now_utc = datetime.now(timezone.utc)
    delta_seconds = int((expires_at - now_utc).total_seconds())
    return max(0, delta_seconds)
