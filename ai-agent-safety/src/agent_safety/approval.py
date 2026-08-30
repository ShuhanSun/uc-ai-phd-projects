"""Short-lived, request-bound human approval tokens."""

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from dataclasses import asdict, dataclass

from .models import ToolRequest


@dataclass(frozen=True)
class ApprovalClaims:
    session_id: str
    request_digest: str
    expires_at: int
    nonce: str


class ApprovalAuthority:
    """Issue and consume HMAC-authenticated approvals with replay protection."""

    def __init__(self, secret: bytes, clock=time.time) -> None:
        if len(secret) < 32:
            raise ValueError("approval secret must contain at least 32 bytes")
        self._secret = secret
        self._clock = clock
        self._consumed: set[str] = set()

    def issue(
        self,
        request: ToolRequest,
        session_id: str,
        nonce: str,
        ttl_seconds: int = 300,
    ) -> str:
        if not nonce or ttl_seconds < 1:
            raise ValueError("nonce must be non-empty and ttl_seconds must be positive")
        claims = ApprovalClaims(
            session_id=session_id,
            request_digest=request_digest(request),
            expires_at=int(self._clock()) + ttl_seconds,
            nonce=nonce,
        )
        payload = json.dumps(asdict(claims), sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.digest(self._secret, payload, "sha256")
        return f"{_encode(payload)}.{_encode(signature)}"

    def consume(
        self, token: str, request: ToolRequest, session_id: str
    ) -> tuple[bool, str]:
        token_id = hashlib.sha256(token.encode()).hexdigest()
        if token_id in self._consumed:
            return False, "approval token was already used"
        try:
            payload_part, signature_part = token.split(".", 1)
            payload = _decode(payload_part)
            signature = _decode(signature_part)
            expected = hmac.digest(self._secret, payload, "sha256")
            if not hmac.compare_digest(signature, expected):
                return False, "approval token signature is invalid"
            claims = ApprovalClaims(**json.loads(payload))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, BinasciiError):
            return False, "approval token is malformed"

        if claims.expires_at < int(self._clock()):
            return False, "approval token has expired"
        if claims.session_id != session_id or claims.request_digest != request_digest(request):
            return False, "approval token does not match this request"
        self._consumed.add(token_id)
        return True, "human approval verified"


def request_digest(request: ToolRequest) -> str:
    canonical = json.dumps(
        {"tool": request.tool, "arguments": request.arguments},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))
