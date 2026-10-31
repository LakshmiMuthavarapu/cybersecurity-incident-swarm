from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime
from typing import Literal, Optional, List

class ThreatIndicatorBase(BaseModel):
    indicator_type: Literal["IP", "DOMAIN", "MD5", "SHA256", "URL", "CVE"]
    value: str = Field(min_length=1, max_length=500)
    reputation: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"]
    threat_actor: Optional[str] = Field(default=None, max_length=200)
    confidence: int = Field(default=80, ge=0, le=100)
    verification_status: Literal["VERIFIED", "UNVERIFIED", "PENDING_REVIEW", "DISPROVEN"] = "UNVERIFIED"
    description: str = Field(min_length=1, max_length=2000)
    is_simulated: bool = True

    @field_validator("value", "description")
    @classmethod
    def require_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Must not be blank")
        return value

class ThreatIndicatorCreate(ThreatIndicatorBase):
    id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class ThreatIndicatorUpdate(BaseModel):
    verification_status: Optional[Literal["VERIFIED", "UNVERIFIED", "PENDING_REVIEW", "DISPROVEN"]] = None
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    reputation: Optional[Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"]] = None
    notes: Optional[str] = None

class ThreatIndicatorResponse(ThreatIndicatorBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]

    model_config = ConfigDict(from_attributes=True)
