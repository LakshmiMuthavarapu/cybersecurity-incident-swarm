from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer
from datetime import datetime, timezone
from app.database import Base

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(String, primary_key=True, index=True)
    indicator_type = Column(String, nullable=False, index=True)  # IP, DOMAIN, MD5, SHA256, URL, CVE
    value = Column(String, nullable=False, index=True, unique=True)
    reputation = Column(String, nullable=False, index=True)  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    threat_actor = Column(String, nullable=True, index=True)
    confidence = Column(Integer, default=80)  # 0 to 100
    verification_status = Column(String, default="UNVERIFIED", index=True)  # VERIFIED, UNVERIFIED, PENDING_REVIEW, DISPROVEN
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tags = Column(Text, nullable=False)  # JSON-serialized list of tags
    description = Column(Text, nullable=False)
    is_simulated = Column(Boolean, default=True, nullable=False)
