from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Literal, Optional, List

class AlertBase(BaseModel):
    title: str
    source: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    status: Literal["NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"] = "NEW"
    category: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    description: str
    raw_payload: Optional[str] = None
    incident_id: Optional[str] = None
    is_simulated: bool = True

class AlertCreate(AlertBase):
    id: Optional[str] = None

class AlertUpdate(BaseModel):
    status: Optional[Literal["NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"]] = None
    incident_id: Optional[str] = None
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]] = None

class AlertResponse(AlertBase):
    id: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertListResponse(BaseModel):
    total: int
    items: List[AlertResponse]
