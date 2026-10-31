from pydantic import BaseModel, ConfigDict
from datetime import datetime

class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    action: str
    target_type: str
    target_id: str
    details: str
    client_ip: str
    is_simulated: bool

    model_config = ConfigDict(from_attributes=True)
