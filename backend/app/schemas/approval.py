from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime
from typing import Literal, Optional

class ApprovalDecisionRequest(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    analyst_name: str = Field(default="Analyst Alex Rivera", min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("analyst_name", "reason")
    @classmethod
    def require_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Must not be blank")
        return value

class ApprovalResponse(BaseModel):
    id: str
    incident_id: str
    action_type: str
    target: str
    description: str
    rationale: str
    risk_level: str
    proposed_by: str
    status: str
    created_at: datetime
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    simulation_execution_notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
