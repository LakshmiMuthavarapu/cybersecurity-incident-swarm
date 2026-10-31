from abc import ABC, abstractmethod
from typing import Dict, Any
from app.agents.state import InvestigationGraphState

class BaseSecurityAgent(ABC):
    """Abstract base class for all cybersecurity investigation agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    @abstractmethod
    def run(self, state: InvestigationGraphState) -> InvestigationGraphState:
        """Processes the investigation state and returns updated state."""
        pass
