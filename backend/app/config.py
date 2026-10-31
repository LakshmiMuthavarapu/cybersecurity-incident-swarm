from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List, Union
import json

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "Cybersecurity Incident Investigation Swarm"
    VERSION: str = "1.0.0-phase1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./cyber_swarm.db"
    
    # Guardrails: strictly simulate actions, never alter real systems
    SIMULATION_MODE: bool = True
    ALLOW_REAL_SYSTEM_CHANGES: bool = False
    
    # Future Agent & Provider Configuration
    GEMINI_API_KEY: str = "placeholder-gemini-key"
    LLM_MODEL: str = "gemini-2.0-flash"
    AGENT_MAX_ITERATIONS: int = 10
    
    # CORS
    CORS_ORIGINS: Union[str, List[str]] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]
    
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    @field_validator("CORS_ORIGINS", mode="before")
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            if v.startswith("["):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

settings = Settings()
