from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.database import engine, Base
import app.models  # Ensure all models are registered
from app.api.routes import api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables exist at startup
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=(
        "Multi-Agent Cybersecurity Incident Investigation Swarm API (Phase 1). "
        "Engineered for SOC telemetry triage, automated deterministic correlation, "
        "and human-in-the-loop containment approvals in a synthetic simulation environment."
    ),
    lifespan=lifespan,
)

# CORS Middleware
cors_origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/")
def root():
    return {
        "system": settings.APP_NAME,
        "version": settings.VERSION,
        "environment": "SIMULATION_LAB",
        "simulation_mode": settings.SIMULATION_MODE,
        "docs_url": "/docs",
        "api_prefix": "/api",
        "message": "Cybersecurity Incident Investigation Swarm API is operational."
    }
