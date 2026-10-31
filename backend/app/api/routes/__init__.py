from fastapi import APIRouter
from app.api.routes.health import router as health_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.threat_intel import router as threat_intel_router
from app.api.routes.approvals import router as approvals_router
from app.api.routes.audit_logs import router as audit_logs_router

api_router = APIRouter(prefix="/api")

api_router.include_router(health_router)
api_router.include_router(dashboard_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(threat_intel_router)
api_router.include_router(approvals_router)
api_router.include_router(audit_logs_router)
