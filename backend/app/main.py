from fastapi import FastAPI
from app.api.auth import router as auth_router
from app.api.session import router as session_router
from app.api.organizations import router as organizations_router
from app.api.membership_management import router as membership_management_router
from app.api.membership_revocation import router as membership_revocation_router
from app.api.health import router as health_router


def create_app() -> FastAPI:
    api = FastAPI(
        title="PayFlow OS API",
        description="PayFlow payment infrastructure services",
        version="0.1.0",
    )

    @api.get("/api/v1/health/live", tags=["Health"])
    def liveness() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "payflow-api",
        }

    api.include_router(health_router)
    api.include_router(auth_router)
    api.include_router(session_router)
    api.include_router(organizations_router)
    api.include_router(membership_management_router)
    api.include_router(membership_revocation_router)

    return api


app = create_app()

from app.core.origin_guard import UnsafeOriginGuard
app.add_middleware(UnsafeOriginGuard)

# Added last, so CORS processes browser preflight requests
# before the existing origin guard.
from fastapi.middleware.cors import CORSMiddleware
from app.core.browser_cors import browser_cors_options

app.add_middleware(
    CORSMiddleware,
    **browser_cors_options(),
)

# Validate new audit payloads before ORM flush.
from app.services.audit_integrity import register_audit_guard
register_audit_guard()

# Prelaunch release gate: development remains available,
# nondevelopment APIs stay closed until release approval.
from app.core.release_gate import (
    PrelaunchReleaseGate,
    validate_deployment_configuration,
)
from app.core.config import get_settings as release_settings

validate_deployment_configuration(release_settings())
app.add_middleware(PrelaunchReleaseGate)
