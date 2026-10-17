

# backend/src/main.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.src.api.routes import admin, auth, super_admin
from backend.src.config.settings import Settings
from backend.src.exceptions.errors import (
    AccountLockedError,
    AuthError,
    ConflictError,
    DomainError,
    MustChangePinError,
    NotFoundError,
    PermissionDeniedError,
    WeakPinError,
)

app = FastAPI(title="Tetracore Log", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=Settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(super_admin.router, prefix="/api")

STATUS_CODE_MAP: dict[type[DomainError], int] = {
    PermissionDeniedError: 403,
    MustChangePinError: 403,
    AccountLockedError: 429,
    AuthError: 401,
    NotFoundError: 404,
    ConflictError: 409,
    WeakPinError: 422,

}


def _status_for(exc: DomainError) -> int:
    return STATUS_CODE_MAP.get(type(exc)) or 400


@app.exception_handler(DomainError)
def domain_error_handler(_request: Request, exc: DomainError) -> JSONResponse:
    headers = None
    if isinstance(exc, AccountLockedError):
        headers = {"Retry-After": str(exc.retry_after_seconds)}
    return JSONResponse(
        status_code=_status_for(exc),
        content={"detail": {"code": exc.code, "message": exc.message}},
        headers=headers,
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def serve() -> None:
    """tetracore-log api. Add --reload for development."""
    import sys

    import uvicorn

    uvicorn.run("backend.src.main:app", host="127.0.0.1", port=8000,
                reload="--reload" in sys.argv)
