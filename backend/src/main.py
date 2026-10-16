

# backend/src/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.src.api.routes import (
    auth,
)
from backend.src.config.settings import Settings

app = FastAPI(title="Tetracore Log", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=Settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def serve() -> None:
    """tetracore-log api. Add --reload for development."""
    import sys

    import uvicorn

    uvicorn.run("backend.src.main:app", host="127.0.0.1", port=8000,
                reload="--reload" in sys.argv)
