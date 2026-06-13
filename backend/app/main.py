"""
DeepTrace — FastAPI Backend
Run: cd DeepTrace/backend && uvicorn app.main:app --reload --port 8000
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from loguru import logger

from app.api.routes import router
from app.models.loader import ModelLoader


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DeepTrace starting — loading models...")
    ModelLoader.initialize()
    logger.info(f"Status: {ModelLoader.status()}")
    yield
    logger.info("DeepTrace shutting down.")


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="DeepTrace API",
    version="1.0.0",
    description="Phishing URL · Scam Text · AI Content Detection",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok", "models": ModelLoader.status()}


@app.get("/")
async def root():
    return {"message": "DeepTrace API running. Visit /docs for interactive docs."}
