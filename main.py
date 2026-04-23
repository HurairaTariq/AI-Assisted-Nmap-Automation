from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database import init_db
from app.routers import auth, scan, audit, health

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="AI Assisted Nmap Automation (MCP + GPT-4.1)",
    description="Secure natural language to Nmap command platform using MCP and GPT-4.1",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(auth.router,   prefix="/api/v1/auth", tags=["Auth"])
app.include_router(scan.router,   prefix="/api/v1/scan", tags=["Scan"])
app.include_router(audit.router,  prefix="/api/v1/audit", tags=["Audit"])