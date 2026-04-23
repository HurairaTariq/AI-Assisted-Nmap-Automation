from fastapi import APIRouter
import docker

router = APIRouter()

@router.get("/health")
async def health():
    docker_ok = False
    try:
        client = docker.from_env()
        client.ping()
        docker_ok = True
    except Exception:
        pass

    return {
        "status":  "ok",
        "docker":  "connected" if docker_ok else "unavailable",
        "version": "1.0.0",
    }