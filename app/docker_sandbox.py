"""
Per-request Docker sandbox executor.
Each scan gets a fresh Kali Linux container that is destroyed after execution.
No state persists between scans.
"""

import asyncio
import docker
import docker.errors
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from app.config import settings

_docker_client = docker.from_env()


@dataclass
class ExecutionResult:
    success:   bool
    xml_output: Optional[str]
    stderr:     Optional[str]
    exit_code:  int
    start_time: datetime
    end_time:   datetime
    timed_out:  bool = False


async def run_nmap_in_sandbox(nmap_command: str) -> ExecutionResult:
    """
    Spin up a hardened Kali container, execute the sanitised Nmap command,
    capture XML output, then destroy the container — all in one call.
    """
    start = datetime.utcnow()

    # Container security configuration
    container_config = dict(
        image=settings.DOCKER_KALI_IMAGE,
        command=nmap_command,
        detach=True,
        network_mode="bridge",

        # Filesystem isolation
        read_only=True,
        tmpfs={"/tmp": "size=64m,mode=1777"},

        # Resource limits
        mem_limit=settings.DOCKER_MEM_LIMIT,
        cpu_quota=settings.DOCKER_CPU_QUOTA,
        cpu_period=100000,

        # Drop all capabilities, add only what Nmap requires
        cap_drop=["ALL"],
        cap_add=["NET_RAW", "NET_BIND_SERVICE"],

        # No privilege escalation
        security_opt=["no-new-privileges:true"],

        # No persistent storage
        auto_remove=False,  # we remove manually after capturing output
    )

    container = None
    xml_out   = None
    stderr    = None
    exit_code = -1
    timed_out = False

    try:
        # Run in thread pool — docker-py is synchronous
        loop = asyncio.get_event_loop()
        container = await loop.run_in_executor(
            None,
            lambda: _docker_client.containers.run(**container_config)
        )

        # Wait with hard timeout
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: container.wait()),
                timeout=settings.DOCKER_SCAN_TIMEOUT,
            )
            exit_code = result.get("StatusCode", -1)
        except asyncio.TimeoutError:
            timed_out = True
            exit_code = -1
            try:
                await loop.run_in_executor(None, container.kill)
            except Exception:
                pass

        # Capture logs regardless of timeout
        raw_logs = await loop.run_in_executor(
            None,
            lambda: container.logs(stdout=True, stderr=True)
        )

        # Nmap -oX - writes XML to stdout, errors to stderr
        # Docker merges them; we split by XML declaration
        raw_str = raw_logs.decode("utf-8", errors="replace")
        if "<?xml" in raw_str:
            xml_start = raw_str.index("<?xml")
            xml_out = raw_str[xml_start:]
            stderr  = raw_str[:xml_start].strip() or None
        else:
            stderr  = raw_str.strip() or None

    except docker.errors.ImageNotFound:
        stderr = f"Docker image '{settings.DOCKER_KALI_IMAGE}' not found. Run: docker pull {settings.DOCKER_KALI_IMAGE}"
    except docker.errors.APIError as e:
        stderr = f"Docker API error: {str(e)}"
    finally:
        # Always destroy the container
        if container:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: container.remove(force=True))
            except Exception:
                pass

    end = datetime.utcnow()
    return ExecutionResult(
        success=exit_code == 0 and xml_out is not None,
        xml_output=xml_out,
        stderr=stderr,
        exit_code=exit_code,
        start_time=start,
        end_time=end,
        timed_out=timed_out,
    )