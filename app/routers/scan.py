"""
POST /api/v1/scan/
The main pipeline endpoint:
  1. Authenticate user
  2. Rate limit check
  3. GPT-4.1 → MCP tool proposal
  4. Validation engine
  5. Docker sandbox execution
  6. Output parsing + GPT-4.1 summarisation
  7. Audit log write
  8. Return structured response
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
import uuid
from app.models import AllowlistUpdate

from app.database import get_db
from app.models import AuditLog, ScanRequest, ScanResponse, User
from app.routers.auth import get_current_user
from app.gpt_service import get_tool_proposal, summarise_results
from app.validation import validate
from app.docker_sandbox import run_nmap_in_sandbox
from app.output_parser import parse_nmap_xml
from app.config import settings

router = APIRouter()


async def _check_rate_limit(user: User, db: AsyncSession):
    """Reject if user has exceeded MAX_SCANS_PER_HOUR."""
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    result = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.user_id == user.id,
            AuditLog.created_at >= one_hour_ago,
            AuditLog.validation_pass == True,
        )
    )
    count = result.scalar()
    if count >= settings.MAX_SCANS_PER_HOUR:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {settings.MAX_SCANS_PER_HOUR} scans per hour.",
        )


@router.post("/", response_model=ScanResponse)
async def run_scan(
    payload: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    raw_allowlist = current_user.allowlist or []

    if isinstance(raw_allowlist, str):
        user_allowlist = [t.strip() for t in raw_allowlist.split(",") if t.strip()]
    elif isinstance(raw_allowlist, list):
        user_allowlist = [str(t).strip() for t in raw_allowlist if str(t).strip()]
    else:
        user_allowlist = []

    
    await _check_rate_limit(current_user, db)

    # MCP tool proposal
    proposal = await get_tool_proposal(payload.query)
    print("PROPOSAL:...", proposal)

    if "error" in proposal:
        log = AuditLog(
            id=uuid.UUID(scan_id),
            user_id=current_user.id,
            nl_query=payload.query,
            gpt_proposal=proposal,
            validation_pass=False,
            rejection_reason=proposal.get("reason", "GPT-4.1 returned no valid tool call"),
        )
        db.add(log)
        await db.commit()
        return ScanResponse(
            scan_id=scan_id,
            status="rejected",
            rejection=proposal.get("reason"),
        )

    tool_name = proposal["tool_name"]
    params    = proposal["params"]

    # Validation engine
    v_result = validate(tool_name, params, user_allowlist)

    if not v_result.passed:
        log = AuditLog(
            id=uuid.UUID(scan_id),
            user_id=current_user.id,
            nl_query=payload.query,
            gpt_proposal=proposal,
            validation_pass=False,
            rejection_reason=v_result.reason,
        )
        db.add(log)
        await db.commit()
        return ScanResponse(
            scan_id=scan_id,
            status="rejected",
            rejection=v_result.reason,
        )

    nmap_cmd = v_result.nmap_command

    # Docker sandbox execution
    exec_result = await run_nmap_in_sandbox(nmap_cmd)

    if exec_result.timed_out:
        log = AuditLog(
            id=uuid.UUID(scan_id),
            user_id=current_user.id,
            nl_query=payload.query,
            gpt_proposal=proposal,
            validation_pass=True,
            nmap_command=nmap_cmd,
            scan_start=exec_result.start_time,
            scan_end=exec_result.end_time,
            gpt_summary="Scan timed out after 120 seconds.",
        )
        db.add(log)
        await db.commit()
        return ScanResponse(
            scan_id=scan_id,
            status="error",
            nmap_command=nmap_cmd,
            summary="The scan timed out. Try a smaller port range or target.",
        )

    # Parse XML
    findings = parse_nmap_xml(exec_result.xml_output)

    # summarisation 
    summary = ""
    if findings:
        summary = await summarise_results(findings)

    duration_ms = int(
        (exec_result.end_time - exec_result.start_time).total_seconds() * 1000
    )

    # Audit log
    log = AuditLog(
        id=uuid.UUID(scan_id),
        user_id=current_user.id,
        nl_query=payload.query,
        gpt_proposal=proposal,
        validation_pass=True,
        nmap_command=nmap_cmd,
        scan_start=exec_result.start_time,
        scan_end=exec_result.end_time,
        nmap_xml=exec_result.xml_output,
        gpt_summary=summary,
    )
    db.add(log)
    await db.commit()

    return ScanResponse(
        scan_id=scan_id,
        status="completed" if exec_result.success else "error",
        nmap_command=nmap_cmd,
        summary=summary or exec_result.stderr,
        findings=findings,
        duration_ms=duration_ms,
    )


@router.post("/allowlist")
async def update_allowlist(
    payload: AllowlistUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_user.allowlist = [t.strip() for t in payload.targets if t.strip()]
    await db.commit()
    return {
        "message": "Allowlist updated",
        "targets": current_user.allowlist
    }