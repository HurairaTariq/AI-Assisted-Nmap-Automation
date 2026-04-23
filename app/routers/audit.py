from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List
from app.database import get_db
from app.models import AuditLog, AuditLogEntry, User
from app.routers.auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[AuditLogEntry])
async def get_audit_logs(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current user's audit history, newest first."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .order_by(desc(AuditLog.created_at))
        .offset(skip)
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        AuditLogEntry(
            id=str(l.id),
            nl_query=l.nl_query,
            validation_pass=l.validation_pass,
            rejection_reason=l.rejection_reason,
            nmap_command=l.nmap_command,
            gpt_summary=l.gpt_summary,
            created_at=l.created_at,
        )
        for l in logs
    ]

@router.get("/{scan_id}")
async def get_audit_entry(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the full audit entry for a single scan, including raw XML."""
    result = await db.execute(
        select(AuditLog).where(
            AuditLog.id == scan_id,
            AuditLog.user_id == current_user.id,
        )
    )
    log = result.scalar_one_or_none()
    if not log:
        from fastapi import HTTPException
        raise HTTPException(404, "Audit entry not found")

    return {
        "id":               str(log.id),
        "nl_query":         log.nl_query,
        "gpt_proposal":     log.gpt_proposal,
        "validation_pass":  log.validation_pass,
        "rejection_reason": log.rejection_reason,
        "nmap_command":     log.nmap_command,
        "scan_start":       log.scan_start,
        "scan_end":         log.scan_end,
        "gpt_summary":      log.gpt_summary,
        "nmap_xml":         log.nmap_xml,
        "created_at":       log.created_at,
    }