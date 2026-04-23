from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, JSON, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from typing import Optional, List, Any
from enum import Enum
import uuid

Base = declarative_base()


# SQLAlchemy ORM Models

class User(Base):
    __tablename__ = "users"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username   = Column(String(64), unique=True, nullable=False, index=True)
    email      = Column(String(128), unique=True, nullable=False, index=True)
    hashed_pw  = Column(String(256), nullable=False)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    allowlist  = Column(JSON, default=list)

    __table_args__ = (
        CheckConstraint("email LIKE '%@%.%'", name="valid_email_check"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id         = Column(UUID(as_uuid=True), nullable=False)
    nl_query        = Column(Text, nullable=False)
    gpt_proposal    = Column(JSON, nullable=True)   # raw function-call JSON from GPT-4.1
    validation_pass = Column(Boolean, nullable=False)
    rejection_reason= Column(Text, nullable=True)
    nmap_command    = Column(Text, nullable=True)
    scan_start      = Column(DateTime, nullable=True)
    scan_end        = Column(DateTime, nullable=True)
    nmap_xml        = Column(Text, nullable=True)
    gpt_summary     = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

# Pydantic Schemas

class ScanType(str, Enum):
    syn       = "syn"
    connect   = "connect"

class TimingTemplate(str, Enum):
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"

# What GPT-4.1 returns via function calling (matches MCP tool schemas)
class PortScanParams(BaseModel):
    target:    str
    ports:     str
    scan_type: ScanType
    timing:    TimingTemplate = TimingTemplate.T3

class ServiceDetectParams(BaseModel):
    target:    str
    ports:     str
    intensity: int = Field(default=5, ge=1, le=7)

class OsDetectParams(BaseModel):
    target: str

class VulnScanParams(BaseModel):
    target:  str
    scripts: List[str]

class HostDiscoveryParams(BaseModel):
    target: str

class MCPToolCall(BaseModel):
    tool_name: str
    params:    dict

# API request/response
class ScanRequest(BaseModel):
    query: str = Field(..., min_length=5, max_length=500,
                       example="scan port 80 and 443 on 192.168.1.10")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    rejection: Optional[str] = None
    nmap_command: Optional[str] = None
    summary: Optional[str] = None
    findings: Optional[Any] = None
    duration_ms: Optional[int] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class AllowlistUpdate(BaseModel):
    targets: List[str]   # list of IPs / CIDRs / hostnames

class AuditLogEntry(BaseModel):
    id:               str
    nl_query:         str
    validation_pass:  bool
    rejection_reason: Optional[str]
    nmap_command:     Optional[str]
    gpt_summary:      Optional[str]
    created_at:       datetime

    class Config:
        from_attributes = True