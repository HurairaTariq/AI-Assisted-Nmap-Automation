from datetime import datetime
import uuid

from pydantic import BaseModel, EmailStr
from sqlalchemy import Boolean, Column, DateTime, String, CheckConstraint, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False, index=True)
    hashed_pw = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    allowlist = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint("email LIKE '%@%.%'", name="valid_email_check"),
    )


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"