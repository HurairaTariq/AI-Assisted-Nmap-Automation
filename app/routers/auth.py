from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from app.database import get_db
from app.models import User, TokenResponse, UserCreate
from app.config import settings
import hashlib

router = APIRouter()
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# def hash_password(pw: str) -> str:
#     return pwd_ctx.hash(pw)
def hash_password(password: str):
    return pwd_ctx.hash(password)

# def verify_password(plain: str, hashed: str) -> bool:
#     return pwd_ctx.verify(plain, hashed)
def verify_password(password: str, hashed_password: str):
    return pwd_ctx.verify(password, hashed_password)

def create_access_token(data: dict) -> str:
    exp = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": exp}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise cred_exc
    return user

@router.post("/register", status_code=201)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Username already taken")
    user = User(
        username=payload.username,
        email = payload.email.lower().strip(),
        hashed_pw=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    return {"message": "User created successfully"}

@router.post("/login", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.username == form.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_pw):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token}

@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {
        "id":         str(current_user.id),
        "username":   current_user.username,
        "email":      current_user.email,
        "allowlist": current_user.allowlist or [],
    }