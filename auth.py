from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from uuid import uuid4
from fastapi import HTTPException, status
from typing import Optional
import os  # THÊM IMPORT OS

from app.database import db

# SỬA: Dùng biến môi trường thống nhất
SECRET_KEY = os.getenv("APP_SECRET_KEY", "CHANGE_THIS_SECRET_KEY_FOR_SESSION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
REFRESH_TOKEN_EXPIRE_DAYS = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: str):
    token = str(uuid4())
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db["refresh_tokens"].insert_one({
        "token": token,
        "user_id": user_id,
        "expires_at": expire,
        "created_at": datetime.utcnow()
    })

    return token

def revoke_refresh_token(token: str):
    db["refresh_tokens"].delete_one({"token": token})

def revoke_all_user_refresh_tokens(user_id: str):
    db["refresh_tokens"].delete_many({"user_id": user_id})

def is_refresh_token_valid(token: str):
    doc = db["refresh_tokens"].find_one({"token": token})
    if not doc:
        return None
    if doc["expires_at"] < datetime.utcnow():
        db["refresh_tokens"].delete_one({"token": token})
        return None
    return doc

def add_to_blacklist(token: str):
    try:
        # THÊM: Cho phép decode không verify expiration
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        expire_time = datetime.utcfromtimestamp(payload["exp"]) if "exp" in payload else datetime.utcnow() + timedelta(days=1)
        
        db["token_blacklist"].insert_one({
            "token": token,
            "user_id": payload.get("user_id"),
            "expires_at": expire_time,
            "blacklisted_at": datetime.utcnow(),
            "reason": "logout"
        })
    except JWTError:
        # Nếu token không hợp lệ, vẫn thêm vào blacklist
        db["token_blacklist"].insert_one({
            "token": token,
            "user_id": "unknown",
            "expires_at": datetime.utcnow() + timedelta(days=1),
            "blacklisted_at": datetime.utcnow(),
            "reason": "invalid_token"
        })

def is_token_blacklisted(token: str):
    doc = db["token_blacklist"].find_one({"token": token})
    return doc is not None

def revoke_all_user_tokens(user_id: str):
    revoke_all_user_refresh_tokens(user_id)

def decode_access_token(token: str):
    try:
        if is_token_blacklisted(token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or expired")