from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from app.auth import decode_access_token, is_token_blacklisted, SECRET_KEY, ALGORITHM
from app.crud_user import get_user_by_id
from jose import jwt, JWTError  # THÊM IMPORT

security = HTTPBearer(auto_error=False)

async def get_token_from_request(request: Request):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return None

async def get_current_user(request: Request, credentials = Depends(security)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    if is_token_blacklisted(token):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    payload = decode_access_token(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# SỬA: Dependency cho phép token hết hạn
async def get_current_user_allow_expired(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    token = auth_header.split(" ")[1]
    
    if is_token_blacklisted(token):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    try:
        # Cho phép decode token đã hết hạn
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user = await get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid")

async def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Requires admin role")
    return user