from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import os
from jose import jwt, JWTError

from app.database import init_db, db 
from app.schemas import UserCreate, UserOut, LoginIn, Token, UserUpdate, TokenRefresh, LogoutResponse
from app.crud_user import create_user, get_user_by_username, list_users, update_user, delete_user, get_user_by_id
from app.auth import verify_password, create_access_token, create_refresh_token, is_refresh_token_valid, revoke_refresh_token, add_to_blacklist, revoke_all_user_tokens, decode_access_token, SECRET_KEY, ALGORITHM
from app.deps import get_current_user, require_admin, get_token_from_request

# HÀM LIFESPAN MỚI
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    await create_admin_user()
    yield
    # Shutdown (có thể thêm cleanup code ở đây nếu cần)

# SỬA: Thêm lifespan vào FastAPI app
app = FastAPI(
    title="FastAPI Mongo Auth", 
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SỬA: Dùng biến môi trường thống nhất
SECRET_KEY = os.getenv("APP_SECRET_KEY", "CHANGE_THIS_SECRET_KEY_FOR_SESSION")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

async def create_admin_user():
    """Tạo tài khoản admin mặc định nếu chưa tồn tại"""
    try:
        admin_user = await get_user_by_username("admin")
        if not admin_user:
            await create_user("admin", "admin@example.com", "admin123", "admin")
            print("✅ Admin user created successfully")
            print("   👤 Username: admin")
            print("   🔑 Password: admin123")
            print("   📧 Email: admin@example.com")
        else:
            print("✅ Admin user already exists")
    except Exception as e:
        print(f"⚠️ Could not create admin user: {e}")

@app.get("/")
async def root():
    return {
        "message": "FastAPI Mongo Auth System", 
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "auth": [
                "POST /register - Register new user",
                "POST /login - Login and get tokens", 
                "POST /refresh - Refresh access token",
                "POST /logout - Logout and revoke token"
            ],
            "users": [
                "GET /users/me - Get current user info",
                "PUT /users/me - Update current user", 
                "PUT /users/{username} - Update user by username",
                "DELETE /users/{username} - Delete user by username",
                "GET /users - Get all users (admin only)"
            ]
        }
    }

@app.post("/register", response_model=UserOut, tags=["Auth"])
async def register(user: UserCreate):
    existed = await get_user_by_username(user.username)
    if existed:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = await create_user(user.username, user.email, user.password)
    return JSONResponse(
        status_code=201, 
        content={**new_user, "message": "User registered successfully"}
    )

@app.post("/login", response_model=Token, tags=["Auth"])
async def login(response: Response, payload: LoginIn):
    user = await get_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token({"user_id": user.get("_id"), "role": user.get("role")})
    refresh_token = create_refresh_token(str(user.get("_id")))
    
    # Set secure cookies
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True, 
        secure=False,
        samesite="lax",
        max_age=24 * 60 * 60
    )
    
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True, 
        secure=False,
        samesite="lax", 
        max_age=30 * 24 * 60 * 60
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "refresh_token": refresh_token,
        "message": "Login successful"
    }

@app.post("/refresh", response_model=Token, tags=["Auth"])
async def refresh_token_route(payload: TokenRefresh):
    r = is_refresh_token_valid(payload.refresh_token)
    if not r:
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")
    
    user_id = r.get("user_id")
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    access_token = create_access_token({"user_id": user_id, "role": user.get("role")})
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "refresh_token": payload.refresh_token,
        "message": "Token refreshed successfully"
    }

# SỬA: Logout duy nhất - cải thiện và làm mạnh mẽ hơn
@app.post("/logout", response_model=LogoutResponse, tags=["Auth"])
async def logout(response: Response, request: Request):
    try:
        # Lấy token từ request
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # Nếu không có token trong header, vẫn xóa cookies và session
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            response.delete_cookie("session")
            request.session.clear()
            return {
                "success": True,
                "message": "Đăng xuất thành công (no token provided)."
            }
        
        token = auth_header.split(" ")[1]
        
        if token:
            try:
                # Thử lấy thông tin user từ token (cho phép token hết hạn)
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
                user_id = payload.get("user_id")
                
                if user_id:
                    # Thêm token vào blacklist
                    add_to_blacklist(token)
                    # Xóa refresh token của user (tùy chọn - để chắc chắn hơn)
                    revoke_all_user_tokens(user_id)
            except JWTError:
                # Token không hợp lệ, nhưng vẫn thêm vào blacklist để chắc chắn
                add_to_blacklist(token)
            
        # Xóa session và cookies
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        response.delete_cookie("session")
        
        # Clear session data
        request.session.clear()
        
        return {
            "success": True,
            "message": "Đăng xuất thành công. Token đã bị thu hồi."
        }
    except Exception as e:
        # Vẫn cố gắng xóa cookies ngay cả khi có lỗi
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        response.delete_cookie("session")
        request.session.clear()
        
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Logout completed with warning: {str(e)}"}
        )

# THÊM: Endpoint kiểm tra token
@app.get("/check-token", tags=["Auth"])
async def check_token(request: Request):
    """Kiểm tra token có hợp lệ không"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"valid": False, "message": "No token provided"}
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        user = await get_user_by_id(user_id)
        
        if not user:
            return {"valid": False, "message": "User not found"}
        
        return {
            "valid": True, 
            "user": user["username"],
            "role": user["role"],
            "expires": payload.get("exp")
        }
    except JWTError as e:
        return {"valid": False, "message": f"Token invalid: {str(e)}"}

@app.get("/users", response_model=list[UserOut], tags=["Users"])
async def get_users_route(admin=Depends(require_admin)):
    users = await list_users()
    return users

@app.get("/users/me", response_model=UserOut, tags=["Users"])
async def get_me(user: dict = Depends(get_current_user)):
    return user

@app.put("/users/me", response_model=UserOut, tags=["Users"])
async def update_current_user(payload: UserUpdate, current_user: dict = Depends(get_current_user)):
    updated = await update_user(current_user["_id"], payload.dict(exclude_unset=True))
    return {**updated, "message": "Your profile updated successfully"}

@app.put("/users/{username}", response_model=UserOut, tags=["Users"])
async def update_user_by_username(username: str, payload: UserUpdate, current_user: dict = Depends(get_current_user)):
    target_user = await get_user_by_username(username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if current_user.get("role") != "admin" and current_user.get("username") != username:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    updated = await update_user(target_user["_id"], payload.dict(exclude_unset=True))
    return {**updated, "message": f"User {username} updated successfully"}

@app.delete("/users/{username}", tags=["Users"])
async def delete_user_by_username(username: str, admin=Depends(require_admin)):
    target_user = await get_user_by_username(username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    n = await delete_user(target_user["_id"])
    if n == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User {username} deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)