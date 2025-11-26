from pydantic import BaseModel, EmailStr, Field, validator, ConfigDict
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=50)
    
    @validator('password')
    def validate_password_length(cls, v):
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Password too long (max 72 bytes)')
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=1, max_length=50)
    role: Optional[str] = None
    
    @validator('password')
    def validate_password_length(cls, v):
        if v and len(v.encode('utf-8')) > 72:
            raise ValueError('Password too long (max 72 bytes)')
        return v

class UserOut(BaseModel):
    id: str = Field(..., alias="_id")
    username: str
    email: EmailStr
    role: str

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "6123abc123",
                "username": "alice",
                "email": "alice@example.com",
                "role": "user"
            }
        }
    )

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str

class TokenRefresh(BaseModel):
    refresh_token: str

class LoginIn(BaseModel):
    username: str
    password: str

class LogoutResponse(BaseModel):
    success: bool
    message: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Đăng xuất thành công"
            }
        }
    )