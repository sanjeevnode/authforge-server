from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr                              # rejects malformed emails -> 422
    password: str = Field(min_length=8)          # enforces the min-8 rule -> 422


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str                      # short-lived, use at /login/mfa


class LoginMfaRequest(BaseModel):
    mfa_token: str
    code: str                           # 6-digit OTP or a recovery code
