from pydantic import BaseModel, Field


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MfaVerifyResponse(BaseModel):
    recovery_codes: list[str]           # shown ONCE


class MfaDisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=6)


class RecoveryCountResponse(BaseModel):
    remaining: int


class RecoveryUseRequest(BaseModel):
    code: str
