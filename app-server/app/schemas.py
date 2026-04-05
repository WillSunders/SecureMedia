from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeResponse(BaseModel):
    id: int
    username: str


class CertificateRegisterRequest(BaseModel):
    user_id: int | None = None
    cert_pem: str


class CertificateRegisterResponse(BaseModel):
    cert_id: int


class GroupCreateRequest(BaseModel):
    name: str


class GroupMemberAddRequest(BaseModel):
    user_id: int | None = None
    username: str | None = None


class GroupResponse(BaseModel):
    id: int
    name: str
    owner_id: int
    owner_username: str | None = None
    members: list[int]


class GroupListResponse(BaseModel):
    id: int
    name: str
    owner_id: int
    owner_username: str | None = None


class PostCreateRequest(BaseModel):
    ciphertext: str = Field(..., description="Base64 ciphertext")
    nonce: str = Field(..., description="Base64 nonce")
    auth_tag: str = Field(..., description="Base64 auth tag")
    signature: str = Field(..., description="Base64 signature")
    cert_id: int
    key_version: int


class PostResponse(BaseModel):
    id: int
    group_id: int
    author_id: int
    author_username: str | None = None
    ciphertext: str
    nonce: str
    auth_tag: str
    signature: str
    cert_id: int
    key_version: int
