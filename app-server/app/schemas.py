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


class GroupCreateRequest(BaseModel):
    name: str


class GroupMemberAddRequest(BaseModel):
    user_id: int


class GroupResponse(BaseModel):
    id: int
    name: str
    owner_id: int
    members: list[int]


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
    ciphertext: str
    nonce: str
    auth_tag: str
    signature: str
    cert_id: int
    key_version: int
