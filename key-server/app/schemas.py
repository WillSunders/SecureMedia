from pydantic import BaseModel, Field


class CertificateRequest(BaseModel):
    user_id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Human-readable username")
    signing_public_key_pem: str = Field(..., description="ECDSA public key (PEM)")
    agreement_public_key_pem: str = Field(..., description="ECDH public key (PEM)")


class CertificateResponse(BaseModel):
    user_id: str
    cert_pem: str
    revoked: bool = False


class GroupKeysCreateRequest(BaseModel):
    group_id: str
    member_user_ids: list[str]


class GroupKeysCreateResponse(BaseModel):
    group_id: str
    version: int
    wrapped_keys: dict[str, str]


class WrappedKeyResponse(BaseModel):
    group_id: str
    version: int
    user_id: str
    wrapped_key: str


class PublicKeysResponse(BaseModel):
    user_id: str
    signing_public_key_pem: str
    agreement_public_key_pem: str
