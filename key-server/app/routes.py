from fastapi import APIRouter, HTTPException

from .schemas import (
    CertificateRequest,
    CertificateResponse,
    GroupKeysCreateRequest,
    GroupKeysCreateResponse,
    WrappedKeyResponse,
)
from .crypto import create_ca, generate_group_key, issue_user_certificate, wrap_group_key
from .storage import STORE

CA_KEYS = create_ca()
STORE.ca_certificate_pem = CA_KEYS.certificate_pem

router = APIRouter()


@router.post("/certificates/request", response_model=CertificateResponse)
def request_certificate(payload: CertificateRequest):
    cert_pem = issue_user_certificate(
        CA_KEYS.private_key,
        payload.user_id,
        payload.username,
        payload.signing_public_key_pem,
    )
    STORE.certificates[payload.user_id] = cert_pem
    STORE.signing_public_keys[payload.user_id] = payload.signing_public_key_pem
    STORE.agreement_public_keys[payload.user_id] = payload.agreement_public_key_pem
    return CertificateResponse(user_id=payload.user_id, cert_pem=cert_pem)


@router.get("/certificates/{user_id}", response_model=CertificateResponse)
def get_certificate(user_id: str):
    cert_pem = STORE.certificates.get(user_id)
    if not cert_pem:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return CertificateResponse(
        user_id=user_id,
        cert_pem=cert_pem,
        revoked=user_id in STORE.revoked,
    )


@router.post("/groups/{group_id}/keys/create", response_model=GroupKeysCreateResponse)
def create_group_keys(group_id: str, payload: GroupKeysCreateRequest):
    version = 1
    group_key = generate_group_key()
    STORE.group_keys_raw[(group_id, version)] = group_key
    STORE.group_versions[group_id] = version
    wrapped = {}
    for member_id in payload.member_user_ids:
        member_pub = STORE.agreement_public_keys.get(member_id)
        if not member_pub:
            raise HTTPException(status_code=404, detail=f"Missing agreement key for {member_id}")
        context = f"{group_id}:{version}:{member_id}".encode("utf-8")
        wrapped_key = wrap_group_key(group_key, member_pub, context)
        STORE.wrapped_keys[(group_id, version, member_id)] = wrapped_key
        wrapped[member_id] = wrapped_key
    return GroupKeysCreateResponse(group_id=group_id, version=version, wrapped_keys=wrapped)


@router.post("/groups/{group_id}/keys/rotate", response_model=GroupKeysCreateResponse)
def rotate_group_keys(group_id: str, payload: GroupKeysCreateRequest):
    version = STORE.group_versions.get(group_id, 0) + 1
    group_key = generate_group_key()
    STORE.group_keys_raw[(group_id, version)] = group_key
    STORE.group_versions[group_id] = version
    wrapped = {}
    for member_id in payload.member_user_ids:
        member_pub = STORE.agreement_public_keys.get(member_id)
        if not member_pub:
            raise HTTPException(status_code=404, detail=f"Missing agreement key for {member_id}")
        context = f"{group_id}:{version}:{member_id}".encode("utf-8")
        wrapped_key = wrap_group_key(group_key, member_pub, context)
        STORE.wrapped_keys[(group_id, version, member_id)] = wrapped_key
        wrapped[member_id] = wrapped_key
    return GroupKeysCreateResponse(group_id=group_id, version=version, wrapped_keys=wrapped)


@router.get("/groups/{group_id}/keys/current", response_model=WrappedKeyResponse)
def get_current_key(group_id: str, user_id: str):
    version = STORE.group_versions.get(group_id)
    if not version:
        raise HTTPException(status_code=404, detail="Group key not found")
    wrapped_key = STORE.wrapped_keys.get((group_id, version, user_id))
    if not wrapped_key:
        raise HTTPException(status_code=404, detail="Wrapped key not found")
    return WrappedKeyResponse(
        group_id=group_id, version=version, user_id=user_id, wrapped_key=wrapped_key
    )


@router.get(
    "/groups/{group_id}/keys/{version}/wrapped/{user_id}",
    response_model=WrappedKeyResponse,
)
def get_wrapped_key(group_id: str, version: int, user_id: str):
    wrapped_key = STORE.wrapped_keys.get((group_id, version, user_id))
    if not wrapped_key:
        raise HTTPException(status_code=404, detail="Wrapped key not found")
    return WrappedKeyResponse(
        group_id=group_id, version=version, user_id=user_id, wrapped_key=wrapped_key
    )
