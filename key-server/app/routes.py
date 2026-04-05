from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func

from .schemas import (
    CertificateRequest,
    CertificateResponse,
    GroupKeysCreateRequest,
    GroupKeysCreateResponse,
    PublicKeysResponse,
    WrappedKeyResponse,
)
from .crypto import (
    create_ca,
    generate_group_key,
    issue_user_certificate,
    load_private_key,
    serialize_private_key,
    wrap_group_key,
)
from .db import get_session
from .models import CARecord, Certificate, GroupKey, PublicKeyBundle, WrappedKey

router = APIRouter()


@router.post("/certificates/request", response_model=CertificateResponse)
def request_certificate(payload: CertificateRequest):
    with get_session() as session:
        ca = session.get(CARecord, 1)
        if not ca:
            ca_keys = create_ca()
            ca = CARecord(
                id=1,
                private_key_pem=serialize_private_key(ca_keys.private_key),
                certificate_pem=ca_keys.certificate_pem,
            )
            session.add(ca)
            session.commit()

        ca_private_key = load_private_key(ca.private_key_pem)
        cert_pem = issue_user_certificate(
            ca_private_key,
            payload.user_id,
            payload.username,
            payload.signing_public_key_pem,
        )
        session.merge(
            Certificate(user_id=payload.user_id, cert_pem=cert_pem, revoked=False)
        )
        session.merge(
            PublicKeyBundle(
                user_id=payload.user_id,
                signing_public_key_pem=payload.signing_public_key_pem,
                agreement_public_key_pem=payload.agreement_public_key_pem,
            )
        )
        session.commit()
        return CertificateResponse(user_id=payload.user_id, cert_pem=cert_pem)


@router.get("/certificates/{user_id}", response_model=CertificateResponse)
def get_certificate(user_id: str):
    with get_session() as session:
        cert = session.get(Certificate, user_id)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        return CertificateResponse(
            user_id=user_id,
            cert_pem=cert.cert_pem,
            revoked=cert.revoked,
        )


@router.get("/ca/certificate")
def get_ca_certificate():
    with get_session() as session:
        ca = session.get(CARecord, 1)
        if not ca:
            raise HTTPException(status_code=404, detail="CA not initialized")
        return {"certificate_pem": ca.certificate_pem}


@router.get("/public-keys/{user_id}", response_model=PublicKeysResponse)
def get_public_keys(user_id: str):
    with get_session() as session:
        keys = session.get(PublicKeyBundle, user_id)
        if not keys:
            raise HTTPException(status_code=404, detail="Public keys not found")
        return PublicKeysResponse(
            user_id=user_id,
            signing_public_key_pem=keys.signing_public_key_pem,
            agreement_public_key_pem=keys.agreement_public_key_pem,
        )


@router.post("/groups/{group_id}/keys/create", response_model=GroupKeysCreateResponse)
def create_group_keys(group_id: str, payload: GroupKeysCreateRequest):
    with get_session() as session:
        version = 1
        group_key = generate_group_key()
        session.add(GroupKey(group_id=group_id, version=version, key_bytes=group_key))
        wrapped = {}
        for member_id in payload.member_user_ids:
            pk = session.get(PublicKeyBundle, member_id)
            if not pk:
                raise HTTPException(
                    status_code=404, detail=f"Missing agreement key for {member_id}"
                )
            context = f"{group_id}:{version}:{member_id}".encode("utf-8")
            wrapped_key = wrap_group_key(group_key, pk.agreement_public_key_pem, context)
            session.add(
                WrappedKey(
                    group_id=group_id,
                    version=version,
                    user_id=member_id,
                    wrapped_key=wrapped_key,
                )
            )
            wrapped[member_id] = wrapped_key
        session.commit()
        return GroupKeysCreateResponse(
            group_id=group_id, version=version, wrapped_keys=wrapped
        )


@router.post("/groups/{group_id}/keys/rotate", response_model=GroupKeysCreateResponse)
def rotate_group_keys(group_id: str, payload: GroupKeysCreateRequest):
    with get_session() as session:
        max_version = session.scalar(
            select(func.max(GroupKey.version)).where(GroupKey.group_id == group_id)
        )
        version = (max_version or 0) + 1
        group_key = generate_group_key()
        session.add(GroupKey(group_id=group_id, version=version, key_bytes=group_key))
        wrapped = {}
        for member_id in payload.member_user_ids:
            pk = session.get(PublicKeyBundle, member_id)
            if not pk:
                raise HTTPException(
                    status_code=404, detail=f"Missing agreement key for {member_id}"
                )
            context = f"{group_id}:{version}:{member_id}".encode("utf-8")
            wrapped_key = wrap_group_key(group_key, pk.agreement_public_key_pem, context)
            session.add(
                WrappedKey(
                    group_id=group_id,
                    version=version,
                    user_id=member_id,
                    wrapped_key=wrapped_key,
                )
            )
            wrapped[member_id] = wrapped_key
        session.commit()
        return GroupKeysCreateResponse(
            group_id=group_id, version=version, wrapped_keys=wrapped
        )


@router.get("/groups/{group_id}/keys/current", response_model=WrappedKeyResponse)
def get_current_key(group_id: str, user_id: str):
    with get_session() as session:
        max_version = session.scalar(
            select(func.max(GroupKey.version)).where(GroupKey.group_id == group_id)
        )
        if not max_version:
            raise HTTPException(status_code=404, detail="Group key not found")
        wrapped = session.scalar(
            select(WrappedKey.wrapped_key).where(
                WrappedKey.group_id == group_id,
                WrappedKey.version == max_version,
                WrappedKey.user_id == user_id,
            )
        )
        if not wrapped:
            raise HTTPException(status_code=404, detail="Wrapped key not found")
        return WrappedKeyResponse(
            group_id=group_id,
            version=max_version,
            user_id=user_id,
            wrapped_key=wrapped,
        )


@router.get(
    "/groups/{group_id}/keys/{version}/wrapped/{user_id}",
    response_model=WrappedKeyResponse,
)
def get_wrapped_key(group_id: str, version: int, user_id: str):
    with get_session() as session:
        wrapped = session.scalar(
            select(WrappedKey.wrapped_key).where(
                WrappedKey.group_id == group_id,
                WrappedKey.version == version,
                WrappedKey.user_id == user_id,
            )
        )
        if not wrapped:
            raise HTTPException(status_code=404, detail="Wrapped key not found")
        return WrappedKeyResponse(
            group_id=group_id, version=version, user_id=user_id, wrapped_key=wrapped
        )
