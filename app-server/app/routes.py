import base64
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from .auth import create_access_token, decode_access_token, hash_password, verify_password
from .db import get_session
from .models import Certificate, Group, Membership, Post, User
from .schemas import (
    CertificateRegisterRequest,
    CertificateRegisterResponse,
    GroupCreateRequest,
    GroupMemberAddRequest,
    GroupResponse,
    LoginRequest,
    MeResponse,
    PostCreateRequest,
    PostResponse,
    RegisterRequest,
    TokenResponse,
)

router = APIRouter()
security = HTTPBearer()


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("utf-8")


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> int:
    return decode_access_token(credentials.credentials)


@router.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    with get_session() as session:
        existing = session.scalar(select(User).where(User.username == payload.username))
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        user = User(
            username=payload.username,
            password_hash=hash_password(payload.password),
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_access_token(user.id)
        return TokenResponse(access_token=token)


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == payload.username))
        if not user or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_access_token(user.id)
        return TokenResponse(access_token=token)


@router.get("/auth/me", response_model=MeResponse)
def me(user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return MeResponse(id=user.id, username=user.username)


@router.post("/certificates/register", response_model=CertificateRegisterResponse)
def register_certificate(
    payload: CertificateRegisterRequest, user_id: int = Depends(get_current_user_id)
):
    with get_session() as session:
        owner_id = payload.user_id or user_id
        cert = Certificate(
            user_id=owner_id,
            cert_pem=payload.cert_pem,
            issued_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            revoked=False,
        )
        session.add(cert)
        session.commit()
        session.refresh(cert)
        return CertificateRegisterResponse(cert_id=cert.id)


@router.post("/groups", response_model=GroupResponse)
def create_group(payload: GroupCreateRequest, user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        group = Group(name=payload.name, owner_id=user_id)
        session.add(group)
        session.commit()
        session.refresh(group)
        session.add(Membership(group_id=group.id, user_id=user_id, role="owner"))
        session.commit()
        return GroupResponse(id=group.id, name=group.name, owner_id=group.owner_id, members=[user_id])


@router.get("/groups/{group_id}", response_model=GroupResponse)
def get_group(group_id: int, user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        members = session.scalars(
            select(Membership.user_id).where(Membership.group_id == group_id, Membership.active == True)
        ).all()
        if user_id not in members:
            raise HTTPException(status_code=403, detail="Not a member")
        return GroupResponse(id=group.id, name=group.name, owner_id=group.owner_id, members=members)


@router.post("/groups/{group_id}/members")
def add_member(
    group_id: int,
    payload: GroupMemberAddRequest,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group.owner_id != user_id:
            raise HTTPException(status_code=403, detail="Only owner can add members")
        existing = session.scalar(
            select(Membership).where(
                Membership.group_id == group_id,
                Membership.user_id == payload.user_id,
            )
        )
        if existing:
            existing.active = True
        else:
            session.add(
                Membership(group_id=group_id, user_id=payload.user_id, role="member")
            )
        session.commit()
        return {"status": "ok"}


@router.delete("/groups/{group_id}/members/{member_id}")
def remove_member(
    group_id: int,
    member_id: int,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group.owner_id != user_id:
            raise HTTPException(status_code=403, detail="Only owner can remove members")
        membership = session.scalar(
            select(Membership).where(
                Membership.group_id == group_id,
                Membership.user_id == member_id,
                Membership.active == True,
            )
        )
        if not membership:
            raise HTTPException(status_code=404, detail="Membership not found")
        membership.active = False
        session.commit()
        return {"status": "ok"}


@router.post("/groups/{group_id}/posts", response_model=PostResponse)
def create_post(
    group_id: int,
    payload: PostCreateRequest,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        membership = session.scalar(
            select(Membership).where(
                Membership.group_id == group_id,
                Membership.user_id == user_id,
                Membership.active == True,
            )
        )
        if not membership:
            raise HTTPException(status_code=403, detail="Not a member")
        post = Post(
            group_id=group_id,
            author_id=user_id,
            ciphertext=_b64d(payload.ciphertext),
            nonce=_b64d(payload.nonce),
            auth_tag=_b64d(payload.auth_tag),
            signature=_b64d(payload.signature),
            cert_id=payload.cert_id,
            key_version=payload.key_version,
        )
        session.add(post)
        session.commit()
        session.refresh(post)
        return PostResponse(
            id=post.id,
            group_id=post.group_id,
            author_id=post.author_id,
            ciphertext=payload.ciphertext,
            nonce=payload.nonce,
            auth_tag=payload.auth_tag,
            signature=payload.signature,
            cert_id=post.cert_id,
            key_version=post.key_version,
        )


@router.get("/groups/{group_id}/posts", response_model=list[PostResponse])
def list_posts(group_id: int, user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        posts = session.scalars(select(Post).where(Post.group_id == group_id)).all()
        return [
            PostResponse(
                id=post.id,
                group_id=post.group_id,
                author_id=post.author_id,
                ciphertext=_b64(post.ciphertext),
                nonce=_b64(post.nonce),
                auth_tag=_b64(post.auth_tag),
                signature=_b64(post.signature),
                cert_id=post.cert_id,
                key_version=post.key_version,
            )
            for post in posts
        ]
