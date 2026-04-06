import base64
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, select

from .auth import create_access_token, decode_access_token, hash_password, verify_password
from .db import get_session
from .models import (
    Certificate,
    Group,
    GroupKeyVersion,
    Membership,
    Post,
    User,
    WrappedKey,
)
from .schemas import (
    CertificateRegisterRequest,
    CertificateRegisterResponse,
    GroupCreateRequest,
    GroupMemberAddRequest,
    GroupListResponse,
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
        owner = session.get(User, group.owner_id)
        return GroupResponse(
            id=group.id,
            name=group.name,
            owner_id=group.owner_id,
            owner_username=owner.username if owner else None,
            members=[user_id],
        )


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
        owner = session.get(User, group.owner_id)
        return GroupResponse(
            id=group.id,
            name=group.name,
            owner_id=group.owner_id,
            owner_username=owner.username if owner else None,
            members=members,
        )


@router.get("/groups/by-name/{group_name}", response_model=GroupResponse)
def get_group_by_name(group_name: str, user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        group = session.scalar(select(Group).where(Group.name == group_name))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        members = session.scalars(
            select(Membership.user_id).where(
                Membership.group_id == group.id, Membership.active == True
            )
        ).all()
        if user_id not in members:
            raise HTTPException(status_code=403, detail="Not a member")
        owner = session.get(User, group.owner_id)
        return GroupResponse(
            id=group.id,
            name=group.name,
            owner_id=group.owner_id,
            owner_username=owner.username if owner else None,
            members=members,
        )


@router.get("/groups", response_model=list[GroupListResponse])
def list_my_groups(user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        memberships = session.scalars(
            select(Membership).where(
                Membership.user_id == user_id, Membership.active == True
            )
        ).all()
        groups = []
        for membership in memberships:
            group = session.get(Group, membership.group_id)
            if not group:
                continue
            owner = session.get(User, group.owner_id)
            groups.append(
                GroupListResponse(
                    id=group.id,
                    name=group.name,
                    owner_id=group.owner_id,
                    owner_username=owner.username if owner else None,
                )
            )
        return groups


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
        member_id = payload.user_id
        if payload.username and not member_id:
            user = session.scalar(select(User).where(User.username == payload.username))
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            member_id = user.id
        if not member_id:
            raise HTTPException(status_code=400, detail="user_id or username required")
        existing = session.scalar(
            select(Membership).where(
                Membership.group_id == group_id,
                Membership.user_id == member_id,
            )
        )
        if existing:
            existing.active = True
        else:
            session.add(
                Membership(group_id=group_id, user_id=member_id, role="member")
            )
        session.commit()
        return {"status": "ok"}


@router.post("/groups/by-name/{group_name}/members")
def add_member_by_name(
    group_name: str,
    payload: GroupMemberAddRequest,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        group = session.scalar(select(Group).where(Group.name == group_name))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group.owner_id != user_id:
            raise HTTPException(status_code=403, detail="Only owner can add members")
        member_id = payload.user_id
        if payload.username and not member_id:
            user = session.scalar(select(User).where(User.username == payload.username))
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            member_id = user.id
        if not member_id:
            raise HTTPException(status_code=400, detail="user_id or username required")
        existing = session.scalar(
            select(Membership).where(
                Membership.group_id == group.id,
                Membership.user_id == member_id,
            )
        )
        if existing:
            existing.active = True
        else:
            session.add(
                Membership(group_id=group.id, user_id=member_id, role="member")
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


@router.post("/groups/{group_id}/leave")
def leave_group(
    group_id: int,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group.owner_id == user_id:
            raise HTTPException(status_code=403, detail="Owner cannot leave group")
        membership = session.scalar(
            select(Membership).where(
                Membership.group_id == group_id,
                Membership.user_id == user_id,
                Membership.active == True,
            )
        )
        if not membership:
            raise HTTPException(status_code=404, detail="Membership not found")
        membership.active = False
        session.commit()
        return {"status": "ok"}


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        group = session.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group.owner_id != user_id:
            raise HTTPException(status_code=403, detail="Only owner can delete group")
        version_ids = select(GroupKeyVersion.id).where(GroupKeyVersion.group_id == group_id)
        session.execute(
            delete(WrappedKey).where(WrappedKey.group_key_version_id.in_(version_ids))
        )
        session.execute(delete(GroupKeyVersion).where(GroupKeyVersion.group_id == group_id))
        session.execute(delete(Post).where(Post.group_id == group_id))
        session.execute(delete(Membership).where(Membership.group_id == group_id))
        session.delete(group)
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
            author_username=(session.get(User, post.author_id).username if session.get(User, post.author_id) else None),
            ciphertext=payload.ciphertext,
            nonce=payload.nonce,
            auth_tag=payload.auth_tag,
            signature=payload.signature,
            cert_id=post.cert_id,
            key_version=post.key_version,
        )


@router.post("/groups/by-name/{group_name}/posts", response_model=PostResponse)
def create_post_by_name(
    group_name: str,
    payload: PostCreateRequest,
    user_id: int = Depends(get_current_user_id),
):
    with get_session() as session:
        group = session.scalar(select(Group).where(Group.name == group_name))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        membership = session.scalar(
            select(Membership).where(
                Membership.group_id == group.id,
                Membership.user_id == user_id,
                Membership.active == True,
            )
        )
        if not membership:
            raise HTTPException(status_code=403, detail="Not a member")
        post = Post(
            group_id=group.id,
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
        author = session.get(User, post.author_id)
        return PostResponse(
            id=post.id,
            group_id=post.group_id,
            author_id=post.author_id,
            author_username=author.username if author else None,
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
                author_username=(session.get(User, post.author_id).username if session.get(User, post.author_id) else None),
                ciphertext=_b64(post.ciphertext),
                nonce=_b64(post.nonce),
                auth_tag=_b64(post.auth_tag),
                signature=_b64(post.signature),
                cert_id=post.cert_id,
                key_version=post.key_version,
            )
            for post in posts
        ]


@router.get("/posts", response_model=list[PostResponse])
def list_all_posts(user_id: int = Depends(get_current_user_id)):
    with get_session() as session:
        posts = session.scalars(select(Post)).all()
        return [
            PostResponse(
                id=post.id,
                group_id=post.group_id,
                author_id=post.author_id,
                author_username=(
                    session.get(User, post.author_id).username
                    if session.get(User, post.author_id)
                    else None
                ),
                ciphertext=_b64(post.ciphertext),
                nonce=_b64(post.nonce),
                auth_tag=_b64(post.auth_tag),
                signature=_b64(post.signature),
                cert_id=post.cert_id,
                key_version=post.key_version,
            )
            for post in posts
        ]
