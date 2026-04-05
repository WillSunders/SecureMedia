from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import get_session, init_db
from .crypto import create_ca, serialize_private_key
from .models import CARecord
from .routes import router

app = FastAPI(title="SecureMedia Key Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "key-server"}


@app.on_event("startup")
def on_startup():
    init_db()
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
