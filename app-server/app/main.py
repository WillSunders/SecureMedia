from fastapi import FastAPI

from .db import init_db
from .routes import router

app = FastAPI(title="SecureMedia App Server")

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "app-server"}


@app.on_event("startup")
def on_startup():
    init_db()
