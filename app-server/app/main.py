from fastapi import FastAPI

from .db import init_db

app = FastAPI(title="SecureMedia App Server")


@app.get("/health")
def health():
    return {"status": "ok", "service": "app-server"}


@app.on_event("startup")
def on_startup():
    init_db()
