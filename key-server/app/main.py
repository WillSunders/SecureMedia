from fastapi import FastAPI

from .routes import router

app = FastAPI(title="SecureMedia Key Server")

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "key-server"}
