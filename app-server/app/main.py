from fastapi import FastAPI

app = FastAPI(title="SecureMedia App Server")


@app.get("/health")
def health():
    return {"status": "ok", "service": "app-server"}
