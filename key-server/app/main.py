from fastapi import FastAPI

app = FastAPI(title="SecureMedia Key Server")


@app.get("/health")
def health():
    return {"status": "ok", "service": "key-server"}
