# SecureMedia

SecureMedia is a secure, Twitter-like social media application where posts are encrypted on the client and stored as ciphertext on the server. Only authorised group members can decrypt posts. The system uses ECC for public-key operations, AES-GCM for post encryption, and a dedicated key management server for certificates and group key distribution.

## Stack
- Frontend: React + Vite
- App Server: Python + FastAPI
- Key Server: Python + FastAPI
- Database: PostgreSQL
- Docker: Docker Compose

## Run with Docker (recommended)
From the project root:

```
docker compose up --build
```

Then open:
- Frontend: http://localhost:5173
- App server health: http://localhost:8000/health
- Key server health: http://localhost:8001/health

## Local development (without Docker)
### Frontend
```
cd frontend
npm install
npm run dev
```

### App server
```
cd app-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Key server
```
cd key-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

## Notes
- This is an early scaffold. Crypto operations, database schema, and full API endpoints are still in progress.
- Frontend currently uses fake data for the UI.
