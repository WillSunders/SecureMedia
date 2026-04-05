# SecureMedia — Technical Design (ECC-Based)

## Overview
SecureMedia is a secure, Twitter-like social media application where posts are encrypted client-side and stored as ciphertext on the server. Only authorised group members can decrypt posts.

The system uses **Elliptic Curve Cryptography (ECC)** for public-key operations, combined with **symmetric encryption** for efficient data protection. A dedicated **Key Management / Certificate Authority (CA) service** manages identities, certificates, and group keys.

---

## Security Goals
- Confidentiality: Only group members can read posts
- Integrity: Posts cannot be tampered with undetected
- Authentication: Users can verify the identity of the sender
- Access control: Group membership determines decryption ability
- Forward access control: Removed users cannot read future posts

---

## Architecture
### Components
1. Client Application (React)
   - Handles encryption/decryption
   - Stores private keys locally
   - Signs posts
   - Verifies certificates and signatures

2. Application Server (Python / FastAPI)
   - Stores ciphertext posts
   - Manages users, groups, memberships
   - No access to plaintext data

3. Key Management / CA Server (Python / FastAPI)
   - Issues certificates
   - Manages group keys
   - Handles key distribution and rotation

4. Database (PostgreSQL)
   - Stores users, posts, keys, certificates

---

## Cryptographic Design
### Algorithms
- ECDSA — Digital signatures
- ECDH — Key agreement / key wrapping
- AES-256-GCM — Symmetric encryption for posts
- X.509 Certificates — Identity binding

### Key Structure
Per user:
- ECC signing key pair (ECDSA)
- ECC key agreement key pair (ECDH)
- X.509 certificate signed by the CA

Per group:
- Symmetric group key `GK_vN`
- Version number for key rotation

### Key Distribution
Group keys are distributed as wrapped keys:

    Enc(PublicKey_User, GK_vN)

Each user receives a copy encrypted with their own public key.

---

## Core Workflows
### 1. User Registration
1. Client generates ECC key pairs
2. Sends public keys to Key Server
3. Key Server issues X.509 certificate
4. Client stores private keys locally

### 2. Group Creation
1. Group created on App Server
2. Key Server generates `GK_v1`
3. Key Server encrypts `GK_v1` for each member
4. Wrapped keys stored in database

### 3. Posting
1. Client fetches wrapped group key
2. Decrypts it locally using private key
3. Encrypts post using AES-GCM
4. Signs post using ECDSA
5. Sends ciphertext + signature to App Server

Server stores:
- ciphertext
- nonce
- auth tag
- signature
- certificate reference
- key version

### 4. Reading Posts
1. Client fetches encrypted posts
2. Retrieves wrapped group key
3. Decrypts group key locally
4. Verifies certificate and signature
5. Decrypts post

### 5. Adding a User
1. Admin adds user to group
2. Key Server wraps current group key for new user

Optional:
- Rotate group key for stronger security

### 6. Removing a User (Rekeying)
1. Admin removes user
2. Key Server generates new key `GK_v(N+1)`
3. Distributes only to remaining members
4. Future posts use new key

Removed users cannot decrypt future posts.

---

## Data Model
### Users
- id
- username
- password_hash
- status

### Certificates
- id
- user_id
- cert_pem
- issued_at
- expires_at
- revoked

### Groups
- id
- name
- owner_id

### Memberships
- group_id
- user_id
- role
- active

### Group Key Versions
- id
- group_id
- version_number

### Wrapped Keys
- group_key_version_id
- user_id
- encrypted_key

### Posts
- id
- group_id
- author_id
- ciphertext
- nonce
- auth_tag
- signature
- cert_id
- key_version

---

## API Design (Planned)
### App Server
- POST /auth/register
- POST /auth/login
- POST /groups
- GET /groups/:id
- POST /groups/:id/members
- DELETE /groups/:id/members/:userId
- POST /groups/:id/posts
- GET /groups/:id/posts

### Key Server
- POST /certificates/request
- GET /certificates/:userId
- POST /groups/:id/keys/create
- POST /groups/:id/keys/rotate
- GET /groups/:id/keys/current
- GET /groups/:id/keys/:version/wrapped/:userId

---

## Repo Structure (Current)
```
.
├── docker-compose.yml
├── TechnicalDesign.md
├── frontend/
│   ├── Dockerfile
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       └── main.jsx
├── app-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       └── main.py
└── key-server/
    ├── Dockerfile
    ├── requirements.txt
    └── app/
        └── main.py
```

---

## Docker Deployment (Current)
Services:
- frontend (Vite + React)
- app-server (FastAPI)
- key-server (FastAPI)
- postgres

Run:
```
docker compose up --build
```

Health checks:
- App Server: http://localhost:8000/health
- Key Server: http://localhost:8001/health
- Frontend: http://localhost:5173

---

## Implementation Status
- File organisation: Done
- Docker Compose + Dockerfiles: Done
- Service skeletons: Done
- Crypto operations: Not started
- Database schema/migrations: Not started
- Auth + API endpoints: Not started
- Frontend UI: Not started

---

## Next Steps
1. Add database schema and migrations (PostgreSQL)
2. Implement auth and group management endpoints
3. Define key server endpoints and key wrapping
4. Implement client-side cryptography in React
5. Build UI for groups and posts
