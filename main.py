from fastapi import FastAPI, HTTPException
from jose import jwt
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import time

app = FastAPI()

# ========================
# Helper: Base64URL encoding
# ========================
def b64url_uint(val: int) -> str:
    """Convert integer to Base64URL-encoded string without padding."""
    return base64.urlsafe_b64encode(
        val.to_bytes((val.bit_length() + 7) // 8, "big")
    ).decode("utf-8").rstrip("=")

# ========================
# Generate RSA Key Pair
# ========================
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Create unique key IDs
valid_kid = str(uuid4())
expired_kid = str(uuid4())

# Track keys with expiries
keys = [
    {
        "kid": valid_kid,
        "expiry": int(time.time()) + 3600,  # valid 1 hour
    },
    {
        "kid": expired_kid,
        "expiry": int(time.time()) - 3600,  # expired 1 hour ago
    },
]

# ========================
# JWKS Endpoint (multiple paths)
# ========================
@app.get("/jwks")
@app.get("/jwks.json")
@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return JWKS containing only non-expired keys."""
    now = int(time.time())
    valid_keys = []
    for k in keys:
        if k["expiry"] > now:
            valid_keys.append({
                "kty": "RSA",
                "kid": k["kid"],
                "use": "sig",
                "alg": "RS256",
                "n": b64url_uint(public_numbers.n),
                "e": b64url_uint(public_numbers.e),
            })
    return {"keys": valid_keys}

# ========================
# Auth Endpoint
# ========================
@app.post("/auth")
def auth(expired: bool = False):
    """Return a valid or expired JWT in JSON format."""
    if expired:
        kid = expired_kid
        exp = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    else:
        kid = valid_kid
        exp = datetime.now(tz=timezone.utc) + timedelta(minutes=5)

    token = jwt.encode(
        {"sub": "fakeuser", "exp": exp},
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return {"token": token}

# Explicitly reject GET on /auth
@app.get("/auth")
def auth_get():
    raise HTTPException(status_code=405, detail="Use POST for /auth")
