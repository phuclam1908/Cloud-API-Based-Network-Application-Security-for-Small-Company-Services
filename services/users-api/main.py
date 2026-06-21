from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt, os, json, uuid
from datetime import datetime

JWKS_URL = os.getenv("JWKS_URL",
    "http://keycloak.keycloak.svc.cluster.local/realms/company/protocol/openid-connect/certs")
ALGORITHM = "ES256"
SERVICE_NAME = "users-api"

def log(level, event, **kwargs):
    print(json.dumps({
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "service": SERVICE_NAME,
        "level": level,
        "event": event,
        **kwargs
    }), flush=True)

_jwks_client = None

def get_jwks_client():
    global _jwks_client
    if not _jwks_client:
        _jwks_client = jwt.PyJWKClient(JWKS_URL)
    return _jwks_client

security = HTTPBearer()

async def verify_jwt(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token = credentials.credentials
    correlation_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=[ALGORITHM],
            options={
                "verify_exp": True,
                "verify_aud": False  # Keycloak không set aud cho realm tokens
            }
        )
        payload["_correlation_id"] = correlation_id
        log("INFO", "jwt_verified",
            correlation_id=correlation_id,
            sub=payload.get("sub","?")[:8]+"...",
            roles=payload.get("realm_access",{}).get("roles",[]))
        return payload
    except jwt.ExpiredSignatureError:
        log("WARN", "jwt_expired", correlation_id=correlation_id)
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        log("WARN", "jwt_invalid", correlation_id=correlation_id, error=str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(*roles):
    async def check(payload: dict = Depends(verify_jwt)):
        user_roles = payload.get("realm_access",{}).get("roles",[])
        if not any(r in user_roles for r in roles):
            log("WARN", "rbac_denied",
                correlation_id=payload.get("_correlation_id"),
                required=list(roles), actual=user_roles)
            raise HTTPException(status_code=403, detail="Insufficient role")
        return payload
    return check

FAKE_DB = {
    "660a0175-851a-41e9-b861-a1ef7e746e99": {
        "id": "660a0175-851a-41e9-b861-a1ef7e746e99",
        "username": "user2",
        "email": "user2@company.com",
        "role": "user"
    },
    "admin-uuid-0001": {
        "id": "admin-uuid-0001",
        "username": "admin",
        "email": "admin@company.com",
        "role": "admin"
    }
}

app = FastAPI(title="users-api")

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/api/users/me")
async def get_me(payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    user = FAKE_DB.get(sub)
    log("INFO", "get_me", correlation_id=payload.get("_correlation_id"),
        sub=sub[:8]+"...")
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/api/users/{user_id}")
async def get_user(user_id: str, payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    user_roles = payload.get("realm_access",{}).get("roles",[])
    is_admin = "admin" in user_roles
    if not is_admin and user_id != sub:
        log("WARN", "bola_attempt",
            correlation_id=payload.get("_correlation_id"),
            attacker=sub[:8]+"...", target=user_id[:8]+"...")
        raise HTTPException(status_code=403, detail="Access denied")
    user = FAKE_DB.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/api/users")
async def list_users(payload: dict = Depends(require_role("admin"))):
    return list(FAKE_DB.values())
