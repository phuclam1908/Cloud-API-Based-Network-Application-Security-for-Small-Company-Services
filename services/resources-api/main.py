from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt, os, json, uuid
from datetime import datetime

JWKS_URL = os.getenv("JWKS_URL",
    "http://keycloak.keycloak.svc.cluster.local/realms/company/protocol/openid-connect/certs")
ALGORITHM = "RS256"
SERVICE_NAME = "resources-api"

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

async def verify_jwt(request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    correlation_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key,
            algorithms=[ALGORITHM],
            options={"verify_exp": True, "verify_aud": False})
        payload["_correlation_id"] = correlation_id
        log("INFO", "jwt_verified", correlation_id=correlation_id,
            sub=payload.get("sub","?")[:8]+"...",
            roles=payload.get("realm_access",{}).get("roles",[]))
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        log("WARN", "jwt_invalid", correlation_id=correlation_id, error=str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(*roles):
    async def check(payload: dict = Depends(verify_jwt)):
        user_roles = payload.get("realm_access",{}).get("roles",[])
        if not any(r in user_roles for r in roles):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return payload
    return check

# Fake DB — resources có owner_id để test BOLA
FAKE_RESOURCES = {
    "res-001": {"id": "res-001", "name": "Order #1", "owner_id": "660a0175-851a-41e9-b861-a1ef7e746e99", "amount": 100},
    "res-002": {"id": "res-002", "name": "Order #2", "owner_id": "admin-uuid-0001", "amount": 200},
    "res-003": {"id": "res-003", "name": "Order #3", "owner_id": "660a0175-851a-41e9-b861-a1ef7e746e99", "amount": 300},
}

app = FastAPI(title="resources-api")

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/api/resources")
async def list_resources(payload: dict = Depends(verify_jwt)):
    """
    List resources — user chỉ thấy resources của mình (BOLA).
    Admin thấy tất cả.
    """
    sub = payload["sub"]
    user_roles = payload.get("realm_access",{}).get("roles",[])
    is_admin = "admin" in user_roles
    if is_admin:
        result = list(FAKE_RESOURCES.values())
    else:
        result = [r for r in FAKE_RESOURCES.values() if r["owner_id"] == sub]
    log("INFO", "list_resources",
        correlation_id=payload.get("_correlation_id"),
        sub=sub[:8]+"...", count=len(result), is_admin=is_admin)
    return result

@app.get("/api/resources/{resource_id}")
async def get_resource(resource_id: str, payload: dict = Depends(verify_jwt)):
    """BOLA: chỉ owner hoặc admin mới xem được"""
    sub = payload["sub"]
    user_roles = payload.get("realm_access",{}).get("roles",[])
    is_admin = "admin" in user_roles
    resource = FAKE_RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    if not is_admin and resource["owner_id"] != sub:
        log("WARN", "bola_attempt",
            correlation_id=payload.get("_correlation_id"),
            attacker=sub[:8]+"...", resource=resource_id)
        raise HTTPException(status_code=403, detail="Access denied")
    return resource

@app.post("/api/resources")
async def create_resource(body: dict, payload: dict = Depends(verify_jwt)):
    """Tạo resource — tự động gán owner_id = sub của người tạo"""
    sub = payload["sub"]
    new_id = "res-" + str(uuid.uuid4())[:6]
    resource = {"id": new_id, "owner_id": sub, **body}
    FAKE_RESOURCES[new_id] = resource
    log("INFO", "create_resource",
        correlation_id=payload.get("_correlation_id"),
        sub=sub[:8]+"...", resource_id=new_id)
    return resource

@app.delete("/api/resources/{resource_id}")
async def delete_resource(resource_id: str, payload: dict = Depends(verify_jwt)):
    """Xóa resource — chỉ owner hoặc admin"""
    sub = payload["sub"]
    user_roles = payload.get("realm_access",{}).get("roles",[])
    is_admin = "admin" in user_roles
    resource = FAKE_RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    if not is_admin and resource["owner_id"] != sub:
        raise HTTPException(status_code=403, detail="Access denied")
    del FAKE_RESOURCES[resource_id]
    return {"deleted": resource_id}
