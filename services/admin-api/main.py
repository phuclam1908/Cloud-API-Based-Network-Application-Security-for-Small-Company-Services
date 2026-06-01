from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt, os, json, uuid, subprocess, requests
from datetime import datetime

JWKS_URL = os.getenv("JWKS_URL",
    "http://keycloak.keycloak.svc.cluster.local/realms/company/protocol/openid-connect/certs")
KC_BASE = os.getenv("KC_BASE", "http://keycloak.keycloak.svc.cluster.local")
KC_REALM = os.getenv("KC_REALM", "company")
KC_ADMIN_USER = os.getenv("KC_ADMIN_USER", "admin")
KC_ADMIN_PASS = os.getenv("KC_ADMIN_PASS", "Admin1234!")
DB_HOST = os.getenv("DB_HOST", "shop-postgres-postgresql.apps.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "shopdb")
DB_USER = os.getenv("DB_USER", "shop")
DB_PASS = os.getenv("DB_PASS", "shop_db_pass_123")
ALGORITHM = "RS256"
SERVICE_NAME = "admin-api"

def log(level, event, **kwargs):
    print(json.dumps({
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "service": SERVICE_NAME, "level": level, "event": event, **kwargs
    }), flush=True)

def db_query_json(sql):
    wrapped = f"SELECT row_to_json(t) FROM ({sql}) t"
    env = os.environ.copy()
    env['PGPASSWORD'] = DB_PASS
    cmd = ['psql', '-h', DB_HOST, '-U', DB_USER, '-d', DB_NAME, '-t', '-A', '--no-psqlrc', '-c', wrapped]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
    rows = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line.startswith('{'):
            try:
                rows.append(json.loads(line))
            except:
                pass
    return rows

def db_execute(sql):
    env = os.environ.copy()
    env['PGPASSWORD'] = DB_PASS
    cmd = ['psql', '-h', DB_HOST, '-U', DB_USER, '-d', DB_NAME, '-t', '-A', '--no-psqlrc', '-c', sql]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
    return result.stdout.strip()

def get_kc_admin_token():
    resp = requests.post(
        f"{KC_BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type":"password","client_id":"admin-cli",
              "username":KC_ADMIN_USER,"password":KC_ADMIN_PASS},
        timeout=10
    )
    return resp.json().get("access_token","")

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
        payload = jwt.decode(token, signing_key.key, algorithms=[ALGORITHM],
            options={"verify_exp": True, "verify_aud": False})
        payload["_correlation_id"] = correlation_id
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        log("WARN", "jwt_invalid", error=str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(payload: dict = Depends(verify_jwt)):
    user_roles = payload.get("realm_access",{}).get("roles",[])
    if "admin" not in user_roles:
        log("WARN", "admin_rbac_denied", roles=user_roles)
        raise HTTPException(status_code=403, detail="Admin only")
    return payload

app = FastAPI(title="admin-api")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

# ── STATS ─────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
async def get_stats(payload: dict = Depends(require_admin)):
    try:
        kc_token = get_kc_admin_token()
        # Lấy users từ Keycloak
        users_resp = requests.get(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users?max=1000",
            headers={"Authorization": f"Bearer {kc_token}"}, timeout=10)
        total_users = len(users_resp.json()) if users_resp.ok else 0

        # Lấy orders từ DB
        orders = db_query_json("SELECT COUNT(*) as count FROM orders")
        total_orders = orders[0].get('count', 0) if orders else 0

        # Tổng doanh thu
        revenue = db_query_json("SELECT COALESCE(SUM(total),0) as total FROM orders WHERE status != 'cancelled'")
        total_revenue = revenue[0].get('total', 0) if revenue else 0

        # Sản phẩm
        products = db_query_json("SELECT COUNT(*) as count FROM products")
        total_products = products[0].get('count', 0) if products else 0

        log("INFO", "get_stats", sub=payload.get("sub","?")[:8]+"...")
        return {
            "total_users": total_users,
            "total_orders": total_orders,
            "total_revenue": total_revenue,
            "total_products": total_products,
            "system": "healthy"
        }
    except Exception as e:
        return {"total_users": 0, "total_orders": 0, "total_revenue": 0,
                "total_products": 0, "system": str(e)}

# ── USERS ─────────────────────────────────────────────────────────
@app.get("/api/admin/users")
async def list_users(payload: dict = Depends(require_admin)):
    try:
        kc_token = get_kc_admin_token()
        resp = requests.get(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users?max=100",
            headers={"Authorization": f"Bearer {kc_token}"}, timeout=10)
        users = resp.json() if resp.ok else []
        # Lấy roles cho mỗi user
        result = []
        for u in users:
            roles_resp = requests.get(
                f"{KC_BASE}/admin/realms/{KC_REALM}/users/{u['id']}/role-mappings/realm",
                headers={"Authorization": f"Bearer {kc_token}"}, timeout=10)
            roles = [r['name'] for r in roles_resp.json() if roles_resp.ok
                     and r['name'] not in ['default-roles-company','offline_access','uma_authorization']]
            result.append({
                "id": u['id'],
                "username": u.get('username',''),
                "email": u.get('email',''),
                "enabled": u.get('enabled', True),
                "created": u.get('createdTimestamp', 0),
                "roles": roles
            })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/users/{user_id}/disable")
async def disable_user(user_id: str, payload: dict = Depends(require_admin)):
    try:
        kc_token = get_kc_admin_token()
        resp = requests.put(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users/{user_id}",
            headers={"Authorization": f"Bearer {kc_token}",
                     "Content-Type": "application/json"},
            json={"enabled": False}, timeout=10)
        if not resp.ok:
            raise HTTPException(status_code=400, detail="Failed to disable user")
        log("INFO", "disable_user", target=user_id[:8]+"...",
            by=payload.get("sub","?")[:8]+"...")
        return {"status": "disabled", "user_id": user_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/users/{user_id}/enable")
async def enable_user(user_id: str, payload: dict = Depends(require_admin)):
    try:
        kc_token = get_kc_admin_token()
        resp = requests.put(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users/{user_id}",
            headers={"Authorization": f"Bearer {kc_token}",
                     "Content-Type": "application/json"},
            json={"enabled": True}, timeout=10)
        if not resp.ok:
            raise HTTPException(status_code=400, detail="Failed to enable user")
        return {"status": "enabled", "user_id": user_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── ORDERS ────────────────────────────────────────────────────────
@app.get("/api/admin/orders")
async def list_orders(payload: dict = Depends(require_admin)):
    try:
        orders = db_query_json("SELECT * FROM orders ORDER BY created_at DESC LIMIT 100")
        return orders
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/admin/orders/{order_id}/status")
async def update_order_status(order_id: int, body: dict,
    payload: dict = Depends(require_admin)):
    status = body.get("status")
    if status not in ["pending","processing","shipped","delivered","cancelled"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    try:
        rows = db_query_json(f"""
            UPDATE orders SET status='{status}', updated_at=NOW()
            WHERE id={order_id} RETURNING *
        """)
        if not rows:
            raise HTTPException(status_code=404, detail="Order not found")
        log("INFO", "order_status_updated", order_id=order_id, status=status,
            by=payload.get("sub","?")[:8]+"...")
        return rows[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── PRODUCTS ──────────────────────────────────────────────────────
@app.get("/api/admin/products")
async def list_products(payload: dict = Depends(require_admin)):
    try:
        return db_query_json("SELECT * FROM products ORDER BY id")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/products")
async def create_product(body: dict, payload: dict = Depends(require_admin)):
    try:
        name = body['name'].replace("'","''")
        desc = body.get('description','').replace("'","''")
        price = int(body['price'])
        old_price = f"{int(body['old_price'])}" if body.get('old_price') else 'NULL'
        cat = body.get('category','other').replace("'","''")
        img = body.get('image_url','').replace("'","''")
        stock = int(body.get('stock',0))
        rows = db_query_json(f"""
            INSERT INTO products (name,description,price,old_price,category,image_url,stock)
            VALUES ('{name}','{desc}',{price},{old_price},'{cat}','{img}',{stock})
            RETURNING *
        """)
        return rows[0] if rows else {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/products/{product_id}")
async def update_product(product_id: int, body: dict,
    payload: dict = Depends(require_admin)):
    try:
        fields = []
        if 'name' in body: fields.append(f"name='{body['name'].replace(chr(39),chr(39)*2)}'")
        if 'price' in body: fields.append(f"price={int(body['price'])}")
        if 'old_price' in body: fields.append(f"old_price={int(body['old_price'])}" if body['old_price'] else "old_price=NULL")
        if 'stock' in body: fields.append(f"stock={int(body['stock'])}")
        if 'category' in body: fields.append(f"category='{body['category']}'")
        if 'image_url' in body: fields.append(f"image_url='{body['image_url']}'")
        if not fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        rows = db_query_json(f"""
            UPDATE products SET {','.join(fields)} WHERE id={product_id} RETURNING *
        """)
        if not rows:
            raise HTTPException(status_code=404, detail="Product not found")
        return rows[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/products/{product_id}")
async def delete_product(product_id: int, payload: dict = Depends(require_admin)):
    try:
        db_execute(f"DELETE FROM products WHERE id={product_id}")
        return {"status": "deleted", "id": product_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── AUDIT LOG ─────────────────────────────────────────────────────
@app.get("/api/admin/audit-log")
async def get_audit_log(payload: dict = Depends(require_admin)):
    try:
        kc_token = get_kc_admin_token()
        resp = requests.get(
            f"{KC_BASE}/admin/realms/{KC_REALM}/events?max=50",
            headers={"Authorization": f"Bearer {kc_token}"}, timeout=10)
        events = resp.json() if resp.ok else []
        return [{
            "time": datetime.fromtimestamp(e.get('time',0)/1000).isoformat(),
            "type": e.get('type',''),
            "user": e.get('details',{}).get('username', e.get('userId','')),
            "ip": e.get('ipAddress',''),
            "client": e.get('clientId','')
        } for e in events]
    except Exception as e:
        return []
