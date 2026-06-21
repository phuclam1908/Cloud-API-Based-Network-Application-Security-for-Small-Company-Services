from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt, os, json, uuid, subprocess
from datetime import datetime

JWKS_URL = os.getenv("JWKS_URL",
    "http://keycloak.keycloak.svc.cluster.local/realms/company/protocol/openid-connect/certs")
DB_HOST = os.getenv("DB_HOST", "shop-postgres-postgresql.apps.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "shopdb")
DB_USER = os.getenv("DB_USER", "shop")
DB_PASS = os.getenv("DB_PASS", "shop_db_pass_123")
ALGORITHM = "ES256"
SERVICE_NAME = "shop-api"

def log(level, event, **kwargs):
    print(json.dumps({
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "service": SERVICE_NAME, "level": level, "event": event, **kwargs
    }), flush=True)

def db_query(sql, params=None):
    """Chạy SQL qua psql CLI, trả về list of dicts"""
    if params:
        for p in params:
            if isinstance(p, str):
                sql = sql.replace('%s', f"$${p}$$", 1)
            elif p is None:
                sql = sql.replace('%s', 'NULL', 1)
            else:
                sql = sql.replace('%s', str(p), 1)
    
    env = os.environ.copy()
    env['PGPASSWORD'] = DB_PASS
    
    cmd = ['psql', '-h', DB_HOST, '-U', DB_USER, '-d', DB_NAME,
           '-t', '-A', '-F', '\t', '--no-psqlrc', '-c', sql]
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
    
    if result.returncode != 0:
        raise Exception(f"DB error: {result.stderr}")
    
    lines = [l for l in result.stdout.strip().split('\n') if l]
    return lines

def db_query_json(sql, params=None):
    """Chạy SQL với JSON output"""
    wrapped = f"SELECT row_to_json(t) FROM ({sql}) t"
    if params:
        for p in params:
            if isinstance(p, str):
                wrapped = wrapped.replace('%s', f"$${p}$$", 1)
            elif p is None:
                wrapped = wrapped.replace('%s', 'NULL', 1)
            else:
                wrapped = wrapped.replace('%s', str(p), 1)
    
    env = os.environ.copy()
    env['PGPASSWORD'] = DB_PASS
    
    cmd = ['psql', '-h', DB_HOST, '-U', DB_USER, '-d', DB_NAME,
           '-t', '-A', '--no-psqlrc', '-c', wrapped]
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
    if result.returncode != 0:
        raise Exception(f"DB error: {result.stderr}")
    
    rows = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line.startswith('{'):
            try:
                rows.append(json.loads(line))
            except:
                pass
    return rows

def db_execute(sql, params=None):
    """Chạy SQL không cần kết quả (INSERT/UPDATE/DELETE)"""
    if params:
        for p in params:
            if isinstance(p, str):
                escaped = p.replace("'", "''")
                sql = sql.replace('%s', f"'{escaped}'", 1)
            elif p is None:
                sql = sql.replace('%s', 'NULL', 1)
            elif isinstance(p, (dict, list)):
                escaped = json.dumps(p).replace("'", "''")
                sql = sql.replace('%s', f"'{escaped}'", 1)
            else:
                sql = sql.replace('%s', str(p), 1)
    
    env = os.environ.copy()
    env['PGPASSWORD'] = DB_PASS
    
    cmd = ['psql', '-h', DB_HOST, '-U', DB_USER, '-d', DB_NAME,
           '-t', '-A', '--no-psqlrc', '-c', sql]
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
    if result.returncode != 0:
        raise Exception(f"DB error: {result.stderr}")
    return result.stdout.strip()

_jwks_client = None
def get_jwks_client():
    global _jwks_client
    if not _jwks_client:
        _jwks_client = jwt.PyJWKClient(JWKS_URL)
    return _jwks_client

security = HTTPBearer(auto_error=False)

async def verify_jwt(request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="No token")
    token = credentials.credentials
    correlation_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key,
            algorithms=[ALGORITHM],
            options={"verify_exp": True, "verify_aud": False})
        payload["_correlation_id"] = correlation_id
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

async def optional_jwt(request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        return {}
    try:
        return await verify_jwt(request, credentials)
    except:
        return {}

def require_role(*roles):
    async def check(payload: dict = Depends(verify_jwt)):
        user_roles = payload.get("realm_access",{}).get("roles",[])
        if not any(r in user_roles for r in roles):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return payload
    return check

app = FastAPI(title="shop-api")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    # Test DB connection
    try:
        db_query("SELECT 1")
        db_ok = True
    except:
        db_ok = False
    return {"status": "ok", "service": SERVICE_NAME, "db": db_ok}

# ── PRODUCTS ──────────────────────────────────────────────────────
@app.get("/api/shop/products")
async def list_products(category: str = None):
    try:
        if category:
            rows = db_query_json(
                f"SELECT * FROM products WHERE category='{category}' ORDER BY sold_count DESC")
        else:
            rows = db_query_json("SELECT * FROM products ORDER BY sold_count DESC")
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/shop/products/{product_id}")
async def get_product(product_id: int):
    try:
        rows = db_query_json(f"SELECT * FROM products WHERE id={product_id}")
        if not rows:
            raise HTTPException(status_code=404, detail="Product not found")
        return rows[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/shop/products")
async def create_product(body: dict, payload: dict = Depends(require_role("admin"))):
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

# ── CART ──────────────────────────────────────────────────────────
@app.get("/api/shop/cart")
async def get_cart(payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    try:
        rows = db_query_json(f"SELECT items FROM cart WHERE user_id='{sub}'")
        return {"items": rows[0]["items"] if rows else []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/shop/cart")
async def update_cart(body: dict, payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    items = body.get("items", [])
    items_json = json.dumps(items).replace("'","''")
    try:
        db_execute(f"""
            INSERT INTO cart (user_id, items, updated_at)
            VALUES ('{sub}', '{items_json}', NOW())
            ON CONFLICT (user_id) DO UPDATE SET items='{items_json}', updated_at=NOW()
        """)
        log("INFO", "cart_updated", sub=sub[:8]+"...", item_count=len(items))
        return {"status": "ok", "item_count": len(items)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── ORDERS ────────────────────────────────────────────────────────
@app.get("/api/shop/orders")
async def list_orders(payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        if is_admin:
            rows = db_query_json("SELECT * FROM orders ORDER BY created_at DESC LIMIT 50")
        else:
            rows = db_query_json(f"SELECT * FROM orders WHERE user_id='{sub}' ORDER BY created_at DESC")
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/shop/orders/{order_id}")
async def get_order(order_id: int, payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        rows = db_query_json(f"SELECT * FROM orders WHERE id={order_id}")
        if not rows:
            raise HTTPException(status_code=404, detail="Order not found")
        order = rows[0]
        if not is_admin and order["user_id"] != sub:
            log("WARN", "bola_attempt", attacker=sub[:8]+"...", order_id=order_id)
            raise HTTPException(status_code=403, detail="Access denied")
        return order
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/shop/orders")
async def create_order(body: dict, payload: dict = Depends(verify_jwt)):
    sub = payload["sub"]
    items = body.get("items", [])
    if not items:
        raise HTTPException(status_code=400, detail="No items")
    total = sum(i.get("price",0) * i.get("qty",1) for i in items)
    items_json = json.dumps(items)
    addr_json = json.dumps(body.get("shipping_address",{}))
    try:
        db_execute("""
            INSERT INTO orders (user_id, items, total, status, shipping_address)
            VALUES (%s, %s, %s, 'pending', %s)
        """, params=[sub, items_json, total, addr_json])
        rows = db_query_json(f"SELECT * FROM orders WHERE user_id='{sub}' ORDER BY id DESC LIMIT 1")

        order = rows[0] if rows else {}
        log("INFO", "order_created", sub=sub[:8]+"...", order_id=order.get("id"), total=total)
        return order
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/shop/orders/{order_id}/status")
async def update_order_status(order_id: int, body: dict,
    payload: dict = Depends(require_role("admin"))):
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
        return rows[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── SELLER ENDPOINTS ──────────────────────────────────────────────
def require_seller_or_admin():
    async def check(payload: dict = Depends(verify_jwt)):
        roles = payload.get("realm_access",{}).get("roles",[])
        if not any(r in roles for r in ["seller","admin"]):
            raise HTTPException(status_code=403, detail="Seller or admin only")
        return payload
    return check

@app.get("/api/shop/seller/products")
async def seller_list_products(payload: dict = Depends(require_seller_or_admin())):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        if is_admin:
            rows = db_query_json("SELECT * FROM products ORDER BY id")
        else:
            rows = db_query_json(f"SELECT * FROM products WHERE seller_id='{sub}' ORDER BY id")
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/shop/seller/products")
async def seller_create_product(body: dict, payload: dict = Depends(require_seller_or_admin())):
    sub = payload["sub"]
    try:
        name = body['name'].replace("'","''")
        desc = body.get('description','').replace("'","''")
        price = int(body['price'])
        old_price = f"{int(body['old_price'])}" if body.get('old_price') else 'NULL'
        cat = body.get('category','other').replace("'","''")
        img = body.get('image_url','').replace("'","''")
        stock = int(body.get('stock',0))
        db_execute(f"""
            INSERT INTO products (name,description,price,old_price,category,image_url,stock,seller_id)
            VALUES ('{name}','{desc}',{price},{old_price},'{cat}','{img}',{stock},'{sub}')
        """)
        rows = db_query_json(f"SELECT * FROM products WHERE name='{name}' AND seller_id='{sub}' ORDER BY id DESC LIMIT 1")
        return rows[0] if rows else {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/shop/seller/products/{product_id}")
async def seller_update_product(product_id: int, body: dict,
    payload: dict = Depends(require_seller_or_admin())):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        # BOLA check — seller chỉ sửa sản phẩm của mình
        rows = db_query_json(f"SELECT seller_id FROM products WHERE id={product_id}")
        if not rows:
            raise HTTPException(status_code=404, detail="Product not found")
        if not is_admin and rows[0].get('seller_id') != sub:
            log("WARN", "bola_attempt_seller", attacker=sub[:8]+"...", product_id=product_id)
            raise HTTPException(status_code=403, detail="Access denied")
        fields = []
        if 'name' in body: fields.append(f"name='{body['name'].replace(chr(39),chr(39)*2)}'")
        if 'price' in body: fields.append(f"price={int(body['price'])}")
        if 'stock' in body: fields.append(f"stock={int(body['stock'])}")
        if 'category' in body: fields.append(f"category='{body['category']}'")
        if 'image_url' in body: fields.append(f"image_url='{body['image_url']}'")
        if not fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        updated = db_query_json(f"UPDATE products SET {','.join(fields)} WHERE id={product_id} RETURNING *")
        return updated[0] if updated else {}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/shop/seller/products/{product_id}")
async def seller_delete_product(product_id: int,
    payload: dict = Depends(require_seller_or_admin())):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        rows = db_query_json(f"SELECT seller_id FROM products WHERE id={product_id}")
        if not rows:
            raise HTTPException(status_code=404, detail="Product not found")
        if not is_admin and rows[0].get('seller_id') != sub:
            log("WARN", "bola_attempt_seller_delete", attacker=sub[:8]+"...", product_id=product_id)
            raise HTTPException(status_code=403, detail="Access denied")
        db_execute(f"DELETE FROM products WHERE id={product_id}")
        return {"status": "deleted", "id": product_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/shop/seller/orders")
async def seller_orders(payload: dict = Depends(require_seller_or_admin())):
    sub = payload["sub"]
    is_admin = "admin" in payload.get("realm_access",{}).get("roles",[])
    try:
        if is_admin:
            rows = db_query_json("SELECT * FROM orders ORDER BY created_at DESC")
        else:
            # Orders chứa sản phẩm của seller này
            rows = db_query_json(f"""
                SELECT DISTINCT o.* FROM orders o,
                json_array_elements(o.items) item
                WHERE item->>'id' IN (
                    SELECT id::text FROM products WHERE seller_id='{sub}'
                )
                ORDER BY o.created_at DESC
            """)
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
