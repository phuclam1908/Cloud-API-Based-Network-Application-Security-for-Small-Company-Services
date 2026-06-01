# ================================================================
#  webhook-svc — Webhook Handler với HMAC-SHA256
#
#  Lý thuyết:
#  Stripe/Twilio ký payload bằng shared secret (HMAC-SHA256)
#  gửi signature trong header X-Webhook-Signature.
#  Server verify lại — nếu không khớp → reject 401.
#  Timestamp check → reject nếu request cũ hơn 5 phút (replay attack).
#
#  Replay attack: attacker capture request hợp lệ, gửi lại sau.
#  Fix: server check timestamp trong payload, reject nếu >5 phút.
#
#  Ref: https://stripe.com/docs/webhooks/signatures
#       OWASP API8:2023 - Security Misconfiguration
# ================================================================

from fastapi import FastAPI, Request, HTTPException, Header
import hmac, hashlib, json, os, time
from datetime import datetime
from typing import Optional

SERVICE_NAME = "webhook-svc"

# Shared secret — trong production lưu trong Vault
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "nt219-webhook-secret-key-2026")
MAX_TIMESTAMP_DIFF = 300  # 5 phút

def log(level, event, **kwargs):
    print(json.dumps({
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "service": SERVICE_NAME,
        "level": level,
        "event": event,
        **kwargs
    }), flush=True)

def verify_signature(payload: bytes, signature: str, timestamp: str) -> bool:
    """
    Verify HMAC-SHA256 signature.
    
    Stripe format: HMAC-SHA256(secret, timestamp + "." + payload)
    Signature gửi trong header: X-Webhook-Signature: t=<timestamp>,v1=<sig>
    
    Tại sao include timestamp vào signature?
    → Attacker không thể reuse signature cũ vì timestamp khác
    → Phải có secret mới tạo được signature mới
    """
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        f"{timestamp}.".encode() + payload,
        hashlib.sha256
    ).hexdigest()
    
    # hmac.compare_digest chống timing attack
    # Nếu dùng == thì attacker có thể đo thời gian response
    # để đoán từng byte của signature
    return hmac.compare_digest(expected, signature)

app = FastAPI(title="webhook-svc")

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.post("/api/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    x_webhook_signature: Optional[str] = Header(None),
    x_webhook_timestamp: Optional[str] = Header(None)
):
    """
    Nhận Stripe webhook event.
    
    Headers cần có:
    - X-Webhook-Signature: HMAC-SHA256 signature
    - X-Webhook-Timestamp: Unix timestamp lúc gửi
    
    Flow:
    1. Check timestamp tồn tại
    2. Check timestamp không quá 5 phút (replay protection)
    3. Verify HMAC signature
    4. Process event
    """
    payload = await request.body()
    client_ip = request.client.host

    # Check headers
    if not x_webhook_signature or not x_webhook_timestamp:
        log("WARN", "webhook_missing_headers",
            ip=client_ip,
            has_sig=bool(x_webhook_signature),
            has_ts=bool(x_webhook_timestamp))
        raise HTTPException(status_code=401,
            detail="Missing signature headers")

    # Replay protection: check timestamp
    try:
        ts = int(x_webhook_timestamp)
        age = int(time.time()) - ts
        if age > MAX_TIMESTAMP_DIFF:
            log("WARN", "webhook_replay_attempt",
                ip=client_ip,
                age_seconds=age,
                max_allowed=MAX_TIMESTAMP_DIFF)
            raise HTTPException(status_code=401,
                detail=f"Request too old: {age}s > {MAX_TIMESTAMP_DIFF}s")
        if age < -60:  # clock skew tolerance
            log("WARN", "webhook_future_timestamp",
                ip=client_ip, age_seconds=age)
            raise HTTPException(status_code=401,
                detail="Invalid timestamp")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp format")

    # Verify HMAC signature
    if not verify_signature(payload, x_webhook_signature, x_webhook_timestamp):
        log("WARN", "signature_invalid",
            ip=client_ip,
            timestamp=x_webhook_timestamp)
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse và process event
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type", "unknown")
    log("INFO", "webhook_received",
        ip=client_ip,
        event_type=event_type,
        timestamp=x_webhook_timestamp)

    # Handle event types
    if event_type == "payment.success":
        log("INFO", "payment_success",
            amount=event.get("data", {}).get("amount"),
            currency=event.get("data", {}).get("currency"))
        return {"status": "processed", "event": event_type}

    elif event_type == "payment.failed":
        log("WARN", "payment_failed",
            reason=event.get("data", {}).get("reason"))
        return {"status": "processed", "event": event_type}

    else:
        log("INFO", "webhook_unknown_event", event_type=event_type)
        return {"status": "ignored", "event": event_type}

@app.post("/api/webhooks/test")
async def test_webhook(request: Request):
    """
    Endpoint test không cần signature — chỉ dùng cho demo
    Trong production KHÔNG có endpoint này
    """
    payload = await request.body()
    event = json.loads(payload) if payload else {}
    log("INFO", "test_webhook_received", event=event)
    return {"status": "received", "event": event}
