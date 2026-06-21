#!/bin/bash
# Chuyển Kong + Keycloak từ RS256 sang ES256
# Usage: bash manifests/kong/setup-es256.sh
set -e

KC_ADMIN_USER="admin"
KC_ADMIN_PASS="Admin1234!"
KC_REALM="company"
CONSUMER="keycloak-issuer"

# ── Lấy IPs ────────────────────────────────────────────────────────
KC_IP=$(kubectl get svc -n keycloak keycloak -o jsonpath='{.spec.clusterIP}')
KONG_ADMIN=$(kubectl get svc -n kong kong-kong-admin -o jsonpath='{.spec.clusterIP}')
KC_BASE="http://${KC_IP}"
KONG_URL="http://${KONG_ADMIN}:8001"

echo "Keycloak: ${KC_BASE}"
echo "Kong Admin: ${KONG_URL}"

# ── 1. Lấy admin token Keycloak ────────────────────────────────────
echo ""
echo "[1/4] Lấy Keycloak admin token..."
KC_TOKEN=$(curl -sf -X POST \
  "${KC_BASE}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=${KC_ADMIN_USER}&password=${KC_ADMIN_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# ── 2. Thêm ECDSA key provider vào Keycloak realm ──────────────────
echo "[2/4] Cấu hình Keycloak dùng ES256 (ecdsa-generated)..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${KC_BASE}/admin/realms/${KC_REALM}/components" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ecdsa-p256",
    "providerId": "ecdsa-generated",
    "providerType": "org.keycloak.keys.KeyProvider",
    "config": {
      "priority": ["200"],
      "enabled": ["true"],
      "active": ["true"],
      "ecdsaEllipticCurveKey": ["P-256"]
    }
  }')

if [ "$HTTP" = "201" ] || [ "$HTTP" = "409" ]; then
  echo "  OK (http $HTTP)"
else
  echo "  WARN: http $HTTP — có thể đã tồn tại hoặc lỗi"
fi

# ── 3. Lấy EC public key (PEM) từ Keycloak ─────────────────────────
echo "[3/4] Lấy EC public key từ Keycloak..."
# Refresh token sau khi tạo key mới
KC_TOKEN=$(curl -sf -X POST \
  "${KC_BASE}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=${KC_ADMIN_USER}&password=${KC_ADMIN_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

EC_PUBLIC_KEY=$(curl -sf \
  "${KC_BASE}/admin/realms/${KC_REALM}/keys" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for k in data.get('keys', []):
    if k.get('algorithm') == 'ES256' and k.get('status') == 'ACTIVE':
        pk = k.get('publicKey', '')
        if pk:
            print('-----BEGIN PUBLIC KEY-----')
            # wrap at 64 chars
            for i in range(0, len(pk), 64):
                print(pk[i:i+64])
            print('-----END PUBLIC KEY-----')
            break
")

if [ -z "$EC_PUBLIC_KEY" ]; then
  echo "  ERROR: Không tìm thấy EC public key ES256 ACTIVE trong Keycloak"
  echo "  Đảm bảo Keycloak đã restart và key provider đã được kích hoạt"
  exit 1
fi
echo "  Tìm thấy EC public key."

# ── 4. Cập nhật Kong consumer credential ───────────────────────────
echo "[4/4] Cập nhật Kong JWT credential (ES256)..."

# Xóa credential RS256 cũ nếu có
OLD_CRED_ID=$(curl -sf "${KONG_URL}/consumers/${CONSUMER}/jwt" \
  | python3 -c "
import sys, json
creds = json.load(sys.stdin).get('data', [])
for c in creds:
    if c.get('algorithm') in ['RS256', 'ES256']:
        print(c['id'])
        break
" 2>/dev/null || true)

if [ -n "$OLD_CRED_ID" ]; then
  curl -sf -X DELETE "${KONG_URL}/consumers/${CONSUMER}/jwt/${OLD_CRED_ID}" > /dev/null
  echo "  Đã xóa credential cũ: ${OLD_CRED_ID}"
fi

# Tạo credential ES256 mới
ISSUER_KEY="http://${KC_IP}/realms/${KC_REALM}"
HTTP=$(curl -s -o /tmp/kong_cred.json -w "%{http_code}" -X POST \
  "${KONG_URL}/consumers/${CONSUMER}/jwt" \
  --data-urlencode "algorithm=ES256" \
  --data-urlencode "key=${ISSUER_KEY}" \
  --data-urlencode "ecdsa_public_key=${EC_PUBLIC_KEY}")

if [ "$HTTP" = "201" ]; then
  CRED_ID=$(python3 -c "import json; print(json.load(open('/tmp/kong_cred.json'))['id'])")
  echo "  OK — credential mới: ${CRED_ID}"
else
  echo "  ERROR: http $HTTP"
  cat /tmp/kong_cred.json
  exit 1
fi

# Cập nhật jwt-credential.txt để lưu lại
CRED_FILE="$(dirname "$0")/jwt-credential.txt"
cat > "${CRED_FILE}" << EOF
# Kong JWT Credential cho consumer keycloak-issuer
# Tạo bằng lệnh:
# curl -X POST http://localhost:30528/consumers/keycloak-issuer/jwt #   -F "algorithm=ES256" #   -F "key=http://KEYCLOAK_CLUSTERIP/realms/company" #   -F "ecdsa_public_key=<nội dung bên dưới>"
#
# LƯU Ý: Public key thay đổi nếu Keycloak restart và rotate key
# Cần chạy lại lệnh tạo credential sau mỗi lần deploy mới

ALGORITHM=ES256
KEY=${ISSUER_KEY}
PUBLIC_KEY:
${EC_PUBLIC_KEY}
EOF
echo "  Đã cập nhật jwt-credential.txt"

echo ""
echo "=== XONG ==="
echo "Keycloak realm '${KC_REALM}' đã có ES256 key active."
echo "Kong consumer '${CONSUMER}' đã dùng ES256 + ecdsa_public_key."
echo ""
echo "Kiểm tra bằng cách lấy token từ Keycloak và decode header:"
echo "  curl -s <token> | cut -d. -f1 | base64 -d | python3 -m json.tool"
echo "  → alg phải là ES256"
