# Bảo mật Ứng dụng Mạng Dựa trên API trên Cloud cho Dịch vụ Công ty Nhỏ

**Môn học:** NT219 - Cryptography  
**Tiêu đề:** Cloud API-Based Network Application Security for Small Company Services  


---

## Tổng quan

Đề tài thiết kế, triển khai và đánh giá một hệ thống API-first cho dịch vụ công ty nhỏ (mô hình ShopSME - e-commerce microservice), tập trung vào:

- Bảo vệ mặt phẳng API (authentication, authorization, token management)
- Bảo vệ luồng mạng (TLS, network segmentation, egress filtering)
- Giải pháp tiết kiệm chi phí, dễ vận hành cho SME
- Khả năng phát hiện và phản ứng (logging, alerting, SIEM nhẹ)
- Thực hành pentest và hardening (OWASP API Top 10)

---

## Hạ tầng

| Thành phần | Phiên bản | Namespace |
|-----------|---------|-----------|
| Kubernetes | v1.30.14 |  |
| Calico CNI | v3.27 | kube-system |
| Keycloak | 24.0.3 | keycloak |
| Kong API Gateway | 3.9.1 | kong |
| PostgreSQL | latest | keycloak, kong, apps |
| HashiCorp Vault | latest | vault |
| Loki + Grafana | latest | monitoring |

**Cloud:** AWS EC2 m7i-flex.large (2 vCPU, 8GB RAM, 30GB EBS)  
**Region:** ap-southeast-2 (Sydney)  
**Domain:** 16-176-66-207.nip.io  
**TLS:** ZeroSSL ECC P-256 (valid 2026-05-31 đến 2026-08-29)

---

## Các tính năng bảo mật

### Xác thực và phân quyền
- OAuth2 + OIDC với PKCE (Authorization Code Flow) cho public clients
- JWT ES256 — được verify tại Kong API Gateway
- 3 roles: `admin`, `seller`, `user`
- RBAC enforcement tại FastAPI layer
- Access token ngắn hạn: 300 giây
- Refresh token: 1800 giây

### Bảo mật API
- JWT plugin trên tất cả các protected routes
- Rate limiting: 60 request/phút, 1000 request/giờ (global)
- CORS policy
- Request size limiting: 4MB
- Correlation ID tracing (X-Request-Id)

### Bảo mật mạng
- TLS 1.3 HTTPS (ZeroSSL ECC P-256)
- NetworkPolicy chặn truy cập metadata service (169.254.169.254)
- mTLS certificates tạo bằng ECDSA P-256 (Kong với các services)
- Calico CNI network segmentation

### Quản lý Secrets
- HashiCorp Vault KV v2
- AppRole authentication cho microservices
- Least privilege policy - mỗi service chỉ đọc secrets cần thiết

### Bảo mật Webhook
- HMAC-SHA256 signature verification
- Replay protection (timestamp + nonce)
- Endpoint: `/api/webhooks/stripe`

### Giám sát và SIEM
- Loki + Grafana dashboard
- 6 alert rules: failed auth spike, rate limit breach, BOLA attempts, anomaly detection

---

## Microservices

| Service | Port | Chức năng |
|---------|------|-----------|
| users-api | 8000 | Quản lý thông tin user, BOLA check |
| resources-api | 8000 | Resource CRUD, ownership check |
| admin-api | 8000 | Admin dashboard, quản lý users/orders/products |
| webhook-svc | 8000 | Xử lý webhook với HMAC verify |
| shop-api | 8000 | E-commerce: products, cart, orders |
| frontend | 80 | ShopSME SPA (HTML/JS, PKCE auth) |

### Kong Routes và JWT Protection

| Route | Path | JWT |
|-------|------|-----|
| users-route | /api/users | Có |
| resources-route | /api/resources | Có |
| admin-route | /api/admin | Có |
| shop-route | /api/shop | Có |
| seller-route | /api/shop/seller | Có |
| shop-products-route | /api/shop/products | Không (public) |
| webhook-route | /api/webhooks | Không (HMAC auth) |
| keycloak-route | /realms, /resources | Không |
| frontend-route | / | Không |

---

## Kết quả Pentest

| Tấn công | Vector | Kết quả | HTTP Status |
|--------|--------|--------|-------------|
| BOLA | Thay đổi order ID trên URL | Chặn được | 403 Access denied |
| Token Replay | Dùng token cũ sau khi logout | Chặn sau 5 phút | 401 token expired |
| JWT alg=none | Forge token không có signature | Chặn được | 401 Unauthorized |
| Rate Limit | 65 requests/phút | Chặn tại request #60 | 429 Too Many Requests |
| SSRF | Gọi 169.254.169.254 từ pod | Chặn được | Network timeout |
| Webhook Forgery | Webhook không có HMAC | Chặn được | 401 Missing signature |


---

## CI/CD Pipeline

GitHub Actions tự động chạy khi push code:

| Job | Tool | Mục đích |
|-----|------|----------|
| SAST | Bandit | Scan Python code tìm lỗ hổng bảo mật |
| SCA | pip-audit | Kiểm tra thư viện có CVE chưa |
| Secrets Scan | Gitleaks | Tìm secrets bị commit nhầm |
| Security Summary |  | Tổng hợp kết quả |

---

## HashiCorp Vault

Secrets được quản lý tập trung tại Vault, không hardcode trong code:

| Path | Nội dung |
|------|----------|
| secret/shopsme/db | DB passwords (shop, kong, keycloak) |
| secret/shopsme/app | webhook_secret, keycloak_backend_secret |
| secret/shopsme/keycloak | admin_pass, realm |

AppRole policy: `shopsme-role` chỉ được đọc `secret/shopsme/db` và `secret/shopsme/app`, không được đọc `secret/shopsme/keycloak`.

---

## Cấu trúc Repository

```
nt219/
├── .github/
│   └── workflows/
│       └── security-ci.yml    # CI/CD pipeline
├── manifests/
│   ├── keycloak/              # Keycloak K8s manifests
│   ├── helm-values/           # Helm chart values (kong, loki, postgres)
│   ├── apps/                  # Microservice deployments
│   ├── network-policy/        # Calico NetworkPolicies
│   └── monitoring/            # Alert rules
├── services/
│   ├── users-api/             # main.py, requirements.txt, Dockerfile
│   ├── resources-api/
│   ├── admin-api/
│   ├── webhook-svc/
│   ├── shop-api/
│   └── frontend/              # index.html, serve.py
├── certs/
│   ├── certificate.crt        # ZeroSSL public cert
│   ├── ca_bundle.crt
│   ├── fullchain.crt
│   └── mtls/                  # mTLS public certs (không có private keys)
├── .gitignore
└── README.md
```

---

## Tài khoản test (Lab only)

| Username | Password | Role |
|----------|----------|------|
| admin1 | Admin1234! | admin |
| seller1 | Seller1234! | seller |
| user2 | User1234! | user |

---

## Hạn chế

- JWT stateless - token replay khả thi trong window 5 phút (access token lifetime = 300s)
- Vault đang dùng dev mode - không phù hợp cho production (dữ liệu mất khi restart)

---

## Tài liệu tham khảo

- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- OAuth 2.0 RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749
- PKCE RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
- JWT RFC 7519: https://datatracker.ietf.org/doc/html/rfc7519
- JWS RFC 7515: https://datatracker.ietf.org/doc/html/rfc7515
- NIST SP 800-95: https://csrc.nist.gov/publications/detail/sp/800-95/final
- HashiCorp Vault Docs: https://developer.hashicorp.com/vault/docs
- Kong Gateway Docs: https://docs.konghq.com
- Keycloak Docs: https://www.keycloak.org/documentation
