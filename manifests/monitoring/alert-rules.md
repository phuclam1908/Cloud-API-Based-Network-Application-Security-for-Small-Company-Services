# Grafana Alert Rules — NT219 SIEM
# Folder: NT219 Security Alerts
# Loki datasource UID: P8E80F9AEF21F6940

1. BruteForceLogin (critical): jwt_invalid > 10/min
2. RateAbuseSpike (critical): 429 > 50/min
3. BOLAProbe (critical): bola_attempt > 3/2min
4. KongAdminAccessed (warning): access port 8001
5. WebhookForgery (warning): signature_invalid > 3/5min
6. RBACDeniedSpike (critical): rbac_denied > 5/2min
