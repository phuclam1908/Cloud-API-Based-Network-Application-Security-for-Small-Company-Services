#!/bin/bash
# Chạy sau khi Grafana up để tạo lại 6 alert rules
# Usage: bash create-alert-rules.sh

GF_IP=$(kubectl get svc -n monitoring loki-stack-grafana -o jsonpath='{.spec.clusterIP}')
GF_URL="http://${GF_IP}"

# Lấy Loki UID
LOKI_UID=$(curl -s -u admin:Grafana1234! "${GF_URL}/api/datasources" | python3 -c "
import sys,json
ds=json.load(sys.stdin)
loki=[d for d in ds if d['type']=='loki']
print(loki[0]['uid'] if loki else 'NOT_FOUND')
")

# Tạo folder
FOLDER_UID=$(curl -s -u admin:Grafana1234! -X POST "${GF_URL}/api/folders" \
  -H "Content-Type: application/json" \
  -d '{"title":"NT219 Security Alerts"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('uid',''))")

post_rule() {
  curl -s -u admin:Grafana1234! -X POST \
    "${GF_URL}/api/v1/provisioning/alert-rules" \
    -H "Content-Type: application/json" \
    -d @- -o /dev/null -w "%{http_code}"
}

echo -n "BruteForceLogin: "
post_rule << ENDRULE
{"title":"BruteForceLogin","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"1m","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"apps\"} |= \"jwt_invalid\" [1m])) > 10","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"Brute force login >10/min"},"labels":{"severity":"critical"}}
ENDRULE
echo ""

echo -n "RateAbuseSpike: "
post_rule << ENDRULE
{"title":"RateAbuseSpike","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"1m","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"kong\"} |= \"429\" [1m])) > 50","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"Rate abuse >50x429/min"},"labels":{"severity":"critical"}}
ENDRULE
echo ""

echo -n "BOLAProbe: "
post_rule << ENDRULE
{"title":"BOLAProbe","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"1m","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"apps\"} |= \"bola_attempt\" [2m])) > 3","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"BOLA probe detected"},"labels":{"severity":"critical"}}
ENDRULE
echo ""

echo -n "KongAdminAccessed: "
post_rule << ENDRULE
{"title":"KongAdminAccessed","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"0s","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"kong\",container=\"proxy\"} |= \"8001\" [5m])) > 0","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"Kong Admin API accessed"},"labels":{"severity":"warning"}}
ENDRULE
echo ""

echo -n "WebhookForgery: "
post_rule << ENDRULE
{"title":"WebhookForgery","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"1m","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"apps\"} |= \"signature_invalid\" [5m])) > 3","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"Webhook signature fail"},"labels":{"severity":"warning"}}
ENDRULE
echo ""

echo -n "RBACDeniedSpike: "
post_rule << ENDRULE
{"title":"RBACDeniedSpike","folderUID":"${FOLDER_UID}","ruleGroup":"nt219-security","noDataState":"OK","execErrState":"Error","for":"1m","condition":"A","data":[{"refId":"A","datasourceUid":"${LOKI_UID}","queryType":"range","relativeTimeRange":{"from":300,"to":0},"model":{"expr":"sum(count_over_time({namespace=\"apps\"} |= \"rbac_denied\" [2m])) > 5","intervalMs":1000,"maxDataPoints":43200,"queryType":"range","refId":"A"}}],"annotations":{"summary":"RBAC denied spike"},"labels":{"severity":"critical"}}
ENDRULE
echo ""

echo "Done. Verify:"
curl -s -u admin:Grafana1234! "${GF_URL}/api/v1/provisioning/alert-rules" | python3 -c "
import sys,json; rules=json.load(sys.stdin)
print('Total:', len(rules))
for r in rules: print(' ', r['title'], '-', r['labels'].get('severity'))
"
