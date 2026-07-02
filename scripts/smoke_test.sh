#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
EMAIL="${ADMIN_EMAIL:-admin@beetleshield.com}"
PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD to the value from your .env}"

echo "== Login =="
TOKEN=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -r '.data.token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo "Login failed"
  exit 1
fi
echo "Got token: ${TOKEN:0:20}..."

echo "== Me =="
curl -s "$BASE_URL/api/v1/auth/me" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Upload (manual package info) =="
echo "dummy content" > /tmp/beetleshield-smoke.aab
UPLOAD_RESP=$(curl -s -X POST "$BASE_URL/api/v1/apps/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/beetleshield-smoke.aab" \
  -F "tag=tool" \
  -F "packageName=com.smoketest.demo" \
  -F "version=1.0.0")
echo "$UPLOAD_RESP" | jq .
APP_ID=$(echo "$UPLOAD_RESP" | jq -r '.data.id')

echo "== List =="
curl -s "$BASE_URL/api/v1/apps?tag=tool" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Get =="
curl -s "$BASE_URL/api/v1/apps/$APP_ID" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Download URL =="
curl -s "$BASE_URL/api/v1/apps/$APP_ID/download-url" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Delete =="
curl -s -X DELETE "$BASE_URL/api/v1/apps/$APP_ID" -H "Authorization: Bearer $TOKEN" | jq .

rm -f /tmp/beetleshield-smoke.aab
echo "Smoke test passed."
