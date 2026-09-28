export TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNS1BJaE9Waml0M2ZmTmNxVHBxdExnSjlSQXFGeUgza2diYmlvN3Zqa0FJIn0.eyJleHAiOjE3ODkzNTA3MDgsImlhdCI6MTc4OTM1MDQwOCwiYXV0aF90aW1lIjoxNzg5MzUwNDA2LCJqdGkiOiJjYjMwZjE5OS0wY2RiLTQ0YTgtYTY3OC1iMDIzYzM5YjdlMDciLCJpc3MiOiJodHRwczovL2F1dGguY2xhZG9uZS5jb20vcmVhbG1zL2NsYWRvbmUiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiY2FjOThhNGEtNTMyOC00MDFjLThkMWMtMjUzNjU2ZWRhZmUxIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidmVyc2lmaWVyIiwic2lkIjoiYmY2YmU1ODUtMGNmMC00YjEwLTg5Y2UtZWU2YzQ3OWIyNDZmIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL3ZlcnMyLmNsYWRvbmUuY29tIiwiaHR0cHM6Ly92ZXJzLmNsYWRvbmUuY29tIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtY2xhZG9uZSIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6ImJlbm9pdCByb2xsYW5kIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYmVub2l0LnJvbGxhbmRAZnJlZS5mciIsImdpdmVuX25hbWUiOiJiZW5vaXQiLCJmYW1pbHlfbmFtZSI6InJvbGxhbmQiLCJlbWFpbCI6ImJlbm9pdC5yb2xsYW5kQGZyZWUuZnIifQ.YGGeyJHjC3ORGHztKWhpLK_dm5VkmY744ywEOtHXY0wPS1CTaARiKneQey7dMCHaCcVbLDY78HxwGAVhbw2Y8Z7WN8J1ztcfwhzsJKrAjKQz53oGde2weJZijaSJPRYkSFETWeoxZd8QMX5ToN0VvbnG0lECLjYnY8gjjH92ajS65tG4Br-CBQ3tW_6q7DSI0ZHkEwuikvxCeg3cFYAeagUC8Nb06g3GGApV5wkXEiQeicM2QUuHdr_KwXYNANeizWjd5rWgkU1QjMKRoGTG8AG_Rz0WUer1DvOdNgp4mHIDk6gdozNziUzMKslgCuyHpEJAZps63mhiWvaxL6wLLQ





#!/bin/bash
# export TOKEN=<the value here>
python3 - <<'PY'
import os, json, base64, datetime, time

token = os.environ["TOKEN"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)

data = json.loads(base64.urlsafe_b64decode(payload))

print("iss =", data.get("iss"))
print("azp =", data.get("azp"))
print("aud =", data.get("aud"))
print("iat =", datetime.datetime.fromtimestamp(data["iat"]))
print("exp =", datetime.datetime.fromtimestamp(data["exp"]))
print("now =", datetime.datetime.now())
print("expired =", data["exp"] <= time.time())
PY




$curl -i \
  https://login.cladone.com/auth \
  -H "Authorization: Bearer $TOKEN" \
  -H 'X-Forwarded-Host: gram.cladone.com' \
  -H 'X-Forwarded-Uri: /mcp' \
  -H 'X-Forwarded-Method: POST'

HTTP/2 200
content-type: text/plain; charset=utf-8
date: Mon, 14 Sep 2026 01:04:16 GMT
etag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
x-auth-expires: 1789347913
x-email: benoit.rolland@free.fr
x-powered-by: Express
x-roles: offline_access,default-roles-cladone,uma_authorization,manage-account,manage-account-links,view-profile
x-user-id: cac98a4a-5328-401c-8d1c-253656edafe1
x-username: benoit.rolland@free.fr
content-length: 2

$curl -i   -X POST   https://gram.cladone.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json, text/event-stream'   -H "Authorization: Bearer $TOKEN"   -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2026-07-28",
      "capabilities": {},
      "clientInfo": {
        "name": "curl",
        "version": "0.1"
      }
    }
  }'

HTTP/2 200
cache-control: no-cache, no-transform
content-type: application/json
date: Mon, 14 Sep 2026 01:04:40 GMT
content-length: 183

{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"logging":{},"tools":{"listChanged":true}},"protocolVersion":"2025-11-25","serverInfo":{"name":"cladone-gateway","version":"0.1.0"}}}


 curl -i   -X POST   https://gram.cladone.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json, text/event-stream'   -H "Authorization: Bearer $TOKEN"   -d '{
"jsonrpc": "2.0",                                                                                                       "id": 2,
"method": "tools/list",
"params": {}
}'  

HTTP/2 200
cache-control: no-cache, no-transform
content-type: application/json
date: Mon, 14 Sep 2026 01:24:27 GMT
content-length: 657                                                                                                                                                                                                                             {"jsonrpc":"2.0","id":2,"result":{"ttlMs":0,"cacheScope":"public","tools":[{"description":"Process French text and stream the processing results.","inputSchema":{"type":"object","properties":{"text":{"type":"string","description":"raw text to process"},"split_mode":{"type":"string","description":"split mode: sentence or newline"},"liaisons":{"type":"boolean","description":"whether to show French liaisons"}},"required":["text"],"additionalProperties":false},"name":"processStream","outputSchema":{"type":"object","properties":{"content_type":{"type":"string"},"data":{"type":"string"}},"required":["content_type","data"],"additionalProperties":false}}]}}


$ curl -i   -X POST   https://gram.cladone.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json, text/event-stream'   -H "Authorization: Bearer $TOKEN"   -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "processStream",
      "arguments": {
        "text": "Bonjour tout le monde.",
        "split_mode": "sentence",
        "liaisons": false
      }
    }
  }'
HTTP/2 200
cache-control: no-cache, no-transform
content-type: application/json
date: Mon, 14 Sep 2026 01:28:42 GMT
content-length: 200

{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"content_type\":\"application/x-ndjson\",\"data\":\"\"}"}],"structuredContent":{"content_type":"application/x-ndjson","data":""}}}

$ curl -i   -X POST   https://gram.cladone.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json, text/event-stream'   -H "Authorization: Bearer $TOKEN"   -d '{
"jsonrpc": "2.0",
"id": 3,
"method": "tools/call",
"params": {
  "name": "processStream",
  "arguments": {
    "text": "Bonjour tout le monde.",
    "split_mode": "sentence",
    "liaisons":cfalse
  }                                                                                                                   }
}'
HTTP/2 200
cache-control: no-cache, no-transform
content-type: application/json
date: Mon, 14 Sep 2026 01:47:30 GMT

{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"content_type\":\"application/x-ndjson\",\"data\":\"{\\\"sentence\\\": 0, \\\"tokens\\\": [{\\\"text\\\": \\\"Bonjour\\\", \\\"lemma\\\": \\\"bonjour\\\", \\\"pos\\\": \\\"NOUN\\\", \\\"tag\\\": \\\"NOUN\\\", \\\"dep\\\": \\\"ROOT\\\", \\\"ipa\\\": \\\"b\\\\u0254\\\\u0303\\\\u0292u\\\\u0281\\\", \\\"liaison\\\": \\\"\\\", \\\"can_swap_next\\\": false}, {\\\"text\\\": \\\"tout\\\", \\\"lemma\\\": \\\"tout\\\", \\\"pos\\\": \\\"ADJ\\\", \\\"tag\\\": \\\"ADJ\\\", \\\"dep\\\": \\\"amod\\\", \\\"ipa\\\": \\\"tu\\\", \\\"liaison\\\": \\\"\\\", \\\"can_swap_next\\\": false}, {\\\"text\\\": \\\"le\\\", \\\"lemma\\\": \\\"le\\\", \\\"pos\\\": \\\"DET\\\", \\\"tag\\\": \\\"DET\\\", \\\"dep\\\": \\\"det\\\", \\\"ipa\\\": \\\"l\\\\u0259\\\", \\\"liaison\\\": \\\"\\\", \\\"can_swap_next\\\": false}, {\\\"text\\\": \\\"monde\\\", \\\"lemma\\\": \\\"monde\\\", \\\"pos\\\": \\\"NOUN\\\", \\\"tag\\\": \\\"NOUN\\\", \\\"dep\\\": \\\"nmod\\\", \\\"ipa\\\": \\\"m\\\\u0254\\\\u0303d\\\", \\\"liaison\\\": \\\"\\\", \\\"can_swap_next\\\": false}, {\\\"text\\\": \\\".\\\", \\\"lemma\\\": \\\".\\\", \\\"pos\\\": \\\"PUNCT\\\", \\\"tag\\\": \\\"PUNCT\\\", \\\"dep\\\": \\\"punct\\\", \\\"ipa\\\": \\\"\\\", \\\"liaison\\\": \\\"\\\", \\\"can_swap_next\\\": false}]}\\n\"}"}],"structuredContent":{"content_type":"application/x-ndjson","data":"{\"sentence\": 0, \"tokens\": [{\"text\": \"Bonjour\", \"lemma\": \"bonjour\", \"pos\": \"NOUN\", \"tag\": \"NOUN\", \"dep\": \"ROOT\", \"ipa\": \"b\\u0254\\u0303\\u0292u\\u0281\", \"liaison\": \"\", \"can_swap_next\": false}, {\"text\": \"tout\", \"lemma\": \"tout\", \"pos\": \"ADJ\", \"tag\": \"ADJ\", \"dep\": \"amod\", \"ipa\": \"tu\", \"liaison\": \"\", \"can_swap_next\": false}, {\"text\": \"le\", \"lemma\": \"le\", \"pos\": \"DET\", \"tag\": \"DET\", \"dep\": \"det\", \"ipa\": \"l\\u0259\", \"liaison\": \"\", \"can_swap_next\": false}, {\"text\": \"monde\", \"lemma\": \"monde\", \"pos\": \"NOUN\", \"tag\": \"NOUN\", \"dep\": \"nmod\", \"ipa\": \"m\\u0254\\u0303d\", \"liaison\": \"\", \"can_swap_next\": false}, {\"text\": \".\", \"lemma\": \".\", \"pos\": \"PUNCT\", \"tag\": \"PUNCT\", \"dep\": \"punct\", \"ipa\": \"\", \"liaison\": \"\", \"can_swap_next\": false}]}\n"}}}


export ADMIN_TOKEN=
curl -s \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://auth.cladone.com/admin/realms/cladone/client-policies/policies" \
  | jq
{
  "policies": []
}


curl -i https://gram.cladone.com/.well-known/oauth-protected-resource
 curl -i https://gram.cladone.com/.well-known/oauth-protected-resourcee
HTTP/2 200
content-type: application/json
date: Mon, 14 Sep 2026 03:44:30 GMT
content-length: 183

{"authorization_servers":["https://auth.cladone.com/realms/cladone"],"bearer_methods_supported":["header"],"resource":"https://gram.cladone.com/mcp","scopes_supported":["mcp:tools"]}

curl -i https://gram.cladone.com/mcp



: "${MCP_TEST_CLIENT_SECRET:?export MCP_TEST_CLIENT_SECRET first}"
: "${MCP_TEST_USERNAME:?export MCP_TEST_USERNAME first}"
: "${MCP_TEST_PASSWORD:?export MCP_TEST_PASSWORD first}"

TOKEN=$(
  curl -s -X POST \
    "https://auth.cladone.com/realms/cladone/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=mcp-test" \
    -d "client_secret=$MCP_TEST_CLIENT_SECRET" \
    -d "username=$MCP_TEST_USERNAME" \
    -d "password=$MCP_TEST_PASSWORD" \
    -d "scope=openid mcp:tools" |
  jq -r '.access_token'
)

curl -s -X POST \
    "https://auth.cladone.com/realms/cladone/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=mcp-test" \
    -d "client_secret=$MCP_TEST_CLIENT_SECRET" \
    -d "username=$MCP_TEST_USERNAME" \
    -d "password=$MCP_TEST_PASSWORD" \
    -d "scope=openid mcp:tools" |
  jq -r '.access_token'
null

$ curl -sS -X POST \
  "https://auth.cladone.com/realms/cladone/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=mcp-test" \
  --data-urlencode "client_secret=$MCP_TEST_CLIENT_SECRET" \
  --data-urlencode "username=$MCP_TEST_USERNAME" \
  --data-urlencode "password=$MCP_TEST_PASSWORD" \
  --data-urlencode "scope=openid mcp:tools" | jq
{
  "error": "invalid_grant",
  "error_description": "Invalid user credentials"
}
