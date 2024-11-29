#!/bin/bash

docker compose -f ./test/docker-compose.yml up -d

sleep 3

tokenResp=$(curl -s -X POST http://localhost:9210/thingsdb \
-u admin:pass \
-H "Content-Type: application/json" \
-d '{
  "type": "query",
  "code": "new_token(\"admin\")"
}'
)

export TEST_THINGSDB_HOST="localhost"
export TEST_THINGSDB_PORT="9200"
export TEST_THINGSDB_TOKEN=$(echo "$tokenResp" | sed 's/^"//;s/"$//')

VAULT_ACC=1 go test -v -run TestAcceptanceUserToken

docker compose -f ./test/docker-compose.yml down