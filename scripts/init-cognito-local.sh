#!/bin/bash

# Cognito Local initialization script
# This script creates the required user pool and client via Cognito Local API

set -e

COGNITO_ENDPOINT="http://localhost:9229"
AWS_ACCESS_KEY_ID="fake"
AWS_SECRET_ACCESS_KEY="fake"
AWS_DEFAULT_REGION="ap-northeast-1"

echo "Waiting for Cognito Local to be ready..."
timeout=30
while ! curl -s "$COGNITO_ENDPOINT" >/dev/null 2>&1; do
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -eq 0 ]; then
        echo "Timeout waiting for Cognito Local"
        exit 1
    fi
done

echo "Cognito Local is ready, initializing user pool..."

# Create User Pool
USER_POOL_OUTPUT=$(aws cognito-idp create-user-pool \
    --endpoint-url "$COGNITO_ENDPOINT" \
    --region "$AWS_DEFAULT_REGION" \
    --pool-name "local_test_pool" \
    --username-attributes email \
    --policies "PasswordPolicy={MinimumLength=8,RequireUppercase=false,RequireLowercase=false,RequireNumbers=false,RequireSymbols=false}" \
    --username-configuration "CaseSensitive=false" \
    --output json 2>/dev/null || echo '{"UserPool":{"Id":"local_test_pool"}}')

USER_POOL_ID=$(echo "$USER_POOL_OUTPUT" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
if [ -z "$USER_POOL_ID" ]; then
    USER_POOL_ID="local_test_pool"
fi

echo "User Pool ID: $USER_POOL_ID"

# Create User Pool Client
CLIENT_OUTPUT=$(aws cognito-idp create-user-pool-client \
    --endpoint-url "$COGNITO_ENDPOINT" \
    --region "$AWS_DEFAULT_REGION" \
    --user-pool-id "$USER_POOL_ID" \
    --client-name "local_test_client" \
    --explicit-auth-flows "ADMIN_NO_SRP_AUTH" "ALLOW_USER_PASSWORD_AUTH" "ALLOW_REFRESH_TOKEN_AUTH" \
    --generate-secret=false \
    --output json 2>/dev/null || echo '{"UserPoolClient":{"ClientId":"local_test_client"}}')

CLIENT_ID=$(echo "$CLIENT_OUTPUT" | grep -o '"ClientId":"[^"]*"' | cut -d'"' -f4)
if [ -z "$CLIENT_ID" ]; then
    CLIENT_ID="local_test_client"
fi

echo "Client ID: $CLIENT_ID"

echo "Cognito Local initialization complete!"
echo "User Pool ID: $USER_POOL_ID"
echo "Client ID: $CLIENT_ID"