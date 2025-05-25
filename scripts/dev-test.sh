#!/bin/bash

# Development testing script
echo "🧪 Testing Huma API endpoints..."

API_BASE="http://localhost:8888"

# Test health endpoint
echo "🏥 Testing health endpoint..."
curl -s "$API_BASE/health" | jq .

echo ""
echo "🔐 Testing authentication endpoints..."

# Test login
echo "📝 Testing login with admin user..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password123"
  }')

echo "Login Response:"
echo $LOGIN_RESPONSE | jq .

# Extract access token
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')

if [ "$ACCESS_TOKEN" != "null" ] && [ "$ACCESS_TOKEN" != "" ]; then
    echo ""
    echo "✅ Login successful! Access token obtained."
    
    # Test protected endpoint
    echo "🔒 Testing protected endpoint..."
    curl -s -X GET "$API_BASE/auth/me" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
    
    echo ""
    echo "🎯 Testing protected greeting endpoint..."
    curl -s -X GET "$API_BASE/api/v1/greeting/developer" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
    
    echo ""
    echo "🚪 Testing logout..."
    curl -s -X POST "$API_BASE/auth/logout" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
else
    echo "❌ Login failed. Check your setup."
fi

echo ""
echo "🌍 Testing public endpoint..."
curl -s "$API_BASE/greeting/world" | jq .

echo ""
echo "🏁 Testing complete!"
