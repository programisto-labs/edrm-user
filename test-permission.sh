#!/bin/bash

# Script de test pour la route /test-permission
# Usage: ./test-permission.sh <token> [base_url]

TOKEN=$1
BASE_URL=${2:-"http://localhost:3000"}

if [ -z "$TOKEN" ]; then
  echo "❌ Erreur: Token JWT requis"
  echo "Usage: ./test-permission.sh <token> [base_url]"
  echo "Exemple: ./test-permission.sh eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  exit 1
fi

echo "🧪 Test de la route /test-permission"
echo "📍 URL: ${BASE_URL}/user/test-permission"
echo "🔑 Token: ${TOKEN:0:50}..."
echo ""

# Test sans token (devrait échouer avec 401)
echo "1️⃣ Test sans token (devrait échouer):"
curl -X GET "${BASE_URL}/user/test-permission" \
  -H "Content-Type: application/json" \
  -w "\n📊 Status: %{http_code}\n" \
  -s | jq '.' || echo ""

echo ""
echo "2️⃣ Test avec token (devrait réussir si l'utilisateur a la permission Admin_Access):"
curl -X GET "${BASE_URL}/user/test-permission" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -w "\n📊 Status: %{http_code}\n" \
  -s | jq '.' || echo ""

echo ""
echo "✅ Test terminé"

