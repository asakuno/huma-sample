#!/bin/bash

# Development startup script
echo "🚀 Starting Huma API development environment..."

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    cp .env.example .env
    echo "✅ .env file created. Please review and update the configuration."
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Build and start containers
echo "🏗️  Building and starting containers..."
docker-compose up --build -d

# Wait for MySQL to be ready
echo "⏳ Waiting for MySQL to be ready..."
sleep 10

# Show container status
echo "📊 Container status:"
docker-compose ps

echo ""
echo "🎉 Development environment is ready!"
echo ""
echo "📋 Available services:"
echo "   🌐 API Server: http://localhost:8888"
echo "   📖 API Docs: http://localhost:8888/docs"
echo "   🗄️  Database Admin: http://localhost:8080 (Adminer)"
echo "   🔧 Nginx Proxy: http://localhost:80"
echo ""
echo "🔐 Test Users (Mock Cognito):"
echo "   👤 admin / password123"
echo "   👤 testuser / password123"
echo "   👤 developer / password123"
echo ""
echo "📝 To view logs: docker-compose logs -f app"
echo "🛑 To stop: docker-compose down"
