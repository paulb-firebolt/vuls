#!/bin/bash

echo "🚀 Starting Vuls Web Application (Development Mode)..."

# Stop any existing web containers
echo "🛑 Stopping existing containers..."
docker compose --profile web down
docker compose --profile dev down

# Start the development stack
echo "📦 Starting PostgreSQL and Redis..."
docker compose --profile dev up -d vuls-db vuls-redis

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Start the development web application with hot reload
echo "🌐 Starting development web application with hot reload..."
docker compose --profile dev up -d vuls-web-dev

echo "✅ Vuls Web Development Environment is starting up!"
echo ""
echo "🔗 Access the application at: http://localhost:8000"
echo "👤 Create admin user by clicking 'Create Admin' on the login page"
echo "📊 Default credentials: admin / admin123"
echo ""
echo "🔄 Hot reload enabled - code changes will automatically restart the server"
echo ""
echo "📝 To view logs:"
echo "   docker compose logs -f vuls-web-dev"
echo ""
echo "🛑 To stop:"
echo "   docker compose --profile dev down"
echo ""
echo "💡 Development features:"
echo "   - Auto-reload on code changes"
echo "   - Source code mounted as volumes"
echo "   - Faster development cycle"
