#!/bin/bash

echo "🚀 Starting Vuls Web Application..."

# Start the web application stack
echo "📦 Starting PostgreSQL and Redis..."
docker compose --profile web up -d vuls-db vuls-redis

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Start the web application
echo "🌐 Starting web application..."
docker compose --profile web up -d vuls-web

echo "✅ Vuls Web is starting up!"
echo ""
echo "🔗 Access the application at: http://localhost:8000"
echo "👤 Create admin user by clicking 'Create Admin' on the login page"
echo "📊 Default credentials: admin / admin123"
echo ""
echo "📝 To view logs:"
echo "   docker compose logs -f vuls-web"
echo ""
echo "🛑 To stop:"
echo "   docker compose --profile web down"
