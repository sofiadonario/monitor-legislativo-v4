#!/bin/bash

# Academic Legislative Monitor - Docker Setup Script
# This script builds and runs the R Shiny application in Docker

echo "=================================================="
echo "   MONITOR LEGISLATIVO ACADÊMICO - DOCKER       "
echo "   Academic Legislative Monitor - Docker Setup   "
echo "=================================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is available and running"
echo ""

# Build the Docker image
echo "🔨 Building R Shiny Docker image..."
docker build -t monitor-legislativo-rshiny .

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed. Please check the Dockerfile and try again."
    exit 1
fi

echo "✅ Docker image built successfully"
echo ""

# Stop any existing container
echo "🛑 Stopping any existing containers..."
docker stop monitor-legislativo-rshiny 2>/dev/null || true
docker rm monitor-legislativo-rshiny 2>/dev/null || true

# Run the container
echo "🚀 Starting R Shiny container..."
docker run -d \
    --name monitor-legislativo-rshiny \
    -p 3838:3838 \
    -v "$(pwd)/data:/app/data" \
    -v "$(pwd)/logs:/app/logs" \
    -e SHINY_LOG_LEVEL=INFO \
    monitor-legislativo-rshiny

if [ $? -ne 0 ]; then
    echo "❌ Failed to start container. Check Docker logs:"
    docker logs monitor-legislativo-rshiny
    exit 1
fi

echo "✅ Container started successfully"
echo ""

# Wait for health check
echo "⏳ Waiting for application to be ready..."
sleep 10

# Check if the application is responding
if curl -f http://localhost:3838/health &> /dev/null; then
    echo "✅ Application is ready!"
else
    echo "⚠️  Application may still be starting. Check logs if needed:"
    echo "   docker logs monitor-legislativo-rshiny"
fi

echo ""
echo "🌐 Application Information:"
echo "───────────────────────────────────────────"
echo "📍 URL: http://localhost:3838"
echo "🔐 Authentication Required"
echo ""
echo "👥 Test Credentials:"
echo "───────────────────────────────────────────"
echo "👨‍💼 Administrator: admin / admin123"
echo "👨‍🔬 Researcher:   researcher / research123"
echo "👨‍🎓 Student:      student / student123"
echo ""
echo "📊 Management Commands:"
echo "───────────────────────────────────────────"
echo "🔍 View logs:      docker logs monitor-legislativo-rshiny"
echo "🛑 Stop app:       docker stop monitor-legislativo-rshiny"
echo "🗑️  Remove container: docker rm monitor-legislativo-rshiny"
echo "🔄 Restart app:    docker restart monitor-legislativo-rshiny"
echo ""
echo "=================================================="