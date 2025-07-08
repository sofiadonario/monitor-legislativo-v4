#!/bin/bash
# Production deployment script for Monitor Legislativo v4

set -e

# Configuration
ENVIRONMENT="${1:-production}"
COMPOSE_FILE="docker-compose.production.yml"
ENV_FILE=".env.production"

echo "🚀 Starting deployment for Monitor Legislativo v4 - Environment: $ENVIRONMENT"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for service health
wait_for_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be healthy..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f "$COMPOSE_FILE" ps "$service_name" | grep -q "Up (healthy)"; then
            echo "✅ $service_name is healthy"
            return 0
        fi
        
        echo "🔄 Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 10
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to become healthy"
    return 1
}

# Pre-deployment checks
echo "🔍 Running pre-deployment checks..."

# Check if Docker is installed
if ! command_exists docker; then
    echo "❌ Docker is not installed"
    exit 1
fi

# Check if Docker Compose is installed
if ! command_exists docker-compose; then
    echo "❌ Docker Compose is not installed"
    exit 1
fi

# Check if environment file exists
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Environment file $ENV_FILE not found"
    echo "ℹ️  Please copy .env.production and configure with your values"
    exit 1
fi

# Load environment variables
set -a
source "$ENV_FILE"
set +a

# Check required environment variables
required_vars=("POSTGRES_PASSWORD")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Required environment variable $var is not set"
        exit 1
    fi
done

echo "✅ Pre-deployment checks passed"

# Generate SSL certificates if they don't exist
if [ ! -f "./nginx/ssl/cert.pem" ] || [ ! -f "./nginx/ssl/key.pem" ]; then
    echo "🔐 Generating SSL certificates..."
    chmod +x scripts/generate_ssl.sh
    ./scripts/generate_ssl.sh
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs exports data/geographic data/cache temp
chmod 755 logs exports data

# Pull latest images
echo "📥 Pulling latest Docker images..."
docker-compose -f "$COMPOSE_FILE" pull

# Stop existing services gracefully
echo "🛑 Stopping existing services..."
docker-compose -f "$COMPOSE_FILE" down --remove-orphans

# Start infrastructure services first
echo "🏗️  Starting infrastructure services..."
docker-compose -f "$COMPOSE_FILE" up -d postgres redis

# Wait for infrastructure to be ready
wait_for_service postgres
wait_for_service redis

# Start application services
echo "🎯 Starting application services..."
docker-compose -f "$COMPOSE_FILE" up -d app1 app2

# Wait for applications to be ready
wait_for_service app1
wait_for_service app2

# Start load balancer
echo "⚖️  Starting load balancer..."
docker-compose -f "$COMPOSE_FILE" up -d nginx

# Wait for load balancer
wait_for_service nginx

# Start monitoring services if enabled
if [ "$ENABLE_MONITORING" = "true" ]; then
    echo "📊 Starting monitoring services..."
    docker-compose -f "$COMPOSE_FILE" --profile monitoring up -d
fi

# Run smoke tests
echo "🧪 Running smoke tests..."

# Test health endpoint
sleep 30  # Wait for services to fully initialize
if curl -f -s "http://localhost:${APP_PORT:-80}/health" > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    echo "📋 Service status:"
    docker-compose -f "$COMPOSE_FILE" ps
    exit 1
fi

# Test HTTPS endpoint if SSL is configured
if [ -f "./nginx/ssl/cert.pem" ]; then
    if curl -f -s -k "https://localhost:${APP_SSL_PORT:-443}/health" > /dev/null; then
        echo "✅ HTTPS health check passed"
    else
        echo "⚠️  HTTPS health check failed (this is okay for self-signed certificates)"
    fi
fi

# Display service status
echo "📋 Final service status:"
docker-compose -f "$COMPOSE_FILE" ps

# Display resource usage
echo "💻 Resource usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Create backup after successful deployment
if [ "$ENVIRONMENT" = "production" ]; then
    echo "💾 Creating post-deployment backup..."
    chmod +x scripts/backup.sh
    ./scripts/backup.sh
fi

echo "🎉 Deployment completed successfully!"
echo "🌐 Application is available at:"
echo "   HTTP:  http://localhost:${APP_PORT:-80}"
echo "   HTTPS: https://localhost:${APP_SSL_PORT:-443}"

if [ "$ENABLE_MONITORING" = "true" ]; then
    echo "📊 Monitoring is available at:"
    echo "   Prometheus: http://localhost:${PROMETHEUS_PORT:-9090}"
    echo "   Grafana:    http://localhost:${GRAFANA_PORT:-3000}"
fi

echo "📚 Next steps:"
echo "   - Monitor application logs: docker-compose -f $COMPOSE_FILE logs -f"
echo "   - Check service health: docker-compose -f $COMPOSE_FILE ps"
echo "   - Create backup: ./scripts/backup.sh"
echo "   - View metrics: http://localhost:${PROMETHEUS_PORT:-9090}"