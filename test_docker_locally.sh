#!/bin/bash

# Local Docker Testing Script for AsyncPG Issue
# This script will test the Docker build locally to verify the asyncpg fix works
# before deploying to Railway

set -e  # Exit on any error

echo "=========================================="
echo "  LOCAL DOCKER TESTING FOR RAILWAY FIX"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is installed
print_step "Checking Docker Installation"
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi
print_success "Docker is installed"

# Check if .env file exists or DATABASE_URL is set
print_step "Checking Database Configuration"
if [ -f ".env" ]; then
    print_success "Found .env file"
    if grep -q "DATABASE_URL" .env; then
        print_success "DATABASE_URL found in .env"
    else
        print_warning "DATABASE_URL not found in .env"
    fi
elif [ -n "$DATABASE_URL" ]; then
    print_success "DATABASE_URL environment variable is set"
else
    print_error "DATABASE_URL not found. Please set it as environment variable or create .env file"
    echo "Example: export DATABASE_URL='postgresql://user:pass@host:5432/db'"
    exit 1
fi

# Clean up any existing containers/images
print_step "Cleaning Up Previous Test Builds"
docker stop monitor-legislativo-test 2>/dev/null || true
docker rm monitor-legislativo-test 2>/dev/null || true
docker rmi monitor-legislativo-test 2>/dev/null || true
print_success "Cleanup complete"

# Build the Docker image
print_step "Building Docker Image (This may take a few minutes)"
echo "Building with the enhanced Dockerfile that includes asyncpg verification..."

if docker build -t monitor-legislativo-test .; then
    print_success "Docker build completed successfully"
else
    print_error "Docker build failed"
    echo "Check the build output above for errors."
    echo "The build should show asyncpg version verification steps."
    exit 1
fi

# Test container startup (without DATABASE_URL first)
print_step "Testing Container Startup (Basic Test)"
echo "Starting container to test basic functionality..."

# Run container in detached mode for testing
CONTAINER_ID=$(docker run -d -p 8081:8080 --name monitor-legislativo-test monitor-legislativo-test)

if [ $? -eq 0 ]; then
    print_success "Container started successfully"
    echo "Container ID: $CONTAINER_ID"
else
    print_error "Container failed to start"
    exit 1
fi

# Wait a bit for container to initialize
print_step "Waiting for Container Initialization"
sleep 10

# Check container logs for asyncpg version info
print_step "Checking Container Logs for AsyncPG Version"
echo "Looking for asyncpg version in container logs..."
docker logs monitor-legislativo-test

# Check if container is still running
if docker ps | grep -q monitor-legislativo-test; then
    print_success "Container is running"
else
    print_error "Container stopped unexpectedly"
    echo "Container logs:"
    docker logs monitor-legislativo-test
    docker stop monitor-legislativo-test 2>/dev/null || true
    docker rm monitor-legislativo-test 2>/dev/null || true
    exit 1
fi

# Test health endpoint
print_step "Testing Health Endpoint"
sleep 5  # Give it more time
if curl -f http://localhost:8081/health >/dev/null 2>&1; then
    print_success "Health endpoint is responding"
    echo "Health response:"
    curl -s http://localhost:8081/health | python -m json.tool 2>/dev/null || curl -s http://localhost:8081/health
else
    print_warning "Health endpoint not responding (this might be expected if database isn't connected)"
fi

# Stop the basic test container
docker stop monitor-legislativo-test
docker rm monitor-legislativo-test

# Test with DATABASE_URL
print_step "Testing with Database Connection"

# Load DATABASE_URL
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

if [ -n "$DATABASE_URL" ]; then
    print_success "Using DATABASE_URL for connection test"
    
    # Run container with DATABASE_URL
    echo "Starting container with database connection..."
    CONTAINER_ID=$(docker run -d -p 8081:8080 -e DATABASE_URL="$DATABASE_URL" --name monitor-legislativo-test monitor-legislativo-test)
    
    if [ $? -eq 0 ]; then
        print_success "Container with database started"
        
        # Wait for initialization
        sleep 15
        
        # Check logs for database connection
        print_step "Checking Database Connection Logs"
        docker logs monitor-legislativo-test | tail -20
        
        # Check if the specific asyncpg error appears
        if docker logs monitor-legislativo-test 2>&1 | grep -q "NoneType.*object has no attribute.*group"; then
            print_error "FOUND THE ASYNCPG ERROR! This confirms the issue."
            echo "The container logs show the exact same error as Railway."
            echo "This means the fix needs to be different."
        else
            print_success "No asyncpg authentication error found in logs"
        fi
        
        # Test database diagnostic endpoint
        sleep 5
        print_step "Testing Database Diagnostic Endpoint"
        if curl -f http://localhost:8081/api/v1/health/database >/dev/null 2>&1; then
            print_success "Database diagnostic endpoint responding"
            echo "Diagnostic response:"
            curl -s http://localhost:8081/api/v1/health/database | python -m json.tool 2>/dev/null || curl -s http://localhost:8081/api/v1/health/database
        else
            print_warning "Database diagnostic endpoint not responding"
        fi
        
        # Clean up
        docker stop monitor-legislativo-test
        docker rm monitor-legislativo-test
        
    else
        print_error "Container with database failed to start"
        exit 1
    fi
else
    print_warning "Skipping database connection test (no DATABASE_URL)"
fi

# Final summary
print_step "Test Summary"
print_success "Local Docker testing completed"
echo ""
echo "Next steps:"
echo "1. Check the logs above for asyncpg version information"
echo "2. If asyncpg shows version 0.29.0, the issue is Railway-specific"
echo "3. If asyncpg shows older version, there's a dependency conflict"
echo "4. Deploy this enhanced Docker image to Railway"
echo ""
echo "To deploy to Railway:"
echo "1. Commit these changes: git add . && git commit -m 'Fix asyncpg version issue'"
echo "2. Push to Railway: git push origin main"
echo "3. Check Railway logs for the enhanced debugging output"
echo ""
print_success "Ready for Railway deployment!"

# Clean up Docker image if requested
read -p "Do you want to clean up the test Docker image? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker rmi monitor-legislativo-test
    print_success "Docker image cleaned up"
fi 