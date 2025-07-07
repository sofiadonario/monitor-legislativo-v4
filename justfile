# Monitor Legislativo v4 - Development Commands (Windows-friendly)
# Install just from: https://github.com/casey/just

# Default command - show help
default:
    @just --list

# Initial setup
setup: env
    @echo "✅ Initial setup complete!"
    @echo "Next steps:"
    @echo "  1. Update .env with your configuration"
    @echo "  2. Run 'just db' to start databases"
    @echo "  3. Run 'just backend' in one terminal"
    @echo "  4. Run 'just frontend' in another terminal"

# Create .env from example
env:
    #!/usr/bin/env bash
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            echo "✅ Created .env from .env.example"
        else
            echo "⚠️  No .env.example found, creating basic .env"
            echo "DATABASE_URL=postgresql://postgres:postgres@localhost:5432/monitor_legislativo" > .env
            echo "REDIS_URL=redis://localhost:6379" >> .env
            echo "PORT=8000" >> .env
        fi
    else
        echo "✅ .env already exists"
    fi

# Start databases
db:
    #!/usr/bin/env bash
    if [ ! -f docker-compose.yml ]; then
        echo "Creating docker-compose.yml..."
        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: monitor_legislativo
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
EOF
    fi
    echo "🚀 Starting Postgres and Redis..."
    docker-compose up -d
    echo "✅ Databases started!"

# Run backend
backend: env
    cd backend && poetry install --no-interaction && poetry run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Run frontend
frontend: env
    #!/usr/bin/env bash
    if [ -d frontend ]; then
        cd frontend && npm install && npm run dev
    else
        echo "⚠️  Frontend directory not found"
    fi

# Run tests
test:
    cd backend && poetry run pytest -v

# Run migrations
migrate: env
    cd backend && poetry run alembic upgrade head

# Clean up
clean:
    docker-compose down || true

# Development shell
shell:
    cd backend && poetry shell