# Monitor Legislativo v4 - Local Development Makefile
SHELL := /bin/bash
.PHONY: help db backend frontend test clean setup env migrate

# Default target
help:
	@echo "Monitor Legislativo v4 - Development Commands"
	@echo "============================================"
	@echo "  make setup     - Initial setup (copy .env.example, install deps)"
	@echo "  make db        - Start Postgres + Redis via docker-compose"
	@echo "  make backend   - Install backend deps + run uvicorn (auto-reload)"
	@echo "  make frontend  - Install frontend deps + run vite dev server"
	@echo "  make test      - Run backend tests with pytest"
	@echo "  make migrate   - Run database migrations"
	@echo "  make clean     - Stop all services and clean up"
	@echo ""

# Initial setup
setup: env
	@echo "✅ Initial setup complete!"
	@echo "Next steps:"
	@echo "  1. Update .env with your configuration"
	@echo "  2. Run 'make db' to start databases"
	@echo "  3. Run 'make backend' in one terminal"
	@echo "  4. Run 'make frontend' in another terminal"

# Create .env from example if it doesn't exist
env:
	@if [ ! -f .env ]; then \
		if [ -f .env.example ]; then \
			cp .env.example .env; \
			echo "✅ Created .env from .env.example"; \
		else \
			echo "⚠️  No .env.example found, creating basic .env"; \
			echo "DATABASE_URL=postgresql://postgres:postgres@localhost:5432/monitor_legislativo" > .env; \
			echo "REDIS_URL=redis://localhost:6379" >> .env; \
			echo "PORT=8000" >> .env; \
		fi \
	else \
		echo "✅ .env already exists"; \
	fi

# Start databases with docker-compose
db:
	@if [ ! -f docker-compose.yml ]; then \
		echo "Creating docker-compose.yml..."; \
		echo "version: '3.8'" > docker-compose.yml; \
		echo "" >> docker-compose.yml; \
		echo "services:" >> docker-compose.yml; \
		echo "  postgres:" >> docker-compose.yml; \
		echo "    image: postgres:15-alpine" >> docker-compose.yml; \
		echo "    environment:" >> docker-compose.yml; \
		echo "      POSTGRES_USER: postgres" >> docker-compose.yml; \
		echo "      POSTGRES_PASSWORD: postgres" >> docker-compose.yml; \
		echo "      POSTGRES_DB: monitor_legislativo" >> docker-compose.yml; \
		echo "    ports:" >> docker-compose.yml; \
		echo "      - \"5432:5432\"" >> docker-compose.yml; \
		echo "    volumes:" >> docker-compose.yml; \
		echo "      - postgres_data:/var/lib/postgresql/data" >> docker-compose.yml; \
		echo "" >> docker-compose.yml; \
		echo "  redis:" >> docker-compose.yml; \
		echo "    image: redis:7-alpine" >> docker-compose.yml; \
		echo "    ports:" >> docker-compose.yml; \
		echo "      - \"6379:6379\"" >> docker-compose.yml; \
		echo "" >> docker-compose.yml; \
		echo "volumes:" >> docker-compose.yml; \
		echo "  postgres_data:" >> docker-compose.yml; \
	fi
	@echo "🚀 Starting Postgres and Redis..."
	@docker-compose up -d
	@echo "✅ Databases started!"
	@echo "   Postgres: postgresql://postgres:postgres@localhost:5432/monitor_legislativo"
	@echo "   Redis: redis://localhost:6379"

# Run backend with auto-reload
backend: env
	@echo "🚀 Starting backend server..."
	@cd backend && \
		poetry install --no-interaction && \
		poetry run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Run frontend dev server
frontend: env
	@echo "🚀 Starting frontend server..."
	@if [ -d frontend ]; then \
		cd frontend && \
		npm install && \
		npm run dev; \
	else \
		echo "⚠️  Frontend directory not found"; \
	fi

# Run tests
test:
	@echo "🧪 Running backend tests..."
	@cd backend && poetry run pytest -v

# Run migrations
migrate: env
	@echo "🔄 Running database migrations..."
	@cd backend && poetry run alembic upgrade head
	@echo "✅ Migrations complete!"

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	@if [ -f docker-compose.yml ]; then \
		docker-compose down; \
	fi
	@echo "✅ Clean up complete!"

# Additional Windows support via justfile
windows-setup:
	@echo "For Windows users, consider using 'just' instead of 'make'"
	@echo "Install from: https://github.com/casey/just"
	@echo "Then run: just setup"