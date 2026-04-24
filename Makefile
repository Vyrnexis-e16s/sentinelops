.PHONY: help up down build logs seed test test-backend test-frontend test-ml test-e2e lint format clean reset-db

help:
	@echo "SentinelOps — useful targets"
	@echo ""
	@echo "  make up            Bring up the full stack with docker compose"
	@echo "  make down          Stop the stack"
	@echo "  make build         Rebuild all docker images"
	@echo "  make logs          Tail logs from all services"
	@echo "  make seed          Load development events, users, and CVEs"
	@echo "  make test          Run all test suites"
	@echo "  make test-backend  pytest inside the backend container"
	@echo "  make test-frontend vitest inside the frontend container"
	@echo "  make test-ml       pytest inside the ml container"
	@echo "  make test-e2e      Playwright smoke suite"
	@echo "  make lint          ruff + black --check + mypy + eslint + tsc"
	@echo "  make format        ruff --fix + black + prettier --write"
	@echo "  make clean         Remove build artifacts"
	@echo "  make reset-db      Drop and recreate the postgres volume"

up:
	docker compose -f infra/docker/docker-compose.yml up -d

down:
	docker compose -f infra/docker/docker-compose.yml down

build:
	docker compose -f infra/docker/docker-compose.yml build

logs:
	docker compose -f infra/docker/docker-compose.yml logs -f --tail=100

seed:
	docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed

test: test-backend test-frontend test-ml

test-backend:
	cd backend && pytest -q

test-frontend:
	cd frontend && pnpm test --run

test-ml:
	cd ml && pytest -q

test-e2e:
	cd frontend && pnpm exec playwright test

lint:
	cd backend && ruff check . && black --check . && mypy app
	cd frontend && pnpm lint && pnpm exec tsc --noEmit

format:
	cd backend && ruff check --fix . && black .
	cd frontend && pnpm exec prettier --write .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/.next frontend/out
	rm -rf backend/dist backend/build

reset-db:
	docker compose -f infra/docker/docker-compose.yml down -v
	docker compose -f infra/docker/docker-compose.yml up -d db redis
