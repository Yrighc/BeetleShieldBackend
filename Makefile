.PHONY: run dev-up dev-down test docker-build docker-up docker-down

run:
	go run ./cmd/server

dev-up:
	docker compose up -d

dev-down:
	docker compose down

test:
	go test ./... -v

# Full-stack deployment: builds and runs the app (server + hardening worker
# + dpt.jar + JRE) alongside postgres/minio, via the "full" compose profile.
# Requires a real dpt.jar at ./dpt/dpt.jar first (see README "Docker 化部署").
docker-build:
	docker compose --profile full build app

docker-up:
	docker compose --profile full up -d --build

docker-down:
	docker compose --profile full down
