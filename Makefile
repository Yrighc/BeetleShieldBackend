.PHONY: run dev-up dev-down test docker-build docker-up docker-down docker-save docker-load-up

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

# Build on this machine, then export to a tar so it can be moved to a
# server that doesn't have (and doesn't need) ./dpt/, ./web/, or a Go/Node
# toolchain — see docs/deployment.md "跨机器部署".
docker-save: docker-build
	docker save beetleshield-backend:latest -o beetleshield-backend.tar

# On the deploy server, after `docker load -i beetleshield-backend.tar`:
# starts postgres/minio/app WITHOUT rebuilding, using the image you loaded.
# Only docker-compose.yml and .env need to exist on that server.
docker-load-up:
	docker compose --profile full up -d
