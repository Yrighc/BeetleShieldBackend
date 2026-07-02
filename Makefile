.PHONY: run dev-up dev-down test

run:
	go run ./cmd/server

dev-up:
	docker compose up -d

dev-down:
	docker compose down

test:
	go test ./... -v
