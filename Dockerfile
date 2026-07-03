# Builds the beetleshield-backend API/worker and packages it together with
# the dpt.jar hardening engine and a JRE: internal/worker/engine.go shells
# out to `java -jar dpt.jar`, so without both the container's hardening
# pipeline cannot run at all, even though the server itself is a static Go
# binary. dpt.jar is a proprietary external artifact not tracked in this
# repo (see .gitignore) — place a real one at ./dpt/dpt.jar before building
# (see README "Docker 化部署").

FROM golang:1.26.1-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/beetleshield-server ./cmd/server

FROM eclipse-temurin:21-jre-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/beetleshield-server ./beetleshield-server
COPY dpt/dpt.jar /opt/dpt/dpt.jar

EXPOSE 8080
ENTRYPOINT ["./beetleshield-server"]
