# Builds the beetleshield-backend API/worker and packages it together with
# the dpt.jar hardening engine and a JRE: internal/worker/engine.go shells
# out to `java -jar dpt.jar`, so without both the container's hardening
# pipeline cannot run at all, even though the server itself is a static Go
# binary. A plain JRE is enough — verified end-to-end (VMP + DEX protection
# + the test-signed artifact, which dpt.jar signs itself via a bundled
# apksig-style library, not the JDK-only `jarsigner`) — but dpt.jar resolves
# its shell-files/ and bin/ companion resources relative to its own jar
# path, not the CWD, so the whole ./dpt/ bundle must be copied, not just the
# jar. dpt.jar and its companions are proprietary external artifacts not
# tracked in this repo (see .gitignore) — populate ./dpt/ (dpt.jar,
# shell-files/, bin/) before building (see README "Docker 化部署").

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
COPY dpt/ /opt/dpt/

EXPOSE 8080
ENTRYPOINT ["./beetleshield-server"]
