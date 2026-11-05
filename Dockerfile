# --- Build stage ---
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Build the API binary and database migration utility.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -tags netgo -ldflags "-s -w" -o /out/gradiol-api ./cmd/api \
    && CGO_ENABLED=0 GOOS=linux go build -tags netgo -ldflags "-s -w" -o /out/gradiol-migrate ./cmd/migrate

# --- Runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/gradiol-api /app/gradiol-api
COPY --from=build --chown=nonroot:nonroot /out/gradiol-migrate /app/gradiol-migrate

EXPOSE 8080
ENTRYPOINT ["/app/gradiol-api"]
