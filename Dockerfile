FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o netflow-collector .

FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app
COPY --from=builder /build/netflow-collector .
COPY --from=builder /build/backend/internal ./internal
COPY frontend/public ./public

EXPOSE 8080 514 2055

ENV DB_PATH=/data/netflow.db
ENV ADMIN_PASSWORD=admin

VOLUME ["/data"]

CMD ["./netflow-collector"]