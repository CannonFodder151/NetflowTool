FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install Node.js for frontend build
RUN apk add --no-cache nodejs npm

# Build frontend
COPY frontend/package.json frontend/package-lock.json* ./frontend/
WORKDIR /build/frontend
RUN npm ci

COPY frontend/ ./frontend/
RUN npm run build

# Build backend
WORKDIR /build
COPY backend/go.mod ./backend/
RUN cd backend && go mod download

COPY backend/ ./backend/
WORKDIR /build/backend
RUN     CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o /build/netflow-collector .

FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app
COPY --from=builder /build/netflow-collector .
COPY --from=builder /build/frontend/dist ./public

EXPOSE 8080 514 2055

ENV DB_PATH=/data/netflow.db
ENV ADMIN_PASSWORD=admin

VOLUME ["/data"]

CMD ["./netflow-collector"]