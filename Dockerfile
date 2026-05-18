FROM ubuntu:latest AS cpp_builder
WORKDIR /app/cpp
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY cpp/packet_capture.cpp .
COPY cpp/Makefile .
RUN make

FROM rust:latest AS rust_builder
WORKDIR /app/rust/packet_service
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY rust/packet_service/src ./src
COPY rust/packet_service/Cargo.toml .
COPY rust/packet_service/Cargo.lock .
RUN openssl genrsa -out server.key 2048
RUN openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"
RUN cargo build --release

FROM golang:latest AS go_builder
WORKDIR /app/go/dashboard
COPY go/dashboard/main.go .
COPY go/dashboard/index.html .
RUN go mod init dashboard || true
RUN go mod tidy
RUN go build -o dashboard .

FROM ubuntu:latest
WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=cpp_builder /app/cpp/packet_capture /app/cpp/packet_capture

COPY --from=rust_builder /app/rust/packet_service/target/release/packet_service /app/rust/packet_service
COPY --from=rust_builder /app/rust/packet_service/server.crt /app/rust/server.crt
COPY --from=rust_builder /app/rust/packet_service/server.key /app/rust/server.key

COPY --from=go_builder /app/go/dashboard/dashboard /app/go/dashboard/dashboard

EXPOSE 8080