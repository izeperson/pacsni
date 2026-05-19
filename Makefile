.PHONY: all cpp rust go run clean certs

all: cpp rust go certs

# Build the C++ packet capture program
cpp:
	@echo "Building C++ packet capture..."
	@mkdir -p cpp/bin 
	@g++ -std=c++17 -Wall -Wextra -lpcap -lssl -lcrypto cpp/packet_capture.cpp -o cpp/bin/packet_capture

# Build the Rust packet service
rust:
	@echo "Building Rust packet service..."
	@cd rust/packet_service && cargo build --release
	@mkdir -p rust/bin
	@cp rust/packet_service/target/release/packet_service rust/bin/

# Build the Go dashboard
go:
	@echo "Building Go dashboard..."
	@mkdir -p go/bin
	@cd go/dashboard && ( [ -f go.mod ] || go mod init dashboard ) && go mod tidy && go build -o ../bin/dashboard .

# Generate self-signed certificates for TLS
certs:
	@if [ ! -f server.crt ] || [ ! -f server.key ]; then \
		echo "Generating self-signed certificates..."; \
		openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"; \
	fi

# Run all components
run: all certs
	@echo "Starting Real-Time Packet Analyzer System..."
	@echo "Make sure you have libpcap installed and run with sudo if needed for packet capture"
	@echo ""
	@rust/bin/packet_service & RUST_PID=$$!; \
	go/bin/dashboard & GO_PID=$$!; \
	echo "Dashboard initialized at http://localhost:8080"; \
	echo "3. Starting C++ packet capture..."; \
	sudo -E cpp/bin/packet_capture || ./cpp/bin/packet_capture; \
	echo "Cleaning up..."; \
	kill $$RUST_PID $$GO_PID 2>/dev/null || true

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -rf cpp/bin rust/bin go/bin server.crt server.key
	@cd rust/packet_service && cargo clean
	@echo "Clean complete."

# Help target
help:
	@echo "Real-Time Packet Analyzer Dashboard"
	@echo ""
	@echo "Targets:"
	@echo "  all    - Build all components (cpp, rust, go)"
	@echo "  cpp    - Build only the C++ packet capture"
	@echo "  rust   - Build only the Rust packet service"
	@echo "  go     - Build only the Go dashboard"
	@echo "  run    - Build and run all components"
	@echo "  clean  - Remove all build artifacts"
	@echo "  help   - Show this help message"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - libpcap development headers (for C++ component)"
	@echo "  - Rust toolchain (for Rust component)"
	@echo "  - Go 1.19+ (for Go component)"
	@echo ""
	@echo "Usage:"
	@echo "  make run     # Build and run the complete system"
	@echo "  make         # Same as make all"
	@echo ""
	@echo "Note: Packet capture typically requires root/administrator privileges."
	@echo "      The system will prompt for sudo when needed."