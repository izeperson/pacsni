.PHONY: all cpp rust go run clean certs

ifeq ($(OS),Windows_NT)
    # Windows Configuration
    EXE_EXT := .exe
    # Detection for MSVC (cl) vs MinGW (g++)
    ifneq ($(shell where cl 2>NUL),)
        CXX := cl
        # Paths for Npcap and OpenSSL - adjust these to your installation
        NPCAP_SDK ?= C:\Program Files\Npcap\sdk
        OPENSSL_DIR ?= C:\Program Files\OpenSSL-Win64
        CXXFLAGS := /EHsc /W3 /O2 /I"$(NPCAP_SDK)\Include" /I"$(OPENSSL_DIR)\include"
        LDFLAGS := /link /LIBPATH:"$(NPCAP_SDK)\Lib\x64" /LIBPATH:"$(OPENSSL_DIR)\lib" wpcap.lib Packet.lib libssl.lib libcrypto.lib ws2_32.lib
        BUILD_CPP_CMD = $(CXX) $(CXXFLAGS) cpp/packet_capture.cpp cpp/protocol_dissectors.cpp /Fe:cpp/bin/packet_capture$(EXE_EXT) $(LDFLAGS)
    else
        CXX := g++
        BUILD_CPP_CMD = $(CXX) -std=c++17 -Wall -Wextra cpp/packet_capture.cpp cpp/protocol_dissectors.cpp -o cpp/bin/packet_capture$(EXE_EXT) -lwpcap -lssl -lcrypto -lws2_32
    endif
    MKDIR := powershell -Command New-Item -ItemType Directory -Force
    RM := powershell -Command Remove-Item -Recurse -Force
    CP := powershell -Command Copy-Item
else
    # Linux / macOS Configuration
    EXE_EXT :=
    BUILD_CPP_CMD = g++ -std=c++17 -Wall -Wextra cpp/packet_capture.cpp cpp/protocol_dissectors.cpp -o cpp/bin/packet_capture -lpcap -lssl -lcrypto
    MKDIR := mkdir -p
    RM := rm -rf
    CP := cp
endif

all: cpp rust go certs

# Build the C++ packet capture program
cpp:
	@echo "Building C++ packet capture..."
	@$(MKDIR) cpp/bin 2>/dev/null || true
	@$(BUILD_CPP_CMD)

# Build the Rust packet service
rust:
	@echo "Building Rust packet service..."
	@cd rust/packet_service && cargo build --release
	@$(MKDIR) rust/bin 2>/dev/null || true
	@$(CP) rust/packet_service/target/release/packet_service$(EXE_EXT) rust/bin/

# Build the Go dashboard
go:
	@echo "Building Go dashboard..."
	@$(MKDIR) go/bin 2>/dev/null || true
	@cd go/dashboard && go mod tidy && go build -o ../bin/dashboard$(EXE_EXT) .

# Generate self-signed certificates for TLS
certs:
	@openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null || echo "Note: OpenSSL failed. Ensure it is in your PATH."

# Run all components
run: all certs
	@echo "Starting system..."
	@echo "Note: On Windows, use Git Bash for the background processes to work correctly."
	@echo ""
	@rust/bin/packet_service$(EXE_EXT) & RUST_PID=$$!; \
	go/bin/dashboard$(EXE_EXT) & GO_PID=$$!; \
	echo "Dashboard initialized at http://localhost:8080"; \
	$(CP) go/dashboard/GeoLite2-City.mmdb go/bin/ 2>/dev/null || true; \
	$(if $(filter $(OS),Windows_NT), ./cpp/bin/packet_capture$(EXE_EXT), sudo -E ./cpp/bin/packet_capture || ./cpp/bin/packet_capture); \
	echo "Cleaning up..."; \
	$(if $(filter $(OS),Windows_NT), taskkill /F /PID $$RUST_PID /PID $$GO_PID, kill $$RUST_PID $$GO_PID 2>/dev/null || true)

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@$(RM) cpp/bin rust/bin go/bin server.crt server.key
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