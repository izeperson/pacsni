# Real-Time Packet Analyzer Dashboard

A high-performance, multi-language packet analysis system built with C++, Rust, and Go. This system captures network packets in real-time, processes them with minimal latency, and displays them in an interactive web dashboard.

## System Architecture

```
[Network Interface] 
        ↓ (libpcap)
[C++ Packet Capture] ───┐
        ↓ (TCP)         │
[Rust Packet Service] ──┼─── [Go Dashboard] ◄── Web Interface
        ↓ (TCP)         │
[WebSocket/SSE] ◄───────┘
```

### Components

1. **C++ Packet Capture** (`cpp/packet_capture.cpp`)
   - Uses libpcap to capture live network packets
   - Parses Ethernet, IP, TCP/UDP/ICMP headers
   - Sends packet metadata and payload to Rust service via TCP
   - Optimized for minimal processing overhead

2. **Rust Packet Service** (`rust/packet_service/`)
   - Receives raw packet data from C++ component
   - Converts to structured format (JSON)
   - Broadcasts to connected Go dashboard clients
   - Built with Tokio for async I/O and high concurrency

3. **Go Dashboard** (`go/`)
   - Web server serving real-time dashboard
   - Uses Server-Sent Events (SSE) for live updates
   - Interactive filtering and statistics
   - Responsive UI with modern styling

## Features

- **Real-time Processing**: Sub-millisecond latency from packet capture to display
- **Multi-protocol Support**: TCP, UDP, ICMP, and other IP protocols
- **Deep Packet Inspection**: View headers and payload data
- **Interactive Filtering**: Filter by protocol, IP addresses, ports
- **Live Statistics**: Real-time packet counters
- **Cross-platform**: Works on Linux and macOS (with libpcap)
- **Secure**: No external dependencies beyond standard libraries

## Prerequisites

- **Linux/macOS**: libpcap development headers
- **Rust**: Latest stable toolchain (via rustup)
- **Go**: Version 1.19 or higher
- **C++ Compiler**: GCC or Clang with C++11 support

### Installation

#### Ubuntu/Debian
```bash
sudo apt-get install libpcap-dev build-essential
```

#### macOS (with Homebrew)
```bash
brew install libpcap
```

#### Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Go
Visit https://golang.org/dl/ or use your package manager

## Building and Running

```bash
# Build all components
make

# Or build individually
make cpp   # Build C++ packet capture
make rust  # Build Rust packet service
make go    # Build Go dashboard

# Run the complete system
make run
```

The system will:
1. Start the Rust service on ports 9001 (C++ input) and 9003 (Go output)
2. Start the Go dashboard on port 8080
3. Start the C++ packet capture (may require sudo)

Access the dashboard at: http://localhost:8080

## Usage Notes

- **Packet Capture Privileges**: The C++ component requires root/administrator privileges to capture packets. The Makefile will prompt for sudo when needed.
- **Interface Selection**: Currently uses the first available network interface. Modify `packet_capture.cpp` to specify a particular interface.
- **Performance**: Designed for high-speed packet processing. Adjust buffer sizes in the source code for your specific network environment.
- **Payload Limitation**: For performance, only the first 128 bytes of each packet payload are transmitted and displayed.

## Customization

### Changing Capture Interface (C++)
Edit `cpp/packet_capture.cpp`:
```cpp
// Instead of using the first interface:
// d = alldevs;
// Specify a particular interface by name:
// d = pcap_findalldevs(...); then find by name
```

### Adjusting Payload Size
Modify `MAX_PAYLOAD_SIZE` in:
- `cpp/packet_capture.cpp`
- `rust/packet_service/src/main.rs`

### Changing Ports
Update the port constants in each component:
- C++: `DEST_PORT` (for sending to Rust)
- Rust: `cpp_addr` and `go_addr` (listening ports)
- Go: Connection port to Rust service (9003)

## Safety and Ethics

This tool is intended for legitimate network analysis, troubleshooting, and educational purposes only. Users should:
- Only capture packets on networks they own or have explicit permission to monitor
- Comply with all applicable laws and regulations
- Respect privacy and data protection requirements
- Use responsibly and ethically

## Troubleshooting

### No Packets Appearing
1. Verify the C++ program is running with sufficient privileges
2. Check that the Rust service is listening (`netstat -tlnp | grep 9001`)
3. Ensure the Go dashboard can connect to the Rust service
4. Check firewall settings

### High CPU Usage
- Consider increasing the payload buffer size to reduce system calls
- Ensure you're capturing on an appropriate interface (not loopback for external traffic)
- Adjust snaplen in `pcap_open_live()` if needed

### Compilation Errors
- Verify all prerequisites are installed
- Check library paths for libpcap
- Ensure Rust and Go toolchains are properly configured

## License

This project is provided for educational and legitimate network analysis purposes. See individual files for specific licensing information.

---
*Built with C++ for performance, Rust for safety and concurrency, and Go for simplicity and excellent standard library.*