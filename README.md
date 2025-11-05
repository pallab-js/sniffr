# sniffr

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern, user-friendly packet capture and analysis tool written in Rust. This CLI tool provides packet capture and analysis capabilities with a better user experience, colored output, and intuitive interface.

## ? Features

- ?? **Beautiful Output**: Color-coded, formatted packet display
- ? **Fast**: Built with Rust for high performance
- ?? **Multiple Formats**: Text, JSON, CSV, and detailed output modes
- ?? **Filtering**: Support for BPF filters and application-level display filters
- ?? **Statistics**: Real-time protocol distribution, top talkers, conversations, and port analysis
- ?? **File I/O**: Read from and write to pcap files
- ?? **Protocol Support**: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, HTTP, DNS
- ??? **Cross-Platform**: Works on Linux, macOS, and Windows

## ?? Installation

### Prerequisites

- **Rust** (latest stable version) - [Install Rust](https://www.rust-lang.org/tools/install)
- **libpcap** (required for packet capture)
  - **macOS**: `brew install libpcap`
  - **Linux**: 
    - Debian/Ubuntu: `sudo apt-get install libpcap-dev`
    - RHEL/CentOS: `sudo yum install libpcap-devel`
    - Fedora: `sudo dnf install libpcap-devel`
  - **Windows**: Install [Npcap](https://nmap.org/npcap/) or WinPcap

### Build from Source

```bash
git clone https://github.com/pallab-js/sniffr.git
cd sniffr
cargo build --release
```

The binary will be located at `target/release/sniffr`.

### Installation

```bash
# Build and install to cargo bin directory
cargo install --path .
```

## ?? Usage

### List Available Interfaces

```bash
sniffr interfaces
```

### Capture Packets

**Basic capture (default interface):**
```bash
sudo sniffr capture
```

**Capture from specific interface:**
```bash
sudo sniffr capture -i en0
```

**Capture specific number of packets:**
```bash
sudo sniffr capture -c 10
```

**Capture with BPF filter:**
```bash
sudo sniffr capture -f "tcp port 80"
sudo sniffr capture -f "udp port 53"
sudo sniffr capture -f "ip src 192.168.1.1"
```

**Verbose/detailed output:**
```bash
sudo sniffr capture -v
```

**JSON output:**
```bash
sudo sniffr capture --format json
```

**CSV output:**
```bash
sudo sniffr capture --format csv > packets.csv
```

**Save captured packets to file:**
```bash
sudo sniffr capture --write output.pcap
```

### Read from Pcap File

**Read packets from file:**
```bash
sniffr read file.pcap
```

**Read with filter:**
```bash
sniffr read file.pcap --filter "tcp port 80"
```

**Read specific number of packets:**
```bash
sniffr read file.pcap -c 100
```

### Statistics Mode

**Collect statistics from live capture:**
```bash
sudo sniffr stats -i en0 -c 1000
```

**Statistics from pcap file:**
```bash
sniffr stats --file file.pcap
```

Statistics include:
- Protocol distribution
- Top conversations
- Top talkers (IP addresses)
- Top ports

## ?? Examples

**Monitor HTTP traffic:**
```bash
sudo sniffr capture -f "tcp port 80" -v
```

**Capture DNS queries:**
```bash
sudo sniffr capture -f "udp port 53" -c 20
```

**Monitor traffic to/from specific IP:**
```bash
sudo sniffr capture -f "host 8.8.8.8"
```

**Capture and save to JSON:**
```bash
sudo sniffr capture --format json > packets.json
```

**Analyze pcap file:**
```bash
sniffr read file.pcap --format detailed
```

**Get statistics from capture:**
```bash
sudo sniffr stats -c 1000
```

## ?? Command Reference

```
sniffr [COMMAND]

Commands:
  capture     Capture and analyze packets from a network interface
  read        Read and analyze packets from a pcap file
  stats       Show statistics from capture or file
  interfaces  List available network interfaces

Options:
  -h, --help     Print help
  -V, --version  Print version

Capture Options:
  -i, --interface <INTERFACE>  Network interface to capture from
  -c, --count <COUNT>          Number of packets to capture (0 = unlimited)
  -f, --filter <FILTER>        BPF filter (e.g., "tcp port 80")
  -v, --verbose                Verbose/detailed output
  --format <FORMAT>            Output format: text, json, csv, detailed [default: text]
  --write <FILE>               Save captured packets to pcap file
```

## ?? Why Better Than tshark?

1. **Modern UI**: Color-coded output makes it easier to read packet information
2. **Simpler Syntax**: More intuitive command-line interface
3. **Better Defaults**: Sensible defaults for common use cases
4. **Faster**: Rust's performance provides better throughput
5. **Better Error Messages**: Clear, helpful error messages
6. **JSON/CSV Support**: Native JSON and CSV output for easy parsing and integration
7. **Statistics Mode**: Built-in statistics collection and analysis
8. **Type Safety**: Rust's type system prevents many common bugs

## ?? Documentation

- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guidelines for contributors
- **[ENHANCEMENTS.md](ENHANCEMENTS.md)** - Complete list of enhancement suggestions
- **[ROADMAP.md](ROADMAP.md)** - Prioritized development roadmap
- **[QUICK_WINS.md](QUICK_WINS.md)** - Step-by-step implementation guides

## ?? Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/pallab-js/sniffr.git
cd sniffr

# Build
cargo build --release

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy
```

## ?? Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ?? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ?? Acknowledgments

- Inspired by tshark/Wireshark
- Built with [Rust](https://www.rust-lang.org/)
- Uses [libpcap](https://www.tcpdump.org/) for packet capture
- Thanks to all contributors!

## ?? Support

- ?? [Documentation](https://github.com/pallab-js/sniffr/wiki)
- ?? [Report Issues](https://github.com/pallab-js/sniffr/issues)
- ?? [Discussions](https://github.com/pallab-js/sniffr/discussions)

---

**Note**: This tool requires root/administrator privileges for live packet capture on most systems.
