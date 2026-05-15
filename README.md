# Sentinel QUIC Observability Agent

An eBPF-powered network observability agent capable of extracting SNI from encrypted QUIC Initial packets (HTTP/3) and traditional TLS (HTTP/1.1/2).

## Features
- **QUIC SNI Extraction**: Decrypts QUIC Initial packets (RFC 9001) for v1, v2, and Draft-29.
- **TLS SNI Extraction**: Parses TCP streams for TLS Handshakes.
- **eBPF Powered**: High-performance packet interception using TC (Traffic Control) classifier.
- **ClickHouse Integration**: Aggregates and persists telemetry data in ClickHouse.

## Architecture
- `sentinel-ebpf`: Kernel-space eBPF program (Rust).
- `sentinel-agent`: Userspace collector and decryptor (Rust + Aya).
- `sentinel-ebpf-common`: Shared types between kernel and userspace.

## Prerequisites
- Linux Kernel 5.15+ (BTF support recommended)
- Rust Nightly (for eBPF compilation)
- Docker (for ClickHouse)

## Usage
1. Start ClickHouse: `docker-compose up -d`
2. Build: `make build`
3. Run: `sudo ./target/release/sentinel-agent --iface <your-interface>`

## License
MIT
