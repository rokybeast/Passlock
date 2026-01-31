# PASSLOCK - Flexible Password Manager

A secure password manager built with **Rust**, **C**, and **Go**.

## Architecture

```
┌─────────────┐
│   Rust CLI  │  ← Main interface
└──────┬──────┘
       │
       ├──→ ┌─────────────┐
       │    │  C Crypto   │  ← Low-level crypto operations
       │    └─────────────┘
       │
       └──→ ┌─────────────┐
            │  Go Server  │  ← Optional HTTP API
            └─────────────┘
```

## Languages Used

- **Rust** - Main CLI, encryption wrapper, storage
- **C** - Core crypto functions, XOR cipher, secure memory ops
- **Go** - HTTP API server for remote access

## Directory Structure

```
password-manager/
├── Cargo.toml
├── build.rs
├── Makefile
├── README.md
├── .gitignore
├── c_src/
│   ├── crypto_core.c
│   └── crypto_core.h
├── go_src/
│   └── api_server.go
└── src/
│   ├── main.rs
│   ├── crypto.rs
│   ├── storage.rs
│   ├── ui.rs
│   └── models.rs
│
└── web/
    └── index.html
```

## Build & Run

```bash
# Build everything
make build

# Run CLI
make run

# Start API server (optional)
make server

# Clean build artifacts
make clean

# Test C crypto
make test
```

## Features

- AES-256-GCM encryption (Rust)
- XOR obfuscation layer (C)
- Argon2 key derivation (Rust)
- Secure memory wiping (C)
- HTTP API (Go)
- Beautiful terminal UI
- Password generator
- Search & filter
- Persistent vault storage

## Security

- Master password protection
- Multi-layer encryption
- Timing-safe comparisons (C)
- Secure random generation (C)
- Zero-on-free for sensitive data (C)

## API Usage (Go Server)

```bash
make server
```
Then you would have to go to http://localhost:8080/

## Why Multi-Language?

- **Rust**: Memory safety + performance for main app
- **C**: Maximum control for crypto primitives
- **Go**: Simple HTTP server with great concurrency
- **Learning**: Shows FFI and language interop
