.PHONY: all build run clean server test

all: build

build:
	@echo "→ building rust cli..."
	cargo build --release
	@echo "✓ done"

run:
	@echo "→ running passlock..."
	cargo run --release

server:
	@echo "→ building go api server..."
	cd go_src && go build -o ../target/release/passlock-server api_server.go
	@echo "→ starting server..."
	./target/release/passlock-server

clean:
	@echo "→ cleaning..."
	cargo clean
	rm -f target/release/passlock-server
	@echo "✓ clean"

test:
	@echo "→ testing c crypto..."
	gcc -o test_crypto c_src/crypto_core.c -DTEST_MODE
	./test_crypto
	rm test_crypto
	@echo "✓ tests passed"