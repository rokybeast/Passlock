.PHONY: all build run clean server test

all: build

build:
	@echo "→ Building rust cli..."
	cargo build --release
	@echo "[✓] Done."

run:
	@echo "[→] Running PASSLOCK..."
	cargo run --release

server:
	@echo "[→] Building GO API server..."
	cd go_src && go build -o ../target/release/passlock-server api_server.go
	@echo "[→] Starting Server..."
	./target/release/passlock-server

clean:
	@echo "[→] Cleaning..."
	cargo clean
	rm -f target/release/passlock-server
	@echo "[✓] Cleaned."

test:
	@echo "[→] Testing c crypto..."
	gcc -o test_crypto c_src/crypto_core.c -DTEST_MODE
	./test_crypto
	rm test_crypto
	@echo "[✓] Tests Passed."