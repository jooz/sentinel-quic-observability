.PHONY: all build-ebpf build-agent build run run-agent clean docker-up docker-down test-db

CARGO = cargo
NIGHTLY = +nightly-2026-04-01

all: build

build: build-ebpf build-agent

build-ebpf:
	$(CARGO) $(NIGHTLY) build --release --target bpfel-unknown-none -Z build-std=core --package sentinel-ebpf

build-agent:
	$(CARGO) build --release --package sentinel-agent

run: docker-up
	sudo ./target/release/sentinel-agent --iface eth0

run-agent:
	sudo ./target/release/sentinel-agent --iface eth0

docker-up:
	docker compose up -d clickhouse

docker-down:
	docker compose down

test-db:
	@echo "Inserting test data..."
	curl -s --user sentinel:sentinel_pass "http://localhost:8123/?database=sentinel" \
		--data-binary "INSERT INTO network_logs (timestamp, source_ip, destination_domain, bytes_transfered) VALUES \
		(now64(), '192.168.1.100', 'youtube.com', 104857600), \
		(now64(), '192.168.1.100', 'github.com', 52428800), \
		(now64(), '192.168.1.101', 'netflix.com', 209715200)"
	@echo ""
	curl -s --user sentinel:sentinel_pass "http://localhost:8123/?database=sentinel" \
		--data-binary "SELECT source_ip, destination_domain, SUM(bytes_transfered) / 1048576 AS MB_consumed \
		FROM network_logs GROUP BY source_ip, destination_domain ORDER BY MB_consumed DESC LIMIT 10 FORMAT Pretty"

clean:
	$(CARGO) clean
	docker compose down -v
