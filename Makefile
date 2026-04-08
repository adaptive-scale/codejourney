BINARY_NAME := codejourney
PORT ?= 3000
VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
DIST_DIR := dist

TARGETS := \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu

.PHONY: build run serve clean test check fmt lint release release-all release-local dist checksums

build:
	cargo build

release:
	cargo build --release

run:
	cargo run -- $(ARGS)

serve:
	cargo run -- serve -p $(PORT)

check:
	cargo check

test:
	cargo test

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

clean:
	cargo clean
	rm -rf $(DIST_DIR)

# Build release binary for the current platform and copy to dist/
release-local:
	cargo build --release
	mkdir -p $(DIST_DIR)
	cp target/release/$(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)
	@echo "Built $(DIST_DIR)/$(BINARY_NAME)"

# Cross-compile release binaries for all targets
release-all:
	mkdir -p $(DIST_DIR)
	@for target in $(TARGETS); do \
		echo "Building $$target..."; \
		cargo build --release --target $$target || { echo "Skipping $$target (toolchain not installed)"; continue; }; \
		os=$$(echo $$target | cut -d'-' -f3); \
		arch=$$(echo $$target | cut -d'-' -f1); \
		cp target/$$target/release/$(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)-$$os-$$arch; \
		echo "  -> $(DIST_DIR)/$(BINARY_NAME)-$$os-$$arch"; \
	done

# Create tarballs for distribution
dist: release-all
	@cd $(DIST_DIR) && for bin in $(BINARY_NAME)-*; do \
		tar czf $$bin-v$(VERSION).tar.gz $$bin; \
		echo "Packaged $$bin-v$(VERSION).tar.gz"; \
	done

# Generate checksums for all artifacts
checksums:
	@cd $(DIST_DIR) && shasum -a 256 *.tar.gz > checksums-v$(VERSION).txt
	@echo "Checksums written to $(DIST_DIR)/checksums-v$(VERSION).txt"
