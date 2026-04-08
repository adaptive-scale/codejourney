BINARY_NAME := codejourney
PORT ?= 3000
VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
DIST_DIR := dist

TARGETS := \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu

.PHONY: build run serve clean test check fmt lint release release-all release-local dist checksums tag publish

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

# Auto-create/update and push a git tag from Cargo.toml version
tag:
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Updating existing tag v$(VERSION)..."; \
		git tag -d "v$(VERSION)"; \
		git push origin ":refs/tags/v$(VERSION)" 2>/dev/null || true; \
	fi
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "Tagged and pushed v$(VERSION)"

# One-shot: build release, tag, and create GitHub release with binary
publish: release-local tag
	@if gh release view "v$(VERSION)" --repo adaptive-scale/codejourney >/dev/null 2>&1; then \
		echo "Updating existing release v$(VERSION)..."; \
		gh release delete "v$(VERSION)" --repo adaptive-scale/codejourney --yes; \
	fi
	gh release create "v$(VERSION)" $(DIST_DIR)/$(BINARY_NAME) \
		--repo adaptive-scale/codejourney \
		--title "v$(VERSION)" \
		--generate-notes
	@echo "Published v$(VERSION) to GitHub"
