BINARY_NAME := codejourney
REPO := adaptive-scale/codejourney
PORT ?= 3000
# Read straight from Cargo.toml: only the [package] version starts a line with
# "version", so this can't pick up a dependency's version by mistake.
VERSION ?= $(shell grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
DIST_DIR := dist

# Optional path to a release-notes markdown file; falls back to --generate-notes.
NOTES ?=

TARGETS := \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu

# Name the host build the same way release-all names cross-compiled targets,
# which is also what install.sh looks for.
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m | sed -e 's/arm64/aarch64/' -e 's/amd64/x86_64/')
HOST_PLATFORM := $(HOST_OS)-$(HOST_ARCH)

.PHONY: build run serve clean test check fmt lint release release-all release-local \
	package dist dist-local checksums tag publish

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

# Build release binary for the current platform and copy to dist/.
# Emitted twice: the bare name for backwards compatibility with v0.1.0, and the
# platform-suffixed name that install.sh resolves.
release-local:
	cargo build --release
	mkdir -p $(DIST_DIR)
	cp target/release/$(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)
	cp target/release/$(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)-$(HOST_PLATFORM)
	@echo "Built $(DIST_DIR)/$(BINARY_NAME)-$(HOST_PLATFORM)"

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

# Tar every platform binary already sitting in dist/, skipping our own output.
package:
	@cd $(DIST_DIR) && for bin in $(BINARY_NAME)-*; do \
		case "$$bin" in *.tar.gz|*.txt) continue;; esac; \
		tar czf $$bin-v$(VERSION).tar.gz $$bin; \
		echo "Packaged $$bin-v$(VERSION).tar.gz"; \
	done

# Cross-compiled artifacts for every target in TARGETS
dist: release-all package checksums

# Artifacts for the host platform only
dist-local: release-local package checksums

# Checksum the binaries as well as the tarballs, under the name install.sh
# checks first.
checksums:
	@cd $(DIST_DIR) && shasum -a 256 $(BINARY_NAME)* > checksums.txt
	@echo "Checksums written to $(DIST_DIR)/checksums.txt"

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

# One-shot: build, package, tag, and create the GitHub release with every
# artifact. Pass NOTES=path/to/notes.md to supply release notes.
publish: dist-local tag
	@if gh release view "v$(VERSION)" --repo $(REPO) >/dev/null 2>&1; then \
		echo "Updating existing release v$(VERSION)..."; \
		gh release delete "v$(VERSION)" --repo $(REPO) --yes; \
	fi
	gh release create "v$(VERSION)" \
		$(DIST_DIR)/$(BINARY_NAME) \
		$(DIST_DIR)/$(BINARY_NAME)-$(HOST_PLATFORM) \
		$(DIST_DIR)/$(BINARY_NAME)-$(HOST_PLATFORM)-v$(VERSION).tar.gz \
		$(DIST_DIR)/checksums.txt \
		--repo $(REPO) \
		--title "v$(VERSION)" \
		$(if $(NOTES),--notes-file $(NOTES),--generate-notes)
	@echo "Published v$(VERSION) to GitHub"
