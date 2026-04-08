BINARY_NAME := codejourney
PORT ?= 3000

.PHONY: build run serve clean test check fmt lint release

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
