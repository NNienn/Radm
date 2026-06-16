# Top-level Makefile for RADM Container Security Engine

.PHONY: all kernel aggregator mitigation inference clean test

all: kernel aggregator mitigation inference

kernel:
	$(MAKE) -C kernel

aggregator:
	cd aggregator && cargo build --release

mitigation:
	cd mitigation && cargo build --release

inference:
	@if command -v protoc >/dev/null 2>&1; then \
		bash proto/generate.sh; \
	else \
		echo "Warning: protoc not found, skipping Python proto generation."; \
	fi

clean:
	$(MAKE) -C kernel clean || true
	cd aggregator && cargo clean
	cd mitigation && cargo clean

test:
	cd aggregator && cargo test
	cd mitigation && cargo test
