BINARY    := witness
PD_BINARY := witness-pd
MODULE    := github.com/bigblue-r4/kiss-protocol
CMD       := ./cmd/witness
PD_CMD    := ./cmd/witness-pd
GOFLAGS   := -trimpath -ldflags="-s -w"

# Flags that produce a reproducible binary: same source + same toolchain = same bytes.
# -trimpath     strips local build paths
# -buildvcs=false  omits VCS metadata that varies between machines
REPRO_FLAGS := -trimpath -ldflags="-s -w" -buildvcs=false

.PHONY: all build build-pd install install-pd clean tidy test \
        reproducible-build verify-reproducible fuzz

all: build build-pd

build:
	go build $(GOFLAGS) -o $(BINARY) $(CMD)

build-pd:
	go build $(GOFLAGS) -o $(PD_BINARY) $(PD_CMD)

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

install-pd: build-pd
	install -m 0755 $(PD_BINARY) /usr/local/bin/$(PD_BINARY)

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(PD_BINARY) $(BINARY).2 $(BINARY).sha256

# Run the test suite (add tests to internal/*/**_test.go as needed).
test:
	go test ./...

# Build with reproducibility flags and record the SHA-256.
reproducible-build:
	GOTOOLCHAIN=local go build $(REPRO_FLAGS) -o $(BINARY) $(CMD)
	sha256sum $(BINARY) | tee $(BINARY).sha256

# Build twice from clean and verify the hashes match.
# A mismatch means a non-deterministic input slipped into the build.
verify-reproducible:
	GOTOOLCHAIN=local go build $(REPRO_FLAGS) -o $(BINARY) $(CMD)
	sha256sum $(BINARY) > $(BINARY).sha256
	GOTOOLCHAIN=local go build $(REPRO_FLAGS) -o $(BINARY).2 $(CMD)
	@h1=$$(sha256sum $(BINARY)   | awk '{print $$1}'); \
	 h2=$$(sha256sum $(BINARY).2 | awk '{print $$1}'); \
	 if [ "$$h1" = "$$h2" ]; then \
	   echo "PASS  reproducible: $$h1"; \
	 else \
	   echo "FAIL  build not reproducible"; \
	   echo "  build 1: $$h1"; \
	   echo "  build 2: $$h2"; \
	   exit 1; \
	 fi
	rm -f $(BINARY).2

# Run all fuzz targets for a short pass (useful locally; CI uses -fuzztime=30s).
fuzz:
	go test -fuzz=FuzzLoad             -fuzztime=10s ./internal/soul/
	go test -fuzz=FuzzAppend           -fuzztime=10s ./internal/store/
	go test -fuzz=FuzzDecodePacket     -fuzztime=10s ./internal/gossip/
	go test -fuzz=FuzzPushJSON         -fuzztime=10s ./internal/mirror/
