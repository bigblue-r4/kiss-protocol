BINARY    := witness
PD_BINARY := witness-pd
MODULE    := github.com/bigblue-r4/kiss-protocol
CMD       := ./cmd/witness
PD_CMD    := ./cmd/witness-pd
GOFLAGS   := -trimpath -ldflags="-s -w"

.PHONY: all build build-pd install install-pd clean tidy test

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
	rm -f $(BINARY) $(PD_BINARY)

# Run the test suite (add tests to internal/*/**_test.go as needed).
test:
	go test ./...
