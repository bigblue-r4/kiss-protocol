BINARY   := witness
MODULE   := github.com/luckyPipewrench/witness-client
CMD      := ./cmd/witness
GOFLAGS  := -trimpath -ldflags="-s -w"

.PHONY: all build install clean tidy

all: build

build:
	go build $(GOFLAGS) -o $(BINARY) $(CMD)

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

# Run the test suite (add tests to internal/*/**_test.go as needed).
test:
	go test ./...
