# Harborlight Stage 2 pilot image: the four harborlight-* binaries plus an
# unmodified transparency-dev/witness omniwitness, built from source at
# pinned versions. Base images are pinned by digest (looked up 2026-11-25).
#
# The witness is in the same image only for the local demo. In the demo it
# runs on the operator's host, so it demonstrates the protocol and gives no
# independence; every report says so.

FROM golang:1.26.11-bookworm@sha256:ea47ee45f1284d60f9cc09cb2c3bb4f508c256b640bd8bb30342ff13d1adcb52 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -trimpath -o /out/ ./cmd/harborlight-log ./cmd/harborlight-verify ./cmd/harborlight-cf-adapter ./cmd/harborlight-adversarial
# The module version is checked against the Go checksum database.
ARG WITNESS_VERSION=v0.0.0-20261125093440-4aa9dadc1f0b
RUN cd / && GOBIN=/out go install -trimpath \
      github.com/transparency-dev/witness/cmd/omniwitness@${WITNESS_VERSION} \
      github.com/transparency-dev/witness/cmd/generate_keys@${WITNESS_VERSION}
# Volume mount points owned by the distroless nonroot user, so named
# volumes start out writable by it.
RUN mkdir -p /rootfs/keys /rootfs/data /rootfs/public /rootfs/feed /rootfs/witness /rootfs/out \
 && chown -R 65532:65532 /rootfs

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
