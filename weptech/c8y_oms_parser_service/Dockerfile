# Enable BuildKit build options
# Builder and runtime use the same Debian release so the binary never needs
# a newer glibc than the runtime provides.
FROM rust:1.99.1-slim-trixie AS builder
WORKDIR /usr/src/c8y-oms-parser

# Copy all source files
COPY . .

# Build release binary using persistent BuildKit cache locations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/c8y-oms-parser/target \
    cargo build --release && \
    cp /usr/src/c8y-oms-parser/target/release/c8y_oms_parser_service /usr/local/bin/c8y-oms-parser

# Runtime image (no extra packages: the service uses no OpenSSL and makes
# no outbound TLS connections)
FROM debian:trixie-slim

COPY --from=builder /usr/local/bin/c8y-oms-parser /usr/local/bin/c8y-oms-parser

EXPOSE 80
CMD ["c8y-oms-parser"]