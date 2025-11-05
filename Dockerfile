# Build stage
FROM rust:1.83-slim as builder

WORKDIR /build

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash honeypot

# Create necessary directories
RUN mkdir -p /app /logs /config && \
    chown -R honeypot:honeypot /app /logs /config

# Copy binary from builder
COPY --from=builder /build/target/release/honeypot /app/honeypot

# Create log directory structure
RUN mkdir -p /logs/connections /logs/payloads /logs/sessions && \
    chown -R honeypot:honeypot /logs

# Switch to non-root user
USER honeypot

# Expose configurable port (default 30012)
EXPOSE 30012

# Run the honeypot
ENTRYPOINT ["/app/honeypot"]
