# Stage 1: Build the Rust binary
FROM rust:1.80-slim AS builder

# Install build dependencies (pkg-config, ssl, and standard build tools)
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential

WORKDIR /usr/src/app

# Copy the entire workspace into the builder
COPY . .

# Build the release binary specifically for the 'api' crate
RUN cargo build --release -p api

# Stage 2: Create a minimal, lightweight runtime image
FROM debian:bookworm-slim

# Install runtime dependencies (like CA certificates for making secure HTTPS requests)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/api /usr/local/bin/open-engine

# Expose the API port your app binds to (0.0.0.0:3001)
EXPOSE 3001

# Set the command to run your engine
CMD ["open-engine"]
