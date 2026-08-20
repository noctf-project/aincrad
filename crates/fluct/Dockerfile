FROM rust:alpine AS builder

RUN apk add --no-cache \
    pkgconfig \
    make \
    g++ \
    openssl-dev \
    openssl-libs-static \
    capnproto \
    capnproto-dev \
    mpfr-dev \
    mpfr-static \
    gmp-dev \
    musl-dev

ENV RUSTFLAGS="-C target-feature=+crt-static"

WORKDIR /build

# Copy root manifest and workspace member manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml ./crates/

# Inject dummy source files (both main.rs and lib.rs) for all workspace crates
RUN for dir in crates/*; do \
      mkdir -p "$dir/src" && \
      echo "fn main() {}" > "$dir/src/main.rs" && \
      touch "$dir/src/lib.rs"; \
    done

RUN cargo build --release -p fluct

COPY crates/ ./crates/
RUN touch crates/*/src/*.rs 2>/dev/null || true

RUN cargo build --release -p fluct

FROM alpine:latest
RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/fluct /bin/fluct

USER 1000
ENTRYPOINT ["/bin/fluct"]