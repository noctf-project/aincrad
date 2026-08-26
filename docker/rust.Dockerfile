# Prepare recipe using only manifests and crates
FROM lukemathwalker/cargo-chef:latest-rust-alpine3.24 AS planner
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo chef prepare --recipe-path /build/recipe.json

FROM lukemathwalker/cargo-chef:latest-rust-alpine3.24 AS builder
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
RUN apk add --no-cache \
    pkgconfig \
    make \
    g++ \
    m4 \
    perl \
    diffutils \
    capnproto \
    capnproto-dev \
    mpfr-dev \
    gmp-dev \
    musl-dev
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source files and compile the final binary
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release

# runtime image
FROM alpine:3 AS fluct
RUN apk add --no-cache nftables libcap
COPY --from=builder /build/target/release/fluct /usr/local/bin/fluct
ENTRYPOINT ["/usr/local/bin/fluct"]

FROM alpine:3 AS cardinal
COPY --from=builder /build/target/release/cardinal /usr/local/bin/cardinal
ENTRYPOINT ["/usr/local/bin/cardinal"]