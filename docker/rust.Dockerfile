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
    mpfr-dev \
    gmp-dev \
    musl-dev \
    libmnl-dev \
    libmnl-static \
    libnftnl-dev
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source files and compile the final binary
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release

FROM gcr.io/distroless/static-debian13 AS fluct
COPY --from=builder /build/target/release/fluct /usr/local/bin/fluct
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fluct"]

FROM gcr.io/distroless/static-debian13 AS cardinal
COPY --from=builder /build/target/release/cardinal /usr/local/bin/cardinal
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cardinal"]
