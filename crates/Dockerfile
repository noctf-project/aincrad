FROM lukemathwalker/cargo-chef:latest-rust-alpine3.24 AS chef
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
    libmnl-dev \
    libmnl-static \
    libnftnl-dev \
    gmp-dev \
    musl-dev
WORKDIR /build

# Prepare recipe using only manifests and crates
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo chef prepare --recipe-path recipe.json

# Build and cache third-party and workspace dependencies
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source files and compile the final binary
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release -p fluct

# runtime image
FROM gcr.io/distroless/static-debian13
COPY --from=builder /build/target/release/fluct /bin/fluct
USER nonroot:nonroot
ENTRYPOINT ["/bin/fluct"]