FROM rust:slim-trixie AS rust-builder

RUN apt-get update -y && \
  apt-get install -y pkg-config make g++ libssl-dev capnproto libmpfr-dev libgmp-dev

COPY fluct/Cargo.toml Cargo.lock /build/
RUN mkdir -p /build/src && echo "fn main() {}" > /build/src/main.rs
WORKDIR /build
RUN cargo build --release
COPY fluct/ /build
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update -y && \
  apt-get install -y libssl3 ca-certificates libmpfr6 libgmp10 && \
  rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/fluct /bin

USER 1000
ENTRYPOINT ["/bin/fluct"]