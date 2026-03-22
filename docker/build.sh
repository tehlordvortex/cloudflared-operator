#!/bin/sh
set -euo pipefail

export CARGO_ZIGBUILD_ZIG_PATH=$(mise which zig)
RUST_TARGET="$(echo $TARGETARCH | sed s/arm64/aarch64/ | sed s/amd64/x86_64/)-unknown-linux-musl"

mkdir -p /out/static
LD_PRELOAD=/usr/lib/libmimalloc.so.2 \
  cargo zigbuild --target $RUST_TARGET --release --bin operator
cp target/$RUST_TARGET/release/operator /out/static
