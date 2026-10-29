#!/usr/bin/env bash
# Build the browser package into pkg-<target>/ (JS glue + .wasm).
#
#   ./build.sh            # --target web: an ES module with an async init(),
#                         # suited to a lazy dynamic import()
#   ./build.sh bundler    # for bundlers that load .wasm themselves
#   ./build.sh nodejs     # for the smoke test (test/smoke.mjs)
#
# Needs: the rustup target wasm32-unknown-unknown and the rust-src component;
# clang with the wasm32 target (zstd's C encoder); wasm-bindgen-cli at the
# same version as the wasm-bindgen in Cargo.lock; binaryen's wasm-opt.
#
# The .wasm carries no build-host paths and no source file paths:
# - -Zlocation-detail=none drops file/line/column from panic locations;
# - -Zbuild-std rebuilds std with that flag too (the prebuilt std embeds its
#   own source paths), with panic_immediate_abort so panics trap without
#   formatting a message. Nothing installs a panic hook, so no message ever
#   reached JS; a panic was already a trap;
# - --remap-path-prefix rewrites anything left to neutral prefixes.
# Reproducing a build byte for byte needs the same absolute source path:
# cargo hashes the path of the kryphocron dependency (outside this
# standalone workspace) into symbol names, which decides function order.
# The -Z flags run on the stable toolchain via RUSTC_BOOTSTRAP=1, so the
# compiler stays the pinned stable release.
#
# Check: strings pkg-web/kryphocron_web_bg.wasm | grep -E "/home|\.rs|rustup|cargo"
# should print nothing.
set -euo pipefail
cd "$(dirname "$0")"
TARGET="${1:-web}"
OUT="pkg-$TARGET"

SRC_ROOT="$(cd .. && pwd)"
SYSROOT="$(rustc --print sysroot)"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Zlocation-detail=none \
  --remap-path-prefix=$CARGO_HOME=/cargo \
  --remap-path-prefix=$SYSROOT=/rust \
  --remap-path-prefix=$SRC_ROOT=/kryphocron"

cargo build --release --target wasm32-unknown-unknown --locked \
  -Zbuild-std=std,panic_abort -Zbuild-std-features=panic_immediate_abort
rm -rf "$OUT"
wasm-bindgen --target "$TARGET" --out-dir "$OUT" \
  target/wasm32-unknown-unknown/release/kryphocron_web.wasm
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  "$OUT/kryphocron_web_bg.wasm" -o "$OUT/kryphocron_web_bg.wasm"
ls -l "$OUT"
