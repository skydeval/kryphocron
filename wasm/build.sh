#!/usr/bin/env bash
# Build the browser package into pkg-<target>/ (JS glue + .wasm).
#
#   ./build.sh            # --target web: an ES module with an async init(),
#                         # suited to a lazy dynamic import()
#   ./build.sh bundler    # for bundlers that load .wasm themselves
#   ./build.sh nodejs     # for the smoke test (test/smoke.mjs)
#
# Needs: the rustup target wasm32-unknown-unknown; clang with the wasm32
# target (zstd's C encoder); wasm-bindgen-cli at the same version as the
# wasm-bindgen in Cargo.lock; binaryen's wasm-opt.
set -euo pipefail
cd "$(dirname "$0")"
TARGET="${1:-web}"
OUT="pkg-$TARGET"

cargo build --release --target wasm32-unknown-unknown --locked
rm -rf "$OUT"
wasm-bindgen --target "$TARGET" --out-dir "$OUT" \
  target/wasm32-unknown-unknown/release/kryphocron_web.wasm
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  "$OUT/kryphocron_web_bg.wasm" -o "$OUT/kryphocron_web_bg.wasm"
ls -l "$OUT"
