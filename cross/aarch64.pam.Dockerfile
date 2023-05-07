FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:main

ARG CROSS_DEB_ARCH

COPY cross/script.sh /

RUN /script.sh "$CROSS_DEB_ARCH" && rm -f /script.sh

ENV BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="$BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu -I /usr/include/aarch64-linux-gnu -I /usr/include"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-L /usr/lib/aarch64-linux-gnu -C link-args=-Wl,-rpath-link,/usr/lib/aarch64-linux-gnu $CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
