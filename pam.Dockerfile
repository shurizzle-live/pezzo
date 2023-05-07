ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

ARG CROSS_DEB_ARCH

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN dpkg --add-architecture $CROSS_DEB_ARCH
RUN apt-get update && apt-get -y install libpam0g-dev:$CROSS_DEB_ARCH && apt-get install -y --no-install-recommends libclang-10-dev clang-10

ENV BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="$BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu -I /usr/include/aarch64-linux-gnu -I /usr/include"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-L /usr/lib/aarch64-linux-gnu -C link-args=-Wl,-rpath-link,/usr/lib/aarch64-linux-gnu $CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
