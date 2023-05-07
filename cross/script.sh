#!/bin/sh

CROSS_DEB_ARCH="$1"

set -eux

apt-get update
apt-get install -y --no-install-recommends apt-utils
dpkg --add-architecture $CROSS_DEB_ARCH
apt-get update
apt-get -y install libpam0g-dev:$CROSS_DEB_ARCH
apt-get install -y --no-install-recommends libclang-10-dev clang-10
