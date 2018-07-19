#!/bin/sh

set -ex

export CC=hfuzz-clang
export CXX=hfuzz-clang++
export CFLAGS="-fsanitize=address,undefined -Wno-shift-negative-value -Wno-logical-not-parentheses -g -ggdb -O0"
./configure \
		--prefix=/opt/bind-9.11.4/ \
		--enable-threads \
		--without-gssapi \
		--disable-chroot \
		--disable-linux-caps \
		--disable-seccomp \
		--with-libtool \
		--enable-ipv6 \
		--enable-atomic \
		--enable-epoll \
		--enable-afl \
		--disable-crypto-rand \
		--disable-backtrace \
		--with-openssl=yes

make clean
make -j$(nproc)
