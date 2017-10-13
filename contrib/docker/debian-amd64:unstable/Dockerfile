FROM debian:unstable
MAINTAINER BIND 9 Developers <bind9-dev@isc.org>
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt-get -y dist-upgrade
RUN apt-get -y install	\
	autoconf	\
	automake	\
	autotools-dev	\
	bash-completion	\
	bison		\
	build-essential	\
	git		\
	libcap2-dev	\
	libdb-dev	\
	libgeoip-dev	\
	libkrb5-dev	\
	libldap2-dev	\
	liblmdb-dev	\
	libtool		\
	libssl-dev	\
	libxml2-dev	\
	pkg-config
RUN apt-get -y install \
	net-tools
