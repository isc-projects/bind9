FROM centos:latest
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN yum -y upgrade
RUN yum -y install epel-release
RUN yum -y install		\
	'autoconf'		\
	'automake'		\
	'bison'			\
	'libtool'		\
	'lmdb-devel'		\
	'pkgconfig'		\
	'pkgconfig(openssl)'	\
	'pkgconfig(jansson)'	\
	'pkgconfig(libcap2)'	\
	'openldap-devel'	\
	'krb5-devel'		\
	'pkgconfig(libxml-2.0)'
