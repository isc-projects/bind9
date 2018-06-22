##### Conditionally enabled features

%bcond_without dnstap

%if 0%{?rhel} >= 7 || 0%{?fedora} >= 14
%bcond_without python
%else
%bcond_with python
%endif

%if 0%{?rhel} >= 7 || 0%{?fedora} >= 15
%bcond_without systemd
%else
%bcond_with systemd
%endif

##### Package metadata

# 'isc-bind' package

Name:		isc-bind
Version:	9.13.1
Release:	1%{?dist}
Summary:	The Berkeley Internet Name Domain (BIND) DNS (Domain Name System) server
License:	MPL 2.0
URL:		https://www.isc.org/downloads/BIND/
BuildRequires:	docbook-style-xsl, json-c-devel, krb5-devel, libxml2-devel, libxslt, openssl-devel
Requires:	isc-bind-libs = 9.13.1
Conflicts:	bind

%if %{with dnstap}
BuildRequires: fstrm-devel protobuf-c-compiler protobuf-c-devel protobuf-compiler protobuf-devel
%endif

%if %{with systemd}
BuildRequires:	systemd
%{?systemd_requires}
%endif

%if %{with python}
%if 0%{?fedora} < 26 && 0%{?rhel} < 7
BuildRequires:	python-argparse
Requires:	python-argparse
%endif
BuildRequires:	python-ply
Requires:	python-ply
%endif

Source0:	https://ftp.isc.org/isc/bind9/%{version}/bind-%{version}.tar.gz
Source1:	named.service
Source2:	named.init
Source3:	named.sysconfig
Source4:	named.conf

%description
BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocol. BIND includes a DNS server (named),
which resolves host names to IP addresses; a resolver library
(routines for applications to use when interfacing with DNS); and
tools for verifying that the DNS server is operating properly.

# 'isc-bind-devel' package

%package devel
Summary:	Header files and libraries needed for BIND DNS development
Requires:	%{name}-libs = %{version}-%{release}
Conflicts:	bind-devel

%description devel
The isc-bind-devel package contains full version of the header files and libraries
required for development with ISC BIND 9.

# 'isc-bind-libs' package

%package libs
Summary:	Libraries used by the BIND DNS packages
Requires:	json-c, krb5-libs, libxml2, openssl
Conflicts:	bind-libs

%description libs
Contains heavyweight version of BIND suite libraries used by both named DNS
server and utilities in isc-bind-utils package.

# 'isc-bind-utils' package

%package utils
Summary:	Utilities for querying DNS name servers
Requires:	%{name}-libs = %{version}-%{release}
Conflicts:	bind-utils

%description utils
isc-bind-utils contains a collection of utilities for querying DNS (Domain
Name System) name servers to find out information about Internet
hosts. These tools will provide you with the IP addresses for given
host names, as well as other information about registered domains and
network addresses.

You should install isc-bind-utils if you need to get information from DNS name
servers.

##### Build instructions

# 'isc-bind' package

%prep
%setup -q -n bind-%{version}

%build
%configure \
	--disable-static \
	--enable-threads \
	--enable-ipv6 \
	--with-pic \
	--with-gssapi \
	--with-libjson \
	--with-libtool \
	--with-libxml2 \
	--without-lmdb \
	--with-docbook-xsl=%{_datadir}/sgml/docbook/xsl-stylesheets \
%if %{with python}
	--with-python \
%else
	--without-python \
%endif
%if %{with dnstap}
      --enable-dnstap \
%else
      --disable-dnstap \
%endif
;
make %{?_smp_mflags}
# Do not generate Bv9ARM.pdf to avoid pulling LaTeX
make -C doc/arm Bv9ARM.html notes.html

%install
make install DESTDIR=${RPM_BUILD_ROOT}

# Remove redundant files installed by "make install"
rm -f ${RPM_BUILD_ROOT}/etc/bind.keys
rm -f ${RPM_BUILD_ROOT}/%{_libdir}/*.la

# systemd unit file / init script
%if %{with systemd}
install -d ${RPM_BUILD_ROOT}%{_unitdir}
install %{SOURCE1} ${RPM_BUILD_ROOT}%{_unitdir}
%else
install -d ${RPM_BUILD_ROOT}%{_initrddir}
install %{SOURCE2} ${RPM_BUILD_ROOT}%{_initrddir}/named
%endif

# /etc files
install -d ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig
install %{SOURCE3} ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig/named
install %{SOURCE4} ${RPM_BUILD_ROOT}%{_sysconfdir}/named.conf
touch ${RPM_BUILD_ROOT}%{_sysconfdir}/rndc.key

# /var directories
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/named/data
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/run/named

%if %{with systemd}
# tmpfiles.d entry required to recreate /run/named on reboot (/tmp is a tmpfs)
install -d ${RPM_BUILD_ROOT}%{_tmpfilesdir}
echo "d /run/named 0755 named named -" > ${RPM_BUILD_ROOT}%{_tmpfilesdir}/named.conf
%endif

%files
%defattr(-,root,root,-)
%doc CHANGES README doc/arm/*.html
%{_mandir}/man5
%{_mandir}/man8
%{_sbindir}/*

%if %{with python}
%{python_sitelib}/*
%endif

%if %{with systemd}
%attr(0644,root,root) %{_unitdir}/named.service
%else
%attr(0755,root,root) %{_initrddir}/named
%endif

%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/sysconfig/named

%defattr(0640, root, named, 0750)
%config(noreplace) %{_sysconfdir}/named.conf
%ghost %config(noreplace) %{_sysconfdir}/rndc.key
%dir %{_localstatedir}/named
%defattr(0660, named, named, 0770)
%dir %{_localstatedir}/named/data
%dir %{_localstatedir}/run/named

%if %{with systemd}
%defattr(-,root,root,-)
%{_tmpfilesdir}/named.conf
%endif

# 'isc-bind-devel' package

%files devel
%defattr(-,root,root,-)
%{_bindir}/bind9-config
%{_bindir}/isc-config.sh
%{_includedir}/*
%{_mandir}/man1/bind9-config.1.*
%{_mandir}/man1/isc-config.sh.1.*

# 'isc-bind-libs' package

%files libs
%defattr(-,root,root,-)
%{_libdir}/*

# 'isc-bind-utils' package

%files utils
%defattr(-,root,root,-)
%{_bindir}/arpaname
%{_bindir}/dig
%{_bindir}/host
%{_bindir}/nslookup
%{_bindir}/nsupdate
%if %{with dnstap}
%{_bindir}/dnstap-read
%endif
%{_mandir}/man1/arpaname.1.*
%{_mandir}/man1/dig.1.*
%{_mandir}/man1/host.1.*
%{_mandir}/man1/nslookup.1.*
%{_mandir}/man1/nsupdate.1.*
%{_bindir}/delv
%{_bindir}/named-rrchecker
%{_mandir}/man1/delv.1.*
%{_mandir}/man1/named-rrchecker.1.*
%{_bindir}/mdig
%{_mandir}/man1/mdig.1.*
%if %{with dnstap}
%{_mandir}/man1/dnstap-read.1.*
%endif

##### Installation/upgrade/removal scriptlets

# 'isc-bind' package

%pre
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	groupadd -f -r named
	if ! cut -d: -f1 /etc/passwd | grep -F -x -q named; then
		useradd -c named -d /var/named -g named -r -s /sbin/nologin named
	fi
fi

%post
%if %{with systemd}
%systemd_post named.service
%else
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	chkconfig --add named
fi
%endif

if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	if [ ! -s /etc/rndc.key ] && [ ! -s /etc/rndc.conf ]; then
		if /usr/sbin/rndc-confgen -a -r /dev/urandom > /dev/null 2>&1; then
			chown root:named /etc/rndc.key
			chmod 640 /etc/rndc.key
			[ -x /sbin/restorecon ] && /sbin/restorecon /etc/rndc.key
		fi
	fi
fi

%preun
%if %{with systemd}
%systemd_preun named.service
%else
if [ "$1" -eq 0 ]; then
	# Package removal, not upgrade
	service named stop > /dev/null 2>&1 || true
	chkconfig --del named || true
fi
%endif

%postun
%if %{with systemd}
%systemd_postun_with_restart named.service
%else
if [ "$1" -eq 1 ]; then
	# Upgrade, not removal
	if service named status > /dev/null 2>&1; then
		service named restart > /dev/null 2>&1 || true
	fi
fi
%endif

# 'isc-bind-libs' package

%post libs
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	ldconfig
fi
# ldconfig is intentionally not run in %%post during an upgrade; if the newer
# version of the 'isc-bind-libs' package contains a library with the same
# interface number, but an older revision number than the library present in
# the currently installed version of this package, running ldconfig will reset
# the relevant symlink in /usr/lib64 so that it points to the library with
# highest revision number (i.e. the one installed by the version of the package
# which is about to be removed); this in turn will likely break restarting
# named upon upgrade (in %%postun for the 'isc-bind' package), because it will
# attempt to dynamically load an incorrect version of the library

%postun libs
ldconfig

##### Changelog

%changelog
* Thu Jul 13 2017 Michał Kępień <michal@isc.org>
- Initial version, tested with 9.9.10-P3, 9.10.5-P3, 9.11.1-P3 and master
