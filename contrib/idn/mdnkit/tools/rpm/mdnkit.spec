%define name mdnkit
%define version 1.2
%define disttop %{name}-%{version}-src
%define bind_version 8.2.2-P7
%define serial 2000112701

Name: %{name}
Version: %{version}
Release:  1
Copyright: distributable
Group: System Environment/Daemons
Source: %{disttop}.tar.gz
#Source10: ftp://ftp.isc.org/isc/bind/src/%{bind_version}/bind-src.tar.gz
#Source11: ftp://ftp.isc.org/isc/bind/src/%{bind_version}/bind-doc.tar.gz
#Source12: ftp://ftp.isc.org/isc/bind/src/%{bind_version}/bind-contrib.tar.gz
#NoSource: 10
#NoSource: 11
#NoSource: 12
#Patch0: dnsproxy.patch1
BuildRoot: /var/tmp/%{name}-root
Serial: %{serial}
Summary: multilingual Domain Name evaluation kit (mDNkit/JPNIC)
Vendor: JPNIC
Packager: Japan Network Information Center

%description
mDNkit is a kit for evaluating various proposed methods regarding
multilingualized/internationalized DNS.

%package devel
Group: Development/Libraries
Summary: The development files for mDNkit

%description devel
The header files and library(libmdn.a) to develop applications
that use MDN library.

%prep
%setup -n %{disttop}
#%patch0 -p0 -b .patch1

%build
if [ -f /usr/lib/libiconv.a -o -f /usr/lib/libiconv.so ]
then
  ICONV="--with-iconv=yes"
fi

CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr --sysconfdir=/etc $ICONV
make

%install
rm -fr $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/lib
mkdir -p $RPM_BUILD_ROOT/usr/include
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
make prefix=$RPM_BUILD_ROOT/usr ETCDIR=$RPM_BUILD_ROOT/etc install
# make prefix=$RPM_BUILD_ROOT/usr sysconfdir=$RPM_BUILD_ROOT/etc install

install -c -m 755 tools/rpm/dnsproxy.init $RPM_BUILD_ROOT/etc/rc.d/init.d/dnsproxy

# devel kit
#install -c lib/libmdn.a $RPM_BUILD_ROOT/usr/lib
#cp -r include/mdn $RPM_BUILD_ROOT/usr/include

# docs
mkdir rpm_docs
(cp DISTFILES README.ja README LICENSE.txt ChangeLog rpm_docs)
cp tools/mdnconv/README.ja rpm_docs/README-mdnconv.ja
cp -r patch rpm_docs

%clean
rm -fr $RPM_BUILD_ROOT

%changelog
* Mon Nov 27 2000 Makoto Ishisone <ishisone@sra.co.jp>
- 1.2 release

* Thu Nov  2 2000 MANABE Takashi <manabe@dsl.gr.jp>
- 1.1 release

* Fri Oct 27 2000 MANABE Takashi <manabe@dsl.gr.jp>
- dnsproxy.patch1
- move libmdnresolv.{la,so} from mdnkit-devel to mdnkit package

* Wed Oct 18 2000 MANABE Takashi <manabe@dsl.gr.jp>
- 1.0 release

%files
%defattr(-, root, root)
/usr/sbin/dnsproxy
/usr/bin/mdnconv
/usr/bin/runmdn
/etc/rc.d/init.d/dnsproxy
/usr/lib/libmdn.so.*
/usr/lib/libmdnresolv.so.*
/usr/lib/libmdnresolv.so
/usr/lib/libmdnresolv.la
%attr(0644, root, root) %config(noreplace) /etc/dnsproxy.conf
%attr(0644, root, root) /etc/mdnres.conf.sample
%attr(0644, root, man) /usr/man/man1/mdnconv.1
%attr(0644, root, man) /usr/man/man1/runmdn.1
%attr(0644, root, man) /usr/man/man5/mdnres.conf.5
%attr(0644, root, man) /usr/man/man8/dnsproxy.8
%doc rpm_docs/*

%files devel
%defattr(-, root, root)
/usr/lib/libmdn.a
/usr/lib/libmdn.la
/usr/lib/libmdn.so
/usr/lib/libmdnresolv.a
/usr/include/mdn/*
%doc lib/README
