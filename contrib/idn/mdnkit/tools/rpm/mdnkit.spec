%define version 2.1

# official/beta release:
%define release 1
%define distrel %{version}

# release candidate:
#define release rc1
#define distrel %{version}-%{release}

%define serial 2001052801

%define name mdnkit
%define distsrc %{name}-%{distrel}-src

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: distributable
Group: System Environment/Daemons
Source: %{distsrc}.tar.gz
#Source1: mdnsproxy.init
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
%setup -n %{distsrc}
#%patch0 -p1 -b .runmdn

%build
if [ -f /usr/lib/libiconv.a -o -f /usr/lib/libiconv.so ]
then
  if [ -f /lib/libc-2.0* ]
  then
    ICONV="--with-iconv=yes"
  fi
fi

CFLAGS="$RPM_OPT_FLAGS" ./configure \
	--prefix=/usr --sysconfdir=/etc \
	--localstatedir=/var $ICONV
make

%install
rm -fr $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/lib
mkdir -p $RPM_BUILD_ROOT/usr/include
mkdir -p $RPM_BUILD_ROOT/usr/share/mdnkit
mkdir -p $RPM_BUILD_ROOT/var/mdnsproxy
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
make prefix=$RPM_BUILD_ROOT/usr sysconfdir=$RPM_BUILD_ROOT/etc \
	localstatedir=$RPM_BUILD_ROOT/var install

mv $RPM_BUILD_ROOT/etc/mdn.conf.sample $RPM_BUILD_ROOT/etc/mdn.conf
mv $RPM_BUILD_ROOT/etc/mdnsproxy.conf.sample $RPM_BUILD_ROOT/etc/mdnsproxy.conf
install -c -m 755 tools/rpm/mdnsproxy.init $RPM_BUILD_ROOT/etc/rc.d/init.d/mdnsproxy

# devel kit
#install -c lib/libmdn.a $RPM_BUILD_ROOT/usr/lib
#cp -r include/mdn $RPM_BUILD_ROOT/usr/include

# docs
mkdir rpm_docs
(cp NEWS DISTFILES README.ja README LICENSE.txt ChangeLog rpm_docs)
cp -r patch rpm_docs

%clean
rm -fr $RPM_BUILD_ROOT

%changelog
* Mon May 28 2001 MANABE Takashi <manabe@dsl.gr.jp>
- include runmdn, libmdnresolv

* Mon Apr  4 2001 Motoyuki Kasahara <m-kasahr@sra.co.jp>
- 2.1 release

* Mon Apr  4 2001 Motoyuki Kasahara <m-kasahr@sra.co.jp>
- 2.0.1 release

* Mon Apr  2 2001 MANABE Takashi <manabe@dsl.gr.jp>
- 2.0 release

* Fri Mar  3 2001 MANABE Takashi <manabe@dsl.gr.jp>
- 1.3 release

* Mon Dec  6 2000 MANABE Takashi <manabe@dsl.gr.jp>
- add brace/lace functions to libmdnresolv(mdnkit-1.2-runmdn.patch)
- include /var/dnsproxy
- change files section for compressed man pages

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
/usr/sbin/mdnsproxy
/var/mdnsproxy
/usr/bin/mdnconv
/usr/bin/runmdn
/etc/rc.d/init.d/mdnsproxy
/usr/lib/libmdn.so.*
/usr/lib/libmdnresolv.so.*
/usr/lib/libmdnresolv.la
/usr/share/mdnkit/*
%attr(0644, root, root) %config(noreplace) /etc/mdn.conf
%attr(0644, root, root) %config(noreplace) /etc/mdnsproxy.conf
%attr(0644, root, man) /usr/man/man1/*
%attr(0644, root, man) /usr/man/man5/*
%attr(0644, root, man) /usr/man/man8/*
%doc rpm_docs/*

%files devel
%defattr(-, root, root)
/usr/lib/libmdn.a
/usr/lib/libmdn.la
/usr/lib/libmdn.so
/usr/lib/libmdnresolv.a
/usr/include/mdn/*
