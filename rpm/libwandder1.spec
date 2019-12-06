Name:           libwandder1
Version:        1.2.0
Release:        1%{?dist}
Summary:        C Library for encoding and decoding data using DER

License:        LPGLv3
URL:            https://github.com/wanduow/libwandder
Source0:        https://github.com/wanduow/libwandder/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: uthash-devel

%description
Libwandder is a helper library that can be used to perform some typical
tasks related to the encoding and decoding of data structures defined
using the ASN.1 format.

This library also includes some routines that are specifically useful for
capturing and processing records using the ETSI Lawful Intercept standards.

libwandder is developed by the WAND Network Research Group at Waikato
University, New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n libwandder-%{version}

%build
%configure --disable-static --mandir=%{_mandir}
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%{_libdir}/*.so.*

%files devel
%{_includedir}/*
%{_libdir}/*.so

%changelog
* Thu Sep 26 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.2.0-1
- Updated to 1.2.0 release of libwandder

* Tue Jun 25 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.3-1
- Updated to 1.1.3 release of libwandder

* Fri May 10 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.2-2
- Re-package for new Bintray repo architecture

* Wed Mar 20 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.2-1
- First libwandder package
