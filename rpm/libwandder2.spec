Name:           libwandder2
Version:        2.0.7
Release:        1%{?dist}
Summary:        C Library for encoding and decoding data using DER

License:        LGPLv3
URL:            https://github.com/LibtraceTeam/libwandder
Source0:        https://github.com/LibtraceTeam/libwandder/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: uthash-devel
BuildRequires: openssl-devel

%description
Libwandder is a helper library that can be used to perform some typical
tasks related to the encoding and decoding of data structures defined
using the ASN.1 format.

This library also includes some routines that are specifically useful for
capturing and processing records using the ETSI Lawful Intercept standards.

libwandder was originally developed by the WAND Network Research Group at
Waikato University, New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       uthash-devel

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
* Wed Jul 19 2023 Shane Alcock <shane@alcock.co.nz> - 2.0.7-1
- Updated to 2.0.7 release of libwandder

* Wed Nov 02 2022 Shane Alcock <shane@alcock.co.nz> - 2.0.6-1
- Updated to 2.0.6 release of libwandder

* Wed Jun 29 2022 Shane Alcock <salcock@waikato.ac.nz> - 2.0.5-1
- Updated to 2.0.5 release of libwandder

* Wed Jan 05 2022 Shane Alcock <salcock@waikato.ac.nz> - 2.0.4-1
- Updated to 2.0.4 release of libwandder

* Wed Mar 03 2021 Shane Alcock <salcock@waikato.ac.nz> - 2.0.3-1
- Updated to 2.0.3 release of libwandder

* Fri Jan 22 2021 Shane Alcock <salcock@waikato.ac.nz> - 2.0.2-1
- Updated to 2.0.2 release of libwandder

* Tue Nov 10 2020 Shane Alcock <salcock@waikato.ac.nz> - 2.0.1-1
- Updated to 2.0.1 release of libwandder

* Sat May 09 2020 Shane Alcock <salcock@waikato.ac.nz> - 2.0.0-1
- Bump version to 2.0.0 to properly reflect API changes

* Fri May 08 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.3.0-2
- Fix uthash dependency in 1.3.0-1 release

* Fri May 08 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.3.0-1
- Updated to 1.3.0 release of libwandder

* Thu Sep 26 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.2.0-1
- Updated to 1.2.0 release of libwandder

* Tue Jun 25 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.3-1
- Updated to 1.1.3 release of libwandder

* Fri May 10 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.2-2
- Re-package for new Bintray repo architecture

* Wed Mar 20 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.1.2-1
- First libwandder package
