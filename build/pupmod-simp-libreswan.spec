Summary: Manages IPSec VPN Tunnels
Name: pupmod-simp-libreswan
Version: 0.7.0
Release: 0
License: Apache 2.0
Group: Applications/System
Source: %{name}-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: pupmod-iptables >= 2.0.0-0
Requires: pupmod-simplib  >= 1.0.0-0
Requires: puppet >= 3.3.0
Buildarch: noarch

Prefix: /etc/puppet/environments/simp/modules

%description
Manages IPSec service and connections

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/ipsec

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/libreswan
done

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/libreswan

%files
%defattr(0640,root,puppet,0750)
%{prefix}/libreswan

%post
#!/bin/sh

%postun
# Post uninstall stuff

%changelog
* Mon Jun 20 2016 simp - 0.6.0-0
- Change name from ipsec to libreswan.
* Fri May 20 2016 simp - 0.5.0-0
- Change name from ipsec_tunnel to ipsec.
* Fri Mar 11 2016 simp - 0.1.0-0
- Initial package.
