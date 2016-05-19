Summary: Manages IPSec VPN Tunnels
Name: pupmod-ipsec_tunnel
Version: 0.5.0
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
Manages IPSec VPN Tunnels

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/ipsec_tunnel

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/ipsec_tunnel
done

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/ipsec_tunnel

%files
%defattr(0640,root,puppet,0750)
%{prefix}/ipsec_tunnel

%post
#!/bin/sh

%postun
# Post uninstall stuff

%changelog
* Fri Mar 11 2016 simp - 0.1.0-0
- Initial package.
