Name: haproxy
Version: 99.0.0
Release: 1
Summary: Synthetic newer HAProxy package for downgrade testing
License: GPL-2.0-or-later
BuildArch: x86_64

%description
Synthetic package used only to prove convergence to the approved HAProxy RPM.

%install
mkdir -p %{buildroot}/usr/share/doc/haproxy-newer-test
touch %{buildroot}/usr/share/doc/haproxy-newer-test/marker

%files
/usr/share/doc/haproxy-newer-test/marker
