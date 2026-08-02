Name: alloy
Version: 99.0.0
Release: 1
Summary: Synthetic newer Alloy package for downgrade testing
License: Apache-2.0
BuildArch: x86_64

%description
Synthetic package used only to prove convergence back to the approved Alloy RPM.

%install
mkdir -p %{buildroot}/usr/share/doc/alloy-newer-test
touch %{buildroot}/usr/share/doc/alloy-newer-test/marker

%files
/usr/share/doc/alloy-newer-test/marker
