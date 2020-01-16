Name:    {{{ git_name name="fulcrum" }}}
Version: 1.0
Release: {{{ git_version }}}%{?dist}
Summary: A fast & nimble SPV server for Bitcoin Cash

License:    GPLv3
URL:        https://github.com/cculianu/Fulcrum
VCS:        {{{ git_vcs }}}

Source:     {{{ git_pack }}}

BuildRequires: qt5-qtbase-devel
BuildRequires: bzip2-devel
BuildRequires: zlib-devel

Obsoletes:     Fulcrum-contrib-rpm

Requires(pre): shadow-utils

BuildRequires: systemd systemd-rpm-macros
%{?systemd_requires}

%description
%{summary}.

%package admin
Summary: Includes admin tool for fulcrum

%description admin
%{summary}.

%prep
{{{ git_setup_macro }}}

%build
%qmake_qt5
%make_build

%install
install -Dm 640 doc/fulcrum-example-config.conf %{buildroot}/%{_sysconfdir}/fulcrum.conf
install -Dm 755 Fulcrum %{buildroot}/%{_bindir}/fulcrum
install -Dm 644 contrib/rpm/fulcrum.service %{buildroot}/%{_unitdir}/fulcrum.service
install -dm 750 %{buildroot}/%{_sharedstatedir}/fulcrum

#admin
install -Dm 755 FulcrumAdmin %{buildroot}/%{_bindir}/fulcrumctl

%pre
getent group fulcrum >/dev/null || groupadd -r fulcrum
getent passwd fulcrum >/dev/null || \
    useradd -r -g fulcrum -d %{_sharedstatedir}/fulcrum -s /sbin/nologin \
    -c "Fulcrum SPV server for Bitcoin Cash" fulcrum
exit 0

%post
%systemd_post fulcrum.service

%preun
%systemd_preun fulcrum.service

%postun
%systemd_postun_with_restart fulcrum.service

%files
%doc README.md
%license LICENSE.txt
%config %attr(640, root, fulcrum) %{_sysconfdir}/fulcrum.conf
%{_bindir}/fulcrum
%attr(700, fulcrum, fulcrum) %{_sharedstatedir}/fulcrum
%{_unitdir}/fulcrum.service

%files admin
%doc README.md
%license LICENSE.txt
%{_bindir}/fulcrumctl

%changelog
{{{ git_changelog }}}
