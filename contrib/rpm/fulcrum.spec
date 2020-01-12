Name:       {{{ git_dir_name }}}
Version:    {{{ git_dir_version }}}
Release:    1%{?dist}
Summary:    A fast & nimble SPV server for Bitcoin Cash

License:    GPLv3
URL:        https://github.com/cculianu/Fulcrum
VCS:        {{{ git_dir_vcs }}}

Source:     {{{ git_pack }}}

BuildRequires: qt5-qtbase-devel
BuildRequires: bzip2-devel
BuildRequires: zlib-devel

BuildRequires: systemd systemd-rpm-macros
%{?systemd_requires}

%description
%{summary}.

%prep
{{{ git_setup_macro }}}

%build
%qmake_qt5
%make_build

%install
install -Dm 640 doc/fulcrum-example-config.conf %{buildroot}/%{_sysconfdir}/fulcrum.conf
install -Dm 755 Fulcrum %{buildroot}/%{_sbindir}/fulcrum
install -Dm 644 contrib/rpm/fulcrum.service %{buildroot}/%{_unitdir}/fulcrum.service
install -dm 750 %{buildroot}/%{_sharedstatedir}/fulcrum

%post
%systemd_post fulcrum.service

%preun
%systemd_preun fulcrum.service

%postun
%systemd_postun_with_restart fulcrum.service

%files
%{_sysconfdir}/fulcrum.conf
%{_sbindir}/fulcrum
%{_sharedstatedir}/fulcrum
%{_unitdir}/fulcrum.service

%changelog
{{{ git_dir_changelog }}}
