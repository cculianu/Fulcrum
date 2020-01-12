Name:       fulcrum
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
install -Dm 644 contrib/rpm/fulcrum.service %{buildroot}/%{_unitdir}
install -dm 750 %{buildroot}/%{_sharedstatedir}/%{name}

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%{_sysconfdir}/fulcrum.conf
%{_sbindir}/fulcrum
%{_sharedstatedir}/%{name}

%changelog
{{{ git_dir_changelog }}}
