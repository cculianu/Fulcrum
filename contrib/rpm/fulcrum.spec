Name:       {{{ git_dir_name }}}
Version:    {{{ git_dir_version }}}
Release:    1%{?dist}
Summary:    A fast & nimble SPV server for Bitcoin Cash

License:    GPLv2+
URL:        https://someurl.org
VCS:        {{{ git_dir_vcs }}}

Source:     {{{ git_pack }}}

BuildRequires: qt5-qtbase-devel
BuildRequires: bzip2-devel
BuildRequires: zlib-devel

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

%files
%{_sysconfdir}/fulcrum.conf
%{_sbindir}/fulcrum

%changelog
{{{ git_dir_changelog }}}
