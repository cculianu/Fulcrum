Name:    {{{ git_repo_name name="fulcrum" }}}
Version: 1.9.0
Release: {{{ git_repo_version }}}%{?dist}
Summary: A fast & nimble SPV server for Bitcoin Cash & Bitcoin BTC

License:    GPLv3
URL:        https://github.com/cculianu/Fulcrum
VCS:        {{{ git_repo_vcs }}}

Source:     {{{ GIT_DIRTY=1 git_repo_pack }}}

BuildRequires: qt5-qtbase-devel
BuildRequires: bzip2-devel
BuildRequires: zlib-devel
BuildRequires: rocksdb-devel
BuildRequires: jemalloc-devel
BuildRequires: zeromq-devel

BuildRequires: pandoc

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
{{{ git_repo_setup_macro }}}

rm -rfv staticlibs/

%build
%qmake_qt5 "LIBS+=-lrocksdb -lz -lbz2"
%make_build
pandoc --standalone --from markdown-smart --to man doc/unix-man-page.md -o fulcrum.1

%install
install -Dm 640 doc/fulcrum-example-config.conf %{buildroot}/%{_sysconfdir}/fulcrum.conf
install -Dm 755 Fulcrum %{buildroot}/%{_bindir}/fulcrum
install -Dm 644 contrib/rpm/fulcrum.service %{buildroot}/%{_unitdir}/fulcrum.service
install -dm 750 %{buildroot}/%{_sharedstatedir}/fulcrum
#doc
install -Dm 644 fulcrum.1 %{buildroot}/%{_mandir}/man1/fulcrum.1

#admin
install -Dm 755 FulcrumAdmin %{buildroot}/%{_bindir}/fulcrum-admin

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
%{_mandir}/man1/fulcrum.1*
%config(noreplace) %attr(640, root, fulcrum) %{_sysconfdir}/fulcrum.conf
%{_bindir}/fulcrum
%attr(700, fulcrum, fulcrum) %{_sharedstatedir}/fulcrum
%{_unitdir}/fulcrum.service

%files admin
%doc README.md
%license LICENSE.txt
%{_bindir}/fulcrum-admin

%changelog
{{{ git_repo_changelog }}}
