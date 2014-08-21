%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

%define _unpackaged_files_terminate_build 0

Name:		redcurrant
Version:	1.9
Release:	1
%define		tarversion %{version}

Summary:	Redcurrant cloud storage solution
Group:		Redcurrant
License:	AGPL3, GNU Affero General Public License v3.0
URL:		http://www.redcurrent.io/sources/redcurrant-${version}.tar.gz
Source0:	%{name}-%{tarversion}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

%define prefix	/usr
%define libdir	%{prefix}/%{_lib}

BuildRequires:	compat-glib2-devel = 2.28.8
BuildRequires:	openssl-devel >= 0.9.8
BuildRequires:  libzookeeper >= 3.3.4
BuildRequires:  libzookeeper-devel >= 3.3.4
%if %{?el6}0
BuildRequires:	neon-devel >= 0.29
BuildRequires:	python-devel
#BuildRequires:  mysql-devel
BuildRequires:  zeromq3, zeromq3-devel
BuildRequires:	libcurl-devel
%else
BuildRequires:	compat-neon-029-devel >= 0.29
BuildRequires:	python26-devel
BuildRequires:  zeromq, zeromq-devel
BuildRequires:	compat-libcurl-devel
%endif
BuildRequires:	apr-devel >= 1.2
BuildRequires:	sqlite-devel >= 3.7.11
BuildRequires:	libattr-devel >= 2.4.32
#BuildRequires:	pcre-devel
BuildRequires:	compat-libevent-20-devel >= 2.0
BuildRequires:	httpd-devel >= 2.2
BuildRequires:	lzo-devel >= 2.0
BuildRequires:	gamin-devel
BuildRequires:	grid-init-utils
BuildRequires:	net-snmp-devel
BuildRequires:	perl-Template-Toolkit,perl-AppConfig,perl-File-HomeDir
BuildRequires:	asn1c
BuildRequires:	cmake,bison,flex
BuildRequires:	dbus,dbus-devel,dbus-glib-devel,dbus-glib
BuildRequires:	librain-devel
BuildRequires:	json-c, json-c-devel
BuildRequires:	librdkafka1, librdkafka-devel

%description
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.


%package common
License: LGPL3, GNU Lesser General Public License v3.0
Summary: common files for Redcurrant cloud solution
Group: Redcurrant
Requires:	compat-glib2 >= 2.28
Requires:	asn1c >= 0.9.21
Requires:	openssl >= 0.9.8
Requires:	zlib,expat
Requires:       libzookeeper >= 3.3.4
%description common
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains common files used by other Redcurrant packages.


%package server
Summary: Server files for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-common = %{version}
Requires:       libzookeeper >= 3.3.4
Requires:       python-zookeeper
%if %{?el6}0
Requires:	neon >= 0.29
Requires:	python >= 2.6
%else
Requires:	compat-neon-029 >= 0.29
Requires:	python26 >= 2.6
%endif
Requires:	apr >= 1.2
Requires:	sqlite >= 3.7.11
Requires:	libattr >= 2.4.32
#Requires:	pcre
Requires:	compat-libevent-20 >= 2.0
Requires:	lzo >= 2.0
Requires:	grid-init-utils
Requires:	asn1c >= 0.9.21
Requires:	librdkafka1
%description server
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains all needed server files to run Redcurrant storage
solution.


%package client
License: LGPL3, GNU Lesser General Public License v3.0
Summary: Client files for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-common = %{version}
%if %{?el6}0
Requires:	neon >= 0.29
%else
Requires:	compat-neon-029 >= 0.29
%endif
%description client
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains client files for Redcurrant storage solution.


%package client-devel
License: LGPL3, GNU Lesser General Public License v3.0
Summary: Header files for Redcurrant cloud solution client
Group: Redcurrant
Requires:	%{name}-client = %{version}
%description client-devel
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains header files for Redcurrant cloud solution client.


%package mod-snmp
Summary: Net-SNMP module for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-server = %{version}
Requires:	net-snmp
%description mod-snmp
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains Net-SNMP module for Redcurrant cloud storage solution.


%package mod-httpd
Summary: Apache HTTPd module for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-server = %{version}
Requires:	httpd >= 2.2
%description mod-httpd
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains Apache HTTPd module for Redcurrant cloud storage solution.


%package mod-httpd-rainx
Summary: Apache HTTPd module for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-server = %{version}
Requires:	httpd >= 2.2
Requires:       librain
%description mod-httpd-rainx
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains Apache HTTPd module for Redcurrant cloud storage solution.



%package integrityloop
Summary: Integrity Loop for Redcurrant cloud solution
Group: Redcurrant
Requires:	%{name}-server = %{version}
Requires:	dbus-glib, dbus
Requires:       json-c
%if %{?el6}0
Requires:       libcurl
Requires:       zeromq3
%else
Requires:       compat-libcurl
Requires:       zeromq
%endif
%description integrityloop
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains integrity loop files for Redcurrant cloud storage
solution.


%prep
%setup -q -n %{name}-%{tarversion}
%if %{?el5}0
# Fix Python to python26 for CentOS5
%{__grep} -ril '/usr/bin/python$' . | /bin/sort -u | /usr/bin/xargs %{__sed} -i -e 's@/usr/bin/python$@/usr/bin/python26@'
%{__sed} -i -e 's@COMMAND python@COMMAND python26@' ./meta2v2/CMakeLists.txt
%endif


%build
cmake \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPREFIX=%{prefix} \
	-DEXE_PREFIX=redc \
	-DZK_LIBDIR=%{_libdir} \
	-DZK_INCDIR=/usr/include/zookeeper \
	-DLZO_INCDIR=%{_includedir}/lzo \
	-DMOCKS=1 \
	-DSOCKET_OPTIMIZED=1 \
	.

# Ugly fix, waiting to commit
sed -i -e 's@-llog4c@@' integrity/tools/CMakeLists.txt

make %{?_smp_mflags}

# Build python
(cd rules-motor/lib/python && %{__python}2.6 ./setup.py build)
(cd crawler/listener       && %{__python}2.6 ./setup.py build)


%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

# Install python
(cd rules-motor/lib/python; %{__python}2.6 ./setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT)

# Install /etc/ld.so.conf.d/grid file
mkdir -pv ${RPM_BUILD_ROOT}/etc/ld.so.conf.d
echo "%{libdir}" >${RPM_BUILD_ROOT}/etc/ld.so.conf.d/grid.conf

# Install et create configuration file
%{__mkdir_p} ${RPM_BUILD_ROOT}/etc/gridstorage.conf.d
%{__install} -m 644 cluster/gridstorage.conf ${RPM_BUILD_ROOT}/etc/gridstorage.conf

# Install default gridagent config files
%{__mkdir_p} ${RPM_BUILD_ROOT}/GRID/common/{conf,run,spool,init,logs}
%{__install} -m 644 cluster/gridagent.conf.default ${RPM_BUILD_ROOT}/GRID/common/conf/gridagent.conf
%{__install} -m 644 cluster/gridagent.log4crc.default ${RPM_BUILD_ROOT}/GRID/common/conf/gridagent.log4crc

# Install metacd default config files
%{__install} -m 644 client/c/metacd_module/metacd.{conf,log4crc} ${RPM_BUILD_ROOT}/GRID/common/conf/

# Create home directory for admgrid
%{__mkdir_p} ${RPM_BUILD_ROOT}/home/admgrid
 
# Install dbus config for crawler
%{__mkdir_p} ${RPM_BUILD_ROOT}/etc/dbus-1/system.d
%{__install} -m 644 crawler/atos.grid.Crawler.conf ${RPM_BUILD_ROOT}/etc/dbus-1/system.d/


%clean
rm -rf $RPM_BUILD_ROOT


%files common
%defattr(-,root,root,-)
/etc/ld.so.conf.d/grid.conf
%defattr(755,root,root,-)
%{libdir}/libgridclient.so*
%{libdir}/libsolrutils.so
%{libdir}/libgridcluster-conscience.so*
%{libdir}/libgridcluster-events.so*
%{libdir}/libgridcluster.so*
%{libdir}/libgridcluster-eventsremote.so*
%{libdir}/libgridcluster-remote.so*
%{libdir}/libhcresolve.so*
%{libdir}/libmeta0utils.so*
%{libdir}/libmetacomm.so*
%{libdir}/libmetautils.so*
%{libdir}/libmeta0remote.so*
%{libdir}/libmeta1remote.so*
%{libdir}/libmeta2remote.so*
%{libdir}/libmeta2v2remote.so*
%{libdir}/libmeta2servicesremote.so*
# TODO find why libserver is necessary in common
%{libdir}/libserver.so*
# TODO find why libsqliterepo is necessary in common
%{libdir}/libsqliterepo.so*
%{libdir}/libsqlitereporemote.so*
%{libdir}/libsqlxsrv.so*
%{libdir}/libmeta2v2lbutils.so*
%{libdir}/libmeta2v2utils.so*
%{libdir}/libsqliteutils.so*
%{libdir}/libvnsagentremote.so*
%{libdir}/librawxclient.so*
%{libdir}/libstatsclient.so*
%{prefix}/bin/gridd
%{prefix}/bin/redc-admin
%{prefix}/bin/redc-dir

%files server
%defattr(-,root,root,-)
%config(noreplace) /etc/gridstorage.conf
%dir %attr(755,admgrid,admgrid) /etc/gridstorage.conf.d
%dir %attr(755,admgrid,admgrid) /GRID
%config(noreplace) /GRID/common/conf/gridagent.conf
%config(noreplace) /GRID/common/conf/gridagent.log4crc
%dir %attr(755,admgrid,admgrid) /home/admgrid
%defattr(755,root,root,-)
%{libdir}/grid/acl.so*
%{libdir}/grid/msg_conscience.so*
#%{libdir}/grid/msg_event_service.so*
%{libdir}/grid/msg_fallback.so*
%{libdir}/grid/msg_ping.so*
%{libdir}/grid/msg_stats.so*
%{libdir}/grid/msg_vns_agent.so*
%{libdir}/grid/msg_polix.so
%{libdir}/libgridpolix.so*
%{libdir}/libmeta0v2.so*
%{libdir}/libmeta1v2.so*
%{libdir}/libmeta2v2.so*
%{libdir}/libmeta2mover.so*
%{libdir}/librawx.so*
%{libdir}/librulesmotorc2py.so*
%{libdir}/librulesmotorpy2c.so*
%{libdir}/libvns_agent.so*
%{prefix}/bin/meta0_init
%{prefix}/bin/meta0_client
%{prefix}/bin/meta0_server
%{prefix}/bin/meta1_server
%{prefix}/bin/meta2_server
%{prefix}/bin/meta2_client
%{prefix}/bin/sqlx_server
%{prefix}/bin/meta1_client
%{prefix}/bin/gridagent
%{prefix}/bin/redc-cluster
%{prefix}/bin/redc-cluster-register 
%{prefix}/bin/redc-dump-event
%{prefix}/bin/redc-gridc-ping
%{prefix}/bin/redc-gridc-stats
%{prefix}/bin/redc-break
%{prefix}/bin/redc-oid2cid
%{prefix}/bin/redc-m1hash
%{prefix}/bin/redc-path2container
%{prefix}/bin/redc-dump-addr
%{prefix}/bin/redc-sqlx
%{prefix}/bin/redc-rawx-compress
%{prefix}/bin/redc-rawx-uncompress
%{prefix}/bin/redc-rawx-monitor
%{prefix}/bin/redc-svc-monitor
%{prefix}/bin/zk-bootstrap.py*
%{prefix}/bin/redis-monitor.py*
%{prefix}/bin/rainx-monitor.py*
%if %{?el6}0
%{python_sitelib}/pymotor
%{python_sitelib}/python_rules_motor*-py2.6.egg-info
%else
/usr/lib/python2.6/site-packages/pymotor
/usr/lib/python2.6/site-packages/python_rules_motor*-py2.6.egg-info
%endif

%files client
%defattr(755,root,root,-)
%{prefix}/bin/redc
%{libdir}/grid/metacd_module.so*
%config(noreplace) %verify(not md5 size mtime) /GRID/common/conf/metacd.conf
%config(noreplace) %verify(not md5 size mtime) /GRID/common/conf/metacd.log4crc

%files client-devel
%defattr(-,root,root,-)
%{prefix}/include/rawx-lib/src/rawx.h
%{prefix}/include/rawx-lib/src/compression.h
%{prefix}/include/rawx-client/lib/rawx_client.h
%{prefix}/include/meta2v2/meta2v2_remote.h
%{prefix}/include/meta2v2/meta2_utils_lb.h
%{prefix}/include/meta2v2/meta2_utils.h
%{prefix}/include/meta2v2/meta2_test_common.h
%{prefix}/include/meta2v2/meta2_macros.h
%{prefix}/include/meta2v2/meta2_gridd_dispatcher.h
%{prefix}/include/meta2v2/meta2_filters.h
%{prefix}/include/meta2v2/meta2_filter_context.h
%{prefix}/include/meta2v2/meta2_dedup_utils.h
%{prefix}/include/meta2v2/meta2_events.h
%{prefix}/include/meta2v2/meta2_bean.h
%{prefix}/include/meta2v2/meta2_backend_internals.h
%{prefix}/include/meta2v2/meta2_backend.h
%{prefix}/include/meta2v2/meta2_backend_dbconvert.h
%{prefix}/include/meta2v2/generic.h
%{prefix}/include/meta2v2/autogen.h
%{prefix}/include/grid_client.h
%{prefix}/include/grid_client_shortcuts.h
%{prefix}/include/resolver/hc_resolver.h
%{prefix}/include/meta1v2/meta1_remote.h
%{prefix}/include/meta1v2/meta1_prefixes.h
%{prefix}/include/meta1v2/meta1_gridd_dispatcher.h
%{prefix}/include/meta1v2/meta1_backend.h
%{prefix}/include/meta0v2/meta0_utils.h
%{prefix}/include/meta0v2/meta0_remote.h
%{prefix}/include/meta0v2/meta0_prefixassign.h
%{prefix}/include/meta0v2/meta0_gridd_dispatcher.h
%{prefix}/include/meta0v2/meta0_backend.h
%{prefix}/include/gridd/main/srvtimer.h
%{prefix}/include/gridd/main/srvstats.h
%{prefix}/include/gridd/main/srvalert.h
%{prefix}/include/gridd/main/plugin_holder.h
%{prefix}/include/gridd/main/plugin.h
%{prefix}/include/gridd/main/message_handler.h
%{prefix}/include/meta2/remote/meta2_services_remote.h
%{prefix}/include/meta2/remote/meta2_remote.h
%{prefix}/include/cluster/agent/task.h
%{prefix}/include/cluster/agent/gridagent.h
%{prefix}/include/cluster/agent/agent.h
%{prefix}/include/cluster/conscience/conscience_broken_holder_common.h
%{prefix}/include/cluster/conscience/conscience_broken_holder.h
%{prefix}/include/cluster/conscience/conscience_srvtype.h
%{prefix}/include/cluster/conscience/conscience_srv.h
%{prefix}/include/cluster/conscience/conscience.h
%{prefix}/include/cluster/lib/gridcluster.h
%{prefix}/include/cluster/events/gridcluster_eventsremote.h
%{prefix}/include/cluster/events/gridcluster_eventhandler.h
%{prefix}/include/cluster/events/gridcluster_events.h
%{prefix}/include/sqliterepo/zk_manager.h
%{prefix}/include/sqliterepo/version.h
%{prefix}/include/sqliterepo/upgrade.h
%{prefix}/include/sqliterepo/sqlx_remote.h
%{prefix}/include/sqliterepo/sqlite_utils.h
%{prefix}/include/sqliterepo/sqliterepo.h
%{prefix}/include/sqliterepo/replication_dispatcher.h
%{prefix}/include/sqliterepo/hash.h
%{prefix}/include/sqliterepo/election.h
%{prefix}/include/sqliterepo/cache.h
%{prefix}/include/server/transport_http.h
%{prefix}/include/server/transport_gridd.h
%{prefix}/include/server/slab.h
%{prefix}/include/server/network_server.h
%{prefix}/include/server/gridd_dispatcher_filters.h
%{prefix}/include/server/grid_daemon.h
%{prefix}/include/metautils/lib/volume_lock.h
%{prefix}/include/metautils/lib/tree.h
%{prefix}/include/metautils/lib/test_addr.h
%{prefix}/include/metautils/lib/storage_policy.h
%{prefix}/include/metautils/lib/metautils_task.h
%{prefix}/include/metautils/lib/metautils_svc_policy.h
%{prefix}/include/metautils/lib/metautils_strings.h
%{prefix}/include/metautils/lib/metautils_sockets.h
%{prefix}/include/metautils/lib/metautils_resolv.h
%{prefix}/include/metautils/lib/metautils_manifest.h
%{prefix}/include/metautils/lib/metautils_macros.h
%{prefix}/include/metautils/lib/metautils_loggers.h
%{prefix}/include/metautils/lib/metautils_l4v.h
%{prefix}/include/metautils/lib/metautils_internals.h
%{prefix}/include/metautils/lib/metautils_hashstr.h
%{prefix}/include/metautils/lib/metautils.h
%{prefix}/include/metautils/lib/metautils_gba.h
%{prefix}/include/metautils/lib/metautils_errors.h
%{prefix}/include/metautils/lib/metautils-doc.h
%{prefix}/include/metautils/lib/metautils_containers.h
%{prefix}/include/metautils/lib/metautils_bits.h
%{prefix}/include/metautils/lib/metatype_v140.h
%{prefix}/include/metautils/lib/metatype_srvinfo.h
%{prefix}/include/metautils/lib/metatypes.h
%{prefix}/include/metautils/lib/metatype_nsinfo.h
%{prefix}/include/metautils/lib/metatype_metadata.h
%{prefix}/include/metautils/lib/metatype_m1url.h
%{prefix}/include/metautils/lib/metatype_m0info.h
%{prefix}/include/metautils/lib/metatype_kv.h
%{prefix}/include/metautils/lib/metatype_cid.h
%{prefix}/include/metautils/lib/metatype_addrinfo.h
%{prefix}/include/metautils/lib/metatype_acl.h
%{prefix}/include/metautils/lib/event_config.h
%{prefix}/include/metautils/lib/metacomm.h
%{prefix}/include/metautils/lib/lrutree.h
%{prefix}/include/metautils/lib/lb.h
%{prefix}/include/metautils/lib/hc_url.h
%{prefix}/include/metautils/lib/grid_storage_client_stat.h
%{prefix}/include/metautils/lib/gridd_client_pool.h
%{prefix}/include/metautils/lib/gridd_client.h
%{prefix}/include/metautils/lib/expr.h
%{prefix}/include/metautils/lib/common_main.h
%{prefix}/include/metautils/lib/asn_ServiceInfo.h
%{prefix}/include/metautils/lib/asn_Score.h
%{prefix}/include/metautils/lib/asn_PathInfo.h
%{prefix}/include/metautils/lib/asn_Parameter.h
%{prefix}/include/metautils/lib/asn_NamespaceInfo.h
%{prefix}/include/metautils/lib/asn_Meta2Raw.h
%{prefix}/include/metautils/lib/asn_Meta0Info.h
%{prefix}/include/metautils/lib/asn_ContainerInfo.h
%{prefix}/include/metautils/lib/asn_ContainerEvent.h
%{prefix}/include/metautils/lib/asn_ChunkInfo.h
%{prefix}/include/metautils/lib/asn_AddrInfo.h


%files mod-snmp
%defattr(755,root,root,-)
%{libdir}/snmp/grid_storage.so*

%files mod-httpd
%defattr(755,root,root,-)
%{_libdir}/httpd/modules/mod_dav_rawx.so*

%files mod-httpd-rainx
%defattr(755,root,root,-)
%{_libdir}/httpd/modules/mod_dav_rainx.so*

%files integrityloop
%defattr(755,root,root,-)
/etc/dbus-1/system.d/atos.grid.Crawler.conf
%{libdir}/libintegrity.so*
%{libdir}/liblistenerremote.so*
%{libdir}/libtransp_layer.so*
%{libdir}/grid/libtrip_chunk.so
%{libdir}/grid/libtrip_container.so
%{libdir}/grid/libtrip_content.so
%{libdir}/grid/libtrip_prefix.so
%{libdir}/grid/libtrip_sqlx.so
%{prefix}/bin/action_dedup_container_service
%{prefix}/bin/action_purge_container_service
%{prefix}/bin/action_rules_motor_service
%{prefix}/bin/action_integrity_service
%{prefix}/bin/action_list_container_service
%{prefix}/bin/redc-crawler
%{prefix}/bin/redc-crawler-cmd
%{prefix}/bin/redc-chunk-crawler
%{prefix}/bin/redc-rawx-mover
%{prefix}/bin/redc-rebuild
%{prefix}/bin/redc-rawx-list
%{prefix}/bin/redc-meta2-mover
%{prefix}/bin/redc-policycheck
%{prefix}/bin/redc-meta2-crawler


%pre server
# Add user and group "admgrid" if not exist
if ! grep -q "^admgrid" /etc/group ; then
	echo "Adding group admgrid"
	groupadd -g 220 admgrid >/dev/null 2>&1
fi
if ! id admgrid >/dev/null 2>/dev/null ; then
	echo "Adding user admgrid"
	useradd -d /home/admgrid -s /bin/bash -u 120 -g admgrid admgrid >/dev/null 2>&1
fi

%post common
/sbin/ldconfig
%post server
/sbin/ldconfig
%post client
/sbin/ldconfig
%post mod-snmp
/sbin/ldconfig
%post mod-httpd
/sbin/ldconfig
%post mod-httpd-rainx
/sbin/ldconfig
%post integrityloop
/sbin/ldconfig

%postun common
/sbin/ldconfig
%postun server
/sbin/ldconfig
%postun client
/sbin/ldconfig
%postun mod-snmp
/sbin/ldconfig
%postun mod-httpd
/sbin/ldconfig
%postun integrityloop
/sbin/ldconfig

%changelog
* Mon Aug 18 2014 - %{version}-%{release} - Remi Nivet <remi.nivet@worldline.com>
- Initial release
