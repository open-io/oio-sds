#!/usr/bin/env python

# oio-bootstrap.py
# Copyright (C) 2015 Conrad Kleinespel
# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
from six import iterkeys, iteritems
from six.moves import xrange

import errno
import grp
import yaml
import os
import pwd
from random import choice
import re  # noqa
from string import ascii_letters, digits, Template
import sys
import argparse
from collections import namedtuple
import shutil
from os.path import join

template_redis = """
daemonize no
pidfile ${RUNDIR}/redis.pid
port ${PORT}
tcp-backlog 128
bind ${IP}
timeout 0
tcp-keepalive 0
loglevel notice
#logfile ${LOGDIR}/redis.log
syslog-enabled yes
syslog-ident ${NS}-redis-${SRVNUM}
syslog-facility local0
databases 16
save 900 1
save 300 10
save 60 32768
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir ${DATADIR}/${NS}-redis-${SRVNUM}
slave-serve-stale-data yes
slave-read-only yes
repl-disable-tcp-nodelay no
slave-priority 100
maxclients 100
maxmemory 10m
maxmemory-policy volatile-lru
appendonly no
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
lua-time-limit 5000
slowlog-log-slower-than 10000
slowlog-max-len 128
notify-keyspace-events ""
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-entries 512
list-max-ziplist-value 64
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
aof-rewrite-incremental-fsync yes
"""

template_systemd_service_redis = """
[Unit]
Description=[OpenIO] Service redis ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${redis_server} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=HOME=${HOME}
${ENVIRONMENT}

[Install]
WantedBy=${PARENT}
"""
template_systemd_service_beanstalkd = """
[Unit]
Description=[OpenIO] Service beanstalkd ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=/usr/bin/beanstalkd -l ${IP} -p ${PORT} -b ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM} -f 1000 -s 10240000
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}
${ENVIRONMENT}

[Install]
WantedBy=${PARENT}
"""

template_foundationdb = """
## foundationdb.conf
##
## Configuration file for FoundationDB server processes
## Full documentation is available at
## https://apple.github.io/foundationdb/configuration.html#the-configuration-file

[fdbmonitor]
user = ${USER}
group = ${GROUP}

[general]
restart_delay = 60
cluster_file = ${CLUSTERFILE}

[fdbserver]
command = ${fdbserver}
public_address = auto:$ID
listen_address = public
datadir = ${DATADIR}/foundationdb/data/$ID
logdir = ${LOGDIRFDB}

[fdbserver.4600]

[backup_agent]
command = ${backup_agent}
logdir = ${LOGDIRFDB}

[backup_agent.1]
"""

template_foundationdb_cluster = """
${DESCRIPTION}:${RANDOMSTR}@${IP}:${PORT}
"""

template_systemd_service_foundationdb = """
[Unit]
Description=[OpenIO] Service FoundationDB
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
Environment=PATH=${PATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}
#ExecStartPre=/usr/sbin/service foundationdb stop
ExecStart=${fdbmonitor} --conffile ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf --lockfile ${RUNDIR}/${NS}-${SRVTYPE}-${SRVNUM}.pid
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
ExecStartPost=/bin/sleep 5 ; ${fdbcli} -C ${CLUSTERFILE} --exec "configure new ssd single"

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_account = """
[Unit]
Description=[OpenIO] Service account
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_xcute = """
[Unit]
Description=[OpenIO] Service xcute ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_billing_agent = """
[Unit]
Description=[OpenIO] Service billing agent
PartOf=${PARENT}
OioGroup=localhost,${GROUPTYPE},${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_rdir = """
[Unit]
Description=[OpenIO] Service rdir ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_proxy = """
[Unit]
Description=[OpenIO] Service proxy ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
NotifyAccess=main
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=${EXE} -s OIO,${NS},proxy ${IP}:${PORT} ${NS}
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}
${ENVIRONMENT}

[Install]
WantedBy=${PARENT}
"""

template_meta2_indexer_service = """
[meta2-indexer]
namespace = ${NS}
user = ${USER}
volume_list = ${META2_VOLUMES}
interval = 3000
report_interval = 5
scanned_per_second = 3
try_removing_faulty_indexes = False
autocreate = true
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}
"""

template_meta2_crawler_service = """
[meta2-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${META2_VOLUMES}

wait_random_time_before_starting = True
use_marker = False
interval = 1200
report_interval = 300
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300

log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger draining auto_vacuum auto_sharding

[filter:auto_sharding]
use = egg:oio#auto_sharding
sharding_db_size = 104857600
sharding_strategy = shard-with-partition
sharding_threshold = 1000
sharding_partition = 50,50
sharding_preclean_new_shards = True
sharding_preclean_timeout = 60
sharding_preclean_max_db_size = 157286400
sharding_create_shard_timeout = 60
sharding_save_writes_timeout = 60
shrinking_db_size = 26214400
sharding_step_timeout = 960

[filter:auto_vacuum]
use = egg:oio#auto_vacuum
min_waiting_time_after_last_modification = 30
soft_max_unused_pages_ratio = 0.1
hard_max_unused_pages_ratio = 0.2

[filter:draining]
use = egg:oio#draining
drain_limit = 1000
drain_limit_per_pass = 100000

[filter:logger]
use = egg:oio#logger
"""

template_meta2_placement_checker_crawler_service = """
[meta2-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${META2_VOLUMES}

wait_random_time_before_starting = True
interval = 1200
one_shot = True
report_interval = 300
scanned_per_second = 10

log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger verify_chunk_placement

[filter:logger]
use = egg:oio#logger

[filter:verify_chunk_placement]
# Identify misplaced chunks after meta2db scan and tag them with misplaced header.
# This filter is launched by a second instance of meta2 crawler. The second meta2
# instance is a oneshot service that we can launch manually to execute only
# verify_chunk_placement filter.
use = egg:oio#verify_chunk_placement
# Maximum object scanned per second by the filter
max_scanned_per_second  = 10000
# Time interval after which service data are updated
service_update_interval = 3600
"""

template_placement_improver_crawler_service = """
[placement-improver-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${RAWX_VOLUMES}

wait_random_time_before_starting = True
use_marker = False
interval = 300
report_interval = 75
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger changelocation

[filter:logger]
use = egg:oio#logger

[filter:changelocation]
use = egg:oio#changelocation
# Delay in second before next attempt by the improver to move
# a chunk that we were not able to move at previous pass.
# first attemp -> 15 min
# second attemp -> 30 min
# third attemp -> 1h
# fourth attemp -> 2h
# fifth attemp -> 2h
# sixth attemp -> 2h ...
new_attempt_delay = 900
"""

template_rdir_crawler_service = """
[rdir-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${RAWX_VOLUMES}

# How many hexdigits must be used to name the indirection directories
hash_width = ${HASH_WIDTH}
# How many levels of directories are used to store chunks
hash_depth = ${HASH_DEPTH}

wait_random_time_before_starting = True
interval = 1200
report_interval = 300
chunks_per_second = 10
conscience_cache = 30
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}
"""

template_rawx_crawler_service = """
[rawx-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${RAWX_VOLUMES}

wait_random_time_before_starting = True
use_marker = False
interval = 1200
report_interval = 300
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger indexer

[filter:indexer]
use = egg:oio#indexer

[filter:logger]
use = egg:oio#logger
"""

template_checksum_checker_crawler_service = """
[rawx-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${RAWX_VOLUMES}

wait_random_time_before_starting = True
use_marker = True
interval = 1200
report_interval = 300
scanned_per_second = 5
# represents 30 seconds at max rate
scanned_between_markers = 150
nice_value = 19
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger checksum

[filter:checksum]
use = egg:oio#checksum
conscience_cache = 30
# Boolean, indicates if the quarantine folder should be at the mountpoint
# of the rawx or under the corresponding volume path defined in <volume_list>
# Defaults to True
quarantine_mountpoint = False

[filter:logger]
use = egg:oio#logger
"""

template_rawx_service = """
listen ${IP}:${PORT}

docroot           ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
namespace         ${NS}
${WANT_SERVICE_ID}service_id        ${SERVICE_ID}

# How many hexdigits must be used to name the indirection directories
hash_width        ${HASH_WIDTH}

# How many levels of directories are used to store chunks.
hash_depth        ${HASH_DEPTH}

# At the end of an upload, perform a fsync() on the chunk file itself
fsync             ${FSYNC}
buffer_size 8192

# At the end of an upload, perform a fsync() on the directory holding the chunk
fsync_dir         ${FSYNC}

# Preallocate space for the chunk file (enabled by default)
#fallocate enabled

# Enable compression ('zlib' or 'lzo' or 'off')
compression ${COMPRESSION}

# Generic messages
log_format "level_name:{{ .Severity }}	pid:{{ .Pid }}	log_type:log	message:{{ .Message }}"
# Request-related message
log_request_format "level_name:{{ .Severity }}	pid:{{ .Pid }}	log_type:log	method:{{ .Method }}	local:{{ .Local }}	peer:{{ .Peer }}	path:{{ .Path }}	request_id:{{ .ReqId }}	tls:{{ .TLS }}	message:{{ .Message }}"
# Access log
log_access_format "level_name:INFO pid:{{ .Pid }}	log_type:access status_int:{{ .Status }}	bytes_recvd_int:{{ .BytesIn }}	bytes_sent_int:{{ .BytesOut }}	request_time_float:{{ .TimeSpent | div1M | printf \\"%.6f\\" }}	method:{{ .Method }}	local:{{ .Local }}	peer:{{ .Peer }}	path:{{ .Path }}	request_id:{{ .ReqId }}	tls:{{ .TLS }}	ttfb:{{ .TTFB }}"

#tcp_keepalive disabled
#timeout_read_header 10
#timeout_read_request 10
#timeout_write_reply 30
#timeout_idle 10
#headers_buffer_size 32768

${USE_TLS}tls_cert_file ${SRCDIR}/${TLS_CERT_FILE}
${USE_TLS}tls_key_file ${SRCDIR}/${TLS_KEY_FILE}
${USE_TLS}tls_rawx_url ${IP}:${TLS_PORT}
"""

template_wsgi_service_host = """
LoadModule mpm_worker_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mpm_worker.so
LoadModule authz_core_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_authz_core.so
LoadModule env_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_env.so
LoadModule wsgi_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_wsgi.so

<IfModule !mod_logio.c>
  LoadModule logio_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_logio.so
</IfModule>
<IfModule !unixd_module>
  LoadModule unixd_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_unixd.so
</IfModule>
<IfModule !log_config_module>
  LoadModule log_config_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_log_config.so
</IfModule>

Listen ${IP}:${PORT}
PidFile ${RUNDIR}/${NS}-${SRVTYPE}-${SRVNUM}.pid
ServerRoot ${TMPDIR}
ServerName localhost
ServerSignature Off
ServerTokens Prod
DocumentRoot ${RUNDIR}

User  ${USER}
Group ${GROUP}

SetEnv INFO_SERVICES OIO,${NS},${SRVTYPE},${SRVNUM}
SetEnv LOG_TYPE access
SetEnv LEVEL INF
SetEnv HOSTNAME oio

LogFormat "%{end:%b %d %T}t.%{end:usec_frac}t %{HOSTNAME}e %{INFO_SERVICES}e %{pid}P %{tid}P %{LOG_TYPE}e %{LEVEL}e %{Host}i %a:%{remote}p %m %>s %D %O %{${META_HEADER}-container-id}i %{x-oio-req-id}i -" log/common
ErrorLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-errors.log
CustomLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-access.log log/common env=!nolog
LogLevel info

#WSGIDaemonProcess ${SRVTYPE}-${SRVNUM} processes=8 threads=1 response-buffer-size=8388608 send-buffer-size=8388608 receive-buffer-size=8388608 user=${USER} group=${GROUP}
WSGIDaemonProcess ${SRVTYPE}-${SRVNUM} processes=8 threads=1 user=${USER} group=${GROUP}
#WSGIProcessGroup ${SRVTYPE}-${SRVNUM}
WSGIApplicationGroup ${SRVTYPE}-${SRVNUM}
WSGIScriptAlias / ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.wsgi
WSGISocketPrefix ${RUNDIR}/
WSGIChunkedRequest On
LimitRequestFields 200

<Directory />
AllowOverride none
</Directory>

<VirtualHost ${IP}:${PORT}>
# Leave Empty
</VirtualHost>
"""

template_meta_watch = """
host: ${IP}
port: ${PORT}
type: ${SRVTYPE}
location: ${LOC}
slots:
    - ${SRVTYPE}
checks:
    - {type: asn1}

stats:
    - {type: volume, path: ${VOLUME}}
    - {type: meta}
    - {type: system}
"""

template_account_watch = """
host: ${IP}
port: ${PORT}
type: account
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: http, path: /status, parser: json}
    - {type: system}
"""

template_xcute_watch = """
host: ${IP}
port: ${PORT}
type: xcute
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: http, path: /status, parser: json}
    - {type: system}
"""

template_rawx_watch = """
host: ${IP}
port: ${PORT}
type: rawx
location: ${LOC}
${USE_TLS}tls: ${IP}:${TLS_PORT}
checks:
    - {type: http, uri: /info}
slots:
    - ${SRVTYPE}
    - ${EXTRASLOT}
stats:
    - {type: volume, path: ${VOLUME}}
    - {type: rawx, path: /stat}
    - {type: system}
"""

template_rdir_watch = """
host: ${IP}
port: ${PORT}
type: rdir
location: ${LOC}
checks:
    - {type: http, uri: /info}
slots:
    - ${SRVTYPE}
stats:
    - {type: volume, path: ${VOLUME}}
    - {type: rdir, path: /status, parser: json}
    - {type: system}
"""

template_redis_watch = """
host: ${IP}
port: ${PORT}
type: redis
location: ${LOC}
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: volume, path: ${VOLUME}}
    - {type: system}
"""

template_foundationdb_watch = """
host: ${IP}
port: ${PORT}
type: foundationdb
location: ${LOC}
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: volume, path: ${VOLUME}}
    - {type: system}
"""

template_beanstalkd_watch = """
host: ${IP}
port: ${PORT}
type: beanstalkd
location: ${LOC}
checks:
    - {type: tcp}
slots:
    - beanstalkd
stats:
    - {type: beanstalkd}
    - {type: system}
    - {type: volume, path: ${VOLUME}}
"""

template_proxy_watch = """
host: ${IP}
port: ${PORT}
type: oioproxy
location: ${LOC}
checks:
    - {type: tcp}
slots:
    - oioproxy
stats:
    - {type: oioproxy}
    - {type: system}
"""

template_oioswift_watch = """
host: ${IP}
port: ${PORT}
type: oioswift
location: ${LOC}
checks:
    - {type: http, uri: "/healthcheck"}
slots:
    - ${SRVTYPE}
stats:
    - {type: system}
"""

template_conscience_service = """
[General]
to_op=1000
to_cnx=1000

flag.NOLINGER=true
flag.SHUTDOWN=false
flag.KEEPALIVE=false
flag.QUICKACK=false

[Server.conscience]
min_workers=2
min_spare_workers=2
max_spare_workers=10
max_workers=10
listen=${IP}:${PORT}
plugins=conscience,stats,ping,fallback

[Service]
namespace=${NS}
type=conscience
register=false
load_ns_info=false

[Plugin.ping]
path=${LIBDIR}/grid/msg_ping.so

[Plugin.stats]
path=${LIBDIR}/grid/msg_stats.so

[Plugin.fallback]
path=${LIBDIR}/grid/msg_fallback.so

[Plugin.conscience]
path=${LIBDIR}/grid/msg_conscience.so
param_namespace=${NS}

# Multi-conscience
param_hub.me=tcp://${IP}:${PORT_HUB}
param_hub.group=${CS_ALL_HUB}

# Storage policies definitions
param_storage_conf=${CFGDIR}/${NS}-policies.conf

# Service scoring and pools definitions
param_service_conf=${CFGDIR}/${NS}-service-{pool,type}*.conf

"""

template_conscience_policies = """
[STORAGE_POLICY]
# Storage policy definitions
# ---------------------------
#
# The first word is the service pool to use,
# the second word is the data security to use.

SINGLE=NONE:NONE
TWOCOPIES=rawx2:DUPONETWO
THREECOPIES=rawx3:DUPONETHREE
17COPIES=rawx17:DUP17
EC=NONE:EC
EC21=NONE:EC21
ECX21=NONE:ECX21

JUSTENOUGH=justenoughrawx:EC
NOTENOUGH=notenoughrawx:EC

[DATA_SECURITY]
# Data security definitions
# --------------------------
#
# The first word is the kind of data security ("plain" or "ec"),
# after the '/' are the parameters of the data security.

DUPONETWO=plain/min_dist=1,nb_copy=2
DUPONETHREE=plain/max_dist=2,min_dist=1,nb_copy=3
DUP17=plain/min_dist=1,nb_copy=17

EC=ec/k=6,m=3,algo=liberasurecode_rs_vand,min_dist=1
EC21=ec/k=2,m=1,algo=liberasurecode_rs_vand,min_dist=1,warn_dist=${WARN_DIST}
ECX21=ec/k=2,m=1,algo=liberasurecode_rs_vand,min_dist=0,max_dist=2,warn_dist=0

# List of possible values for the "algo" parameter of "ec" data security:
# "jerasure_rs_vand"       EC_BACKEND_JERASURE_RS_VAND
# "jerasure_rs_cauchy"     EC_BACKEND_JERASURE_RS_CAUCHY
# "flat_xor_hd"            EC_BACKEND_FLAT_XOR_HD
# "isa_l_rs_vand"          EC_BACKEND_ISA_L_RS_VAND
# "shss"                   EC_BACKEND_SHSS
# "liberasurecode_rs_vand" EC_BACKEND_LIBERASURECODE_RS_VAND
"""

template_service_pools = """
# Service pools declarations
# ----------------------------
#
# Pools are automatically created if not defined in configuration,
# according to storage policy or service update policy rules.
#
# "targets" is a ';'-separated list.
# Each target is a ','-separated list of:
# - the number of services to pick,
# - the name of a slot where to pick the services,
# - the name of a slot where to pick services if there is
#   not enough in the previous slot
# - and so on...
#
# "strict_location_constraint" is the absolute maximum number of items to select for
# each location level. This can be defined in place of "min_dist".
# Example: 12.6.3.1 meaning 12 per DC, 6 per rack, 3 per server, 1 per drive.
# Notice that the last number is always 1 internally (cannot select 2 services
# on the same drive unless we mess with service location strings).
#
# "fair_location_constraint" is the number of services per location level that is
# considered too much for an optimal placement. When surpassed, an extra
# metadata will be saved in order to trigger a placement improvement.
# This can be defined in place of "warn_dist".
#
# "nearby_mode" is a boolean telling to find services close to each other.
#
# "min_dist" is the absolute minimum distance between services returned
# by the pool. It defaults to 1, which is the minimum. If you set it too
# high, there is a risk the pool fails to find a service set matching
# all the criteria.
#
# "max_dist" is the distance between services that the pool will try to
# ensure. This option defaults to 4, which is the maximum. If you know
# that all the services are close together, you can reduce this number
# to accelerate the research.
#
# "warn_dist" is the distance between services at which the pool will emit
# a warning, for further improvement.
#

[pool:meta1]
targets=${M1_REPLICAS},meta1

[pool:meta2]
targets=${M2_REPLICAS},meta2

#[pool:rdir]
#targets=1,rawx;1,rdir

[pool:account]
targets=1,account

[pool:fastrawx3]
# Pick 3 SSD rawx, or any rawx if SSD is not available
targets=3,rawx-ssd,rawx

[pool:rawxevenodd]
# Pick one "even" and one "odd" rawx
targets=1,rawx-even;1,rawx-odd

[pool:rawx2]
# As with rawxevenodd, but with permissive fallback on any rawx
targets=1,rawx-even,rawx;1,rawx-odd,rawx
warn_dist=${WARN_DIST}

[pool:rawx3]
# Try to pick one "even" and one "odd" rawx, and a generic one
targets=1,rawx-even,rawx;1,rawx-odd,rawx;1,rawx
# If we change max_dist to 3, we need to update test_content_perfectible.py
max_dist=2
warn_dist=${WARN_DIST}

[pool:zonedrawx3]
# Pick one rawx in Europe, one in USA, one in Asia, or anywhere if none available
targets=1,rawx-europe,rawx;1,rawx-usa,rawx;1,rawx-asia,rawx

[pool:rawx3nearby]
targets=3,rawx
nearby_mode=true
warn_dist=0

[pool:rawx3faraway]
targets=3,rawx
min_dist=2
warn_dist=2

# Special pools for placement tests
[pool:justenoughrawx]
targets=9,rawx
min_dist=1
warn_dist=0
strict_location_constraint=9.9.3.1
fair_location_constraint=9.9.2.1

[pool:notenoughrawx]
targets=9,rawx
min_dist=1
warn_dist=0
strict_location_constraint=9.9.2.1
fair_location_constraint=9.9.2.1
"""

template_service_types = """
# Service types declarations
# ---------------------------

[type:meta0]
score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
# Defaults to 300s
score_timeout=3600
# Defaults to 5s
score_variation_bound=20
# Defaults to true
lock_at_first_register=false

[type:meta1]
score_expr=((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
score_timeout=120
lock_at_first_register=false

[type:meta2]
score_expr=((num stat.space)>1) * root(3,((1 + (num stat.cpu))*(num stat.space)*(1 + (num stat.io))))
score_timeout=120

[type:rawx]
score_expr=((num stat.space)>1) * root(3,((1 + (num stat.cpu))*(num stat.space)*(1 + (num stat.io))))
score_timeout=120

[type:rdir]
score_expr=((num stat.space)>1) * root(3,((1 + (num stat.cpu))*(num stat.space)*(1 + (num stat.io))))
score_timeout=120

[type:redis]
score_expr=(1 + (num stat.cpu))
score_timeout=120

[type:foundationdb]
score_expr=(1 + (num stat.cpu))
score_timeout=120

[type:account]
score_expr=(1 + (num stat.cpu))
score_timeout=120

[type:xcute]
score_expr=(1 + (num stat.cpu))
score_timeout=120

[type:echo]
score_expr=(num stat.cpu)
score_timeout=30

[type:oioproxy]
score_expr=(1 + (num stat.cpu))
score_timeout=120
lock_at_first_register=false

[type:oioswift]
#score_expr=((num stat.cpu)>5) * (num stat.cpu)
score_expr=1 + (num stat.cpu)
score_timeout=120
lock_at_first_register=false

[type:beanstalkd]
# 1000000 ready jobs -> score = 0
score_expr=root(3, (num stat.cpu) * (num stat.space) * (100 - root(3, (num stat.jobs_ready))))
score_timeout=120
lock_at_first_register=false
"""

template_systemd_service_ns = """
[Unit]
Description=[OpenIO] Service namespace
PartOf=${PARENT}
OioGroup=${NS},localhost,conscience,conscience-agent

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/conscience-agent.yml
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=PYTHONPATH=${PYTHONPATH}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_conscience = """
[Unit]
Description=[OpenIO] Service conscience ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} -O PersistencePath=${DATADIR}/${NS}-conscience-${SRVNUM}/conscience.dat -O PersistencePeriod=15 -s OIO,${NS},cs,${SRVNUM} ${CFGDIR}/${NS}-conscience-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_target = """
[Unit]
Description=[OpenIO] Target ${SRVTYPE}
${WANTS}
${AFTER}
${PARTOF}

[Install]
${WANTEDBY}
"""

template_systemd_service_meta = """
[Unit]
Description=[OpenIO] Service ${SRVTYPE} ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} -s OIO,${NS},${SRVTYPE},${SRVNUM} -O Endpoint=${IP}:${PORT} ${OPTARGS} ${EXTRA} ${NS} ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_meta2_indexer = """
[Unit]
Description=[OpenIO] Service meta2 indexer
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_meta2_crawler = """
[Unit]
Description=[OpenIO] Service meta2 crawler
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_placement_checker_crawler = """
[Unit]
Description=[OpenIO] Service meta2 crawler to check chunks placement
After=network.target
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=oneshot
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}
"""

template_systemd_service_placement_improver_crawler = """
[Unit]
Description=[OpenIO] Service placement improver crawler
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_rdir_crawler = """
[Unit]
Description=[OpenIO] Service rdir crawler
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_rawx_crawler = """
[Unit]
Description=[OpenIO] Service rawx crawler
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_checksum_checker_crawler = """
[Unit]
Description=[OpenIO] Service checksum checker crawler
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_rawx_command_options = (
    "-s OIO,${NS},${SRVTYPE},${SRVNUM} -D FOREGROUND "
    "-f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.httpd.conf"
)

template_systemd_service_rawx = """
[Unit]
Description=[OpenIO] Service rawx ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} %s
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_httpd = """
[Unit]
Description=[OpenIO] Service ${SRVTYPE} ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${HTTPD_BINARY} -D FOREGROUND -f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.httpd.conf -E /tmp/httpd-startup-failures.log
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=PATH=${PATH}
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_blob_rebuilder = """
[Unit]
Description=[OpenIO] Service blob rebuilder ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} --concurrency 10 --beanstalkd ${QUEUE_URL} --log-facility local0 --log-syslog-prefix OIO,OPENIO,${SRVTYPE},${SRVNUM} ${NS}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_local_header = """
[default]
"""

template_local_ns = """
[${NS}]
${NOZK}# ZK URL, at least used by zk-bootstrap.py
${NOZK}zookeeper=${ZK_CNXSTRING}
${NOZK}# Alternate ZK endpoints for specific services
${NOZK}zookeeper.meta0=${ZK_CNXSTRING}
${NOZK}zookeeper.meta1=${ZK_CNXSTRING}
${NOZK}zookeeper.meta2=${ZK_CNXSTRING}

#proxy-local=${RUNDIR}/${NS}-proxy.sock
proxy=${IP}:${PORT_PROXYD}
conscience=${CS_ALL_PUB}
${NOBS}event-agent=${EVENT_CNXSTRING}
${NOBS}event-agent.meta2=${EVENT_CNXSTRING_M2}

ns.meta1_digits=${M1_DIGITS}

# Small pagination to avoid time-consuming tests
meta2.flush_limit=64
meta2.sharding.max_entries_merged=10
meta2.sharding.max_entries_cleaned=10
# Limit the maximum number of databases open simultaneously
# to avoid using too much RAM
sqliterepo.repo.hard_max=1024

admin=${IP}:${PORT_ADMIN}
"""

template_systemd_service_event_agent = """
[Unit]
Description=[OpenIO] Service event agent ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,event

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_event_agent = """
[event-agent]
tube = oio
namespace = ${NS}
user = ${USER}
workers = 2
concurrency = 5
handlers_conf = ${CFGDIR}/event-handlers-${SRVNUM}.conf
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}
queue_url=${QUEUE_URL}

rdir_connection_timeout = 0.5
rdir_read_timeout = 5.0
"""

template_event_agent_handlers = """
[handler:storage.content.new]
# pipeline = replication
pipeline = ${REPLICATION} ${WEBHOOK} ${PRESERVE}

[handler:storage.content.update]
# pipeline = replication webhook
pipeline = ${REPLICATION} ${WEBHOOK} ${PRESERVE}

[handler:storage.content.append]
# pipeline = replication
pipeline = ${REPLICATION} ${WEBHOOK} ${PRESERVE}

[handler:storage.content.broken]
pipeline = content_rebuild ${PRESERVE}

[handler:storage.content.deleted]
# pipeline = replication content_cleaner
pipeline = ${REPLICATION} ${WEBHOOK} content_cleaner ${PRESERVE}

[handler:storage.content.drained]
# pipeline = replication content_cleaner
pipeline = ${REPLICATION} content_cleaner notify_drained ${PRESERVE}

[handler:storage.container.new]
# pipeline = replication account_update
pipeline = ${REPLICATION} account_update ${PRESERVE}

[handler:storage.container.update]
# pipeline = replication
pipeline = ${REPLICATION} ${PRESERVE}

[handler:storage.container.deleted]
# pipeline = replication account_update
pipeline = ${REPLICATION} account_update ${PRESERVE}

[handler:storage.container.state]
pipeline = account_update ${PRESERVE}

[handler:storage.chunk.new]
pipeline = volume_index ${PRESERVE}

[handler:storage.chunk.deleted]
pipeline = volume_index ${PRESERVE}

[handler:storage.meta2.deleted]
pipeline = volume_index ${PRESERVE}

[handler:account.services]
pipeline = account_update volume_index ${PRESERVE}

[filter:content_cleaner]
use = egg:oio#content_cleaner

# These values are changed only for testing purposes.
# The default values are good for most use cases.
concurrency = 4
pool_connections = 16
pool_maxsize = 16
timeout = 4.5

[filter:content_rebuild]
use = egg:oio#notify
tube = oio-rebuild
queue_url = ${QUEUE_URL}

[filter:account_update]
use = egg:oio#account_update
connection_timeout=1.0
read_timeout=15.0

[filter:volume_index]
use = egg:oio#volume_index

[filter:webhook]
use = egg:oio#webhook
endpoint = ${WEBHOOK_ENDPOINT}

[filter:replication]
use = egg:oio#replicate
tube = oio-repli
queue_url = ${QUEUE_URL}
# This must be explicitly enabled
check_replication_enabled=true
#cache_duration=30.0
#cache_size=10000
#connection_timeout=2.0
#read_timeout=30.0

[filter:bury]
use = egg:oio#bury

[filter:dump]
use = egg:oio#dump

[filter:noop]
use = egg:oio#noop

# This filter is only to demonstrate policy regexes
[filter:notify_drained]
use = egg:oio#notify
queue_url = ${QUEUE_URL}
tube = oio-drained
policy_regex_EC = ^EC.*
tube_EC = oio-drained-ec

[filter:logger]
use = egg:oio#logger

[filter:preserve]
# Preserve all events in the oio-preserved tube. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
tube = oio-preserved
queue_url = ${MAIN_QUEUE_URL}
"""

template_systemd_service_xcute_event_agent = """
[Unit]
Description=[OpenIO] Service xcute event agent ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,event

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=PYTHONPATH=${PYTHONPATH}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_xcute_event_agent = """
[event-agent]
tube = oio-xcute
namespace = ${NS}
user = ${USER}
workers = 2
concurrency = 5
handlers_conf = ${CFGDIR}/xcute-event-handlers-${SRVNUM}.conf
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}
queue_url=${QUEUE_URL}
"""

template_xcute_event_agent_handlers = """
[handler:xcute.tasks]
pipeline = xcute

[filter:xcute]
use = egg:oio#xcute
#cache_size = 50
"""

template_billing_agent_service = """
[billing-agent]
user = ${USER}

wait_random_time_before_starting = True
interval = 1200
report_interval = 300

# Common log stuff
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
syslog_prefix = OIO,${SRVTYPE}

# FoundationDB
fdb_file = ${CLUSTERFILE}

# Billing message
reseller_prefix = AUTH_
default_storage_class = STANDARD
event_type = telemetry.polling
publisher_id = ceilometer.polling
counter_name = storage.bucket.objects.size
batch_size = 5

# RabbitMQ
amqp_url = amqp://guest:guest@localhost:5672/
amqp_exchange = swift
amqp_queue = notifications.info
amqp_durable = True
amqp_auto_delete = False

# Storage classes
storage_class.GLACIER = SINGLE,TWOCOPIES
storage_class.STANDARD = THREECOPIES,EC
"""

template_conscience_agent = """
namespace: ${NS}
user: ${USER}
log_level: INFO
log_facility: LOG_LOCAL0
log_address: /dev/log
syslog_prefix: OIO,${NS},${SRVTYPE},${SRVNUM}
check_interval: ${MONITOR_PERIOD}
rise: 1
fall: 1
include_dir: ${CFGDIR}/watch
"""

template_account = """
[account-server]
bind_addr = ${IP}
bind_port = ${PORT}
namespace = ${NS}
workers = 2
worker_class = gevent
autocreate = true
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}

fdb_file = ${CLUSTERFILE}

time_window_clear_deleted = 60
allow_empty_policy_name = False
"""

template_xcute = """
[DEFAULT]
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}
namespace = ${NS}
# Let this option empty to connect directly to redis_host
#redis_sentinel_hosts = 127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381
#redis_sentinel_name = oio
redis_host = ${IP}:${REDIS_PORT}

[xcute-server]
bind_addr = ${IP}
bind_port = ${PORT}
workers = 2

[xcute-orchestrator]
orchestrator_id = orchestrator-${SRVNUM}
beanstalkd_workers_tube = oio-xcute
beanstalkd_reply_tube = oio-xcute.reply
beanstalkd_reply_addr = ${QUEUE_URL}
"""

template_rdir = """
[rdir-server]
bind_addr = ${IP}
bind_port = ${PORT}
namespace = ${NS}
db_path= ${VOLUME}
# Currently, only 1 worker is allowed to avoid concurrent access to leveldb
worker_class = sync
workers = 1
threads = 1
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
${WANT_SERVICE_ID}service_id = ${SERVICE_ID}
syslog_prefix = OIO,${NS},rdir,${SRVNUM}
"""

template_admin = """
[admin-server]
bind_addr = ${IP}
bind_port = ${PORT}
namespace = ${NS}
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},admin,${SRVNUM}
redis_host = ${IP}
"""

template_systemd_service_webhook_server = """
[Unit]
Description=[OpenIO] Service webhook server ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},localhost,${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} --port 9081
Environment=PATH=${PATH}
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""

template_systemd_rabbitmq_to_beanstalkd = """
[Unit]
Description=[OpenIO] Forward messages from RabbitMQ to Beanstalkd
After=oio-meta2-1.service
PartOf=${PARENT}
OioGroup=${NS},localhost,event

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} --ns ${NS} --workers 2
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=HOME=${HOME}

[Install]
WantedBy=${PARENT}
"""


HOME = str(os.environ["HOME"])
OIODIR = HOME + "/.oio"
SDSDIR = OIODIR + "/sds"
CFGDIR = SDSDIR + "/conf"
RUNDIR = SDSDIR + "/run"
LOGDIR = SDSDIR + "/logs"
LOGDIRFDB = SDSDIR + "/logs/fdb"
SPOOLDIR = SDSDIR + "/spool"
WATCHDIR = SDSDIR + "/conf/watch"
TMPDIR = "/tmp"
CODEDIR = "@CMAKE_INSTALL_PREFIX@"
SRCDIR = "@CMAKE_CURRENT_SOURCE_DIR@"
LIBDIR = CODEDIR + "/@LD_LIBDIR@:@ZK_LIBDIR@:" + os.environ["LD_LIBRARY_PATH"]
BINDIR = CODEDIR + "/bin"
PATH = HOME + "/.local/bin:@CMAKE_INSTALL_PREFIX@/bin:" + os.environ["PATH"]
PYTHON_VERSION = "python" + ".".join(str(x) for x in sys.version_info[:2])
VENV = str(os.environ["VIRTUAL_ENV"])
if VENV:
    PYTHONPATH = "%s/lib/%s/site-packages" % (VENV, PYTHON_VERSION)
    BINDIR = VENV + "/bin"
    PATH = "%s:%s" % (BINDIR, PATH)

# Constants for the configuration of oio-bootstrap
NS = "ns"
IP = "ip"
SVC_HOSTS = "hosts"
SVC_NB = "count"
SVC_PARAMS = "params"
ALLOW_REDIS = "redis"
ALLOW_FDB = "fdb"
OPENSUSE = "opensuse"
ZOOKEEPER = "zookeeper"
REMOTE_ACCOUNT = "remote_account"
GO_RAWX = "go_rawx"
FSYNC_RAWX = "rawx_fsync"
MONITOR_PERIOD = "monitor_period"
M1_DIGITS = "meta1_digits"
M1_REPLICAS = "directory_replicas"
M2_REPLICAS = "container_replicas"
M2_VERSIONS = "container_versions"
M2_STGPOL = "storage_policy"
PROFILE = "profile"
PORT_START = "port_start"
ACCOUNT_ID = "account_id"
BUCKET_NAME = "bucket_name"
COMPRESSION = "compression"
APPLICATION_KEY = "application_key"
META_HEADER = "x-oio-chunk-meta"
COVERAGE = os.getenv("PYTHON_COVERAGE")
TLS_CERT_FILE = None
TLS_KEY_FILE = None
HASH_WIDTH = "hash_width"
HASH_DEPTH = "hash_depth"

defaults = {
    "NS": "OPENIO",
    SVC_HOSTS: ("127.0.0.1",),
    "ZK": "127.0.0.1:2181",
    "NB_CS": 1,
    "NB_M0": 1,
    "NB_M1": 1,
    "NB_M2": 1,
    "NB_RAWX": 3,
    "NB_RAINX": 0,
    "REPLI_M2": 1,
    "REPLI_M1": 1,
    COMPRESSION: "off",
    MONITOR_PERIOD: 1,
    M1_DIGITS: 2,
    HASH_WIDTH: 3,
    HASH_DEPTH: 1,
}

# XXX When /usr/sbin/httpd is present we suspect a Redhat/Centos/Fedora
# environment. If not, we consider being in a Ubuntu/Debian environment.
# Sorry for the others, we cannot manage everything in this helper script for
# developers, so consider using the standard deployment tools for your
# preferred Linux distribution.
HTTPD_BINARY = "/usr/sbin/httpd"
APACHE2_MODULES_SYSTEM_DIR = ""
if not os.path.exists("/usr/sbin/httpd"):
    HTTPD_BINARY = "/usr/sbin/apache2"
    APACHE2_MODULES_SYSTEM_DIR = "/usr/lib/apache2/"


def is_systemd_system():
    return "OIO_SYSTEMD_SYSTEM" in os.environ


def systemd_dir():
    if is_systemd_system():
        return "/etc/systemd/system"
    return HOME + "/.config/systemd/user"


def config(env):
    return "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf".format(**env)


def httpd_config(env):
    return "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.httpd.conf".format(**env)


def watch(env):
    return "{WATCHDIR}/{NS}-{SRVTYPE}-{SRVNUM}.yml".format(**env)


def wsgi(env):
    return "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.wsgi".format(**env)


def cluster(env):
    return "{CFGDIR}/{NS}-fdb.cluster".format(**env)


def systemd_service(env):
    filename = "{PREFIX}{SRVTYPE}"
    if "SRVNUM" in env:
        filename = filename + "-{SRVNUM}"
    filename = filename + ".service"

    return filename.format(**env)


def systemd_target(env):
    return "{PREFIX}{SRVTYPE}.target".format(**env)


def mkdir_noerror(d):
    try:
        os.makedirs(d, 0o700)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise e


def generate(options):
    global first_port

    def ensure(v, default):
        if v is None:
            return default
        return v

    def getint(v, default):
        try:
            return int(ensure(v, default))
        except:
            return default

    final_conf = {}
    final_services = {}

    ports = (x for x in xrange(options["port"], 60000))
    port_proxy = next(ports)
    port_account = next(ports)
    port_admin = next(ports)

    versioning = 1
    stgpol = "SINGLE"

    meta1_digits = getint(options.get(M1_DIGITS), defaults[M1_DIGITS])
    meta1_replicas = getint(options.get(M1_REPLICAS), defaults["REPLI_M1"])
    meta2_replicas = getint(options.get(M2_REPLICAS), defaults["REPLI_M2"])

    if M2_VERSIONS in options:
        versioning = options[M2_VERSIONS]
    if M2_STGPOL in options:
        stgpol = options[M2_STGPOL]
    options["config"]["ns.storage_policy"] = stgpol

    # `options` already holds the YAML values overridden by the CLI values
    hosts = options.get(SVC_HOSTS) or defaults[SVC_HOSTS]

    if options.get(REMOTE_ACCOUNT):
        options["config"]["account"] = f"http://{hosts[0]}:{port_account}"

    ns = options.get("ns") or defaults["NS"]
    want_service_id = "" if options.get("with_service_id") else "#"

    DATADIR = options.get("DATADIR", SDSDIR + "/data")
    WEBHOOK = "webhook" if options.get("webhook_enabled", False) else ""
    WEBHOOK_ENDPOINT = options.get("webhook_endpoint", "")

    compression = options.get("compression", defaults["compression"])

    TLS_CERT_FILE = options.get("tls_cert_file")
    TLS_KEY_FILE = options.get("tls_key_file")

    ENV = dict(
        ZK_CNXSTRING=options.get("ZK"),
        NS=ns,
        HOME=HOME,
        BINDIR=BINDIR,
        PATH=PATH,
        LIBDIR=LIBDIR,
        PYTHONPATH=PYTHONPATH,
        OIODIR=OIODIR,
        SDSDIR=SDSDIR,
        TMPDIR=TMPDIR,
        DATADIR=DATADIR,
        CFGDIR=CFGDIR,
        SYSTEMDDIR=systemd_dir(),
        RUNDIR=RUNDIR,
        SPOOLDIR=SPOOLDIR,
        LOGDIR=LOGDIR,
        LOGDIRFDB=LOGDIRFDB,
        CODEDIR=CODEDIR,
        SRCDIR=SRCDIR,
        WATCHDIR=WATCHDIR,
        UID=str(os.geteuid()),
        GID=str(os.getgid()),
        USER=str(pwd.getpwuid(os.getuid()).pw_name),
        GROUP=str(grp.getgrgid(os.getgid()).gr_name),
        VERSIONING=versioning,
        PORT_PROXYD=port_proxy,
        PORT_ACCOUNT=port_account,
        PORT_ADMIN=port_admin,
        M1_DIGITS=meta1_digits,
        M1_REPLICAS=meta1_replicas,
        M2_REPLICAS=meta2_replicas,
        M2_DISTANCE=str(1),
        COMPRESSION=compression,
        APACHE2_MODULES_SYSTEM_DIR=APACHE2_MODULES_SYSTEM_DIR,
        HTTPD_BINARY=HTTPD_BINARY,
        META_HEADER=META_HEADER,
        PRESERVE="preserve" if options.get("preserve_events") else "",
        PYTHON_VERSION=PYTHON_VERSION,
        REGION=options["config"].get("ns.region"),
        REPLICATION="replication" if options.get("replication_events") else "",
        WANT_SERVICE_ID=want_service_id,
        WEBHOOK=WEBHOOK,
        WEBHOOK_ENDPOINT=WEBHOOK_ENDPOINT,
        TLS_CERT_FILE=TLS_CERT_FILE,
        TLS_KEY_FILE=TLS_KEY_FILE,
    )

    def merge_env(add):
        env = dict(ENV)
        env.update(add)
        env["env.G_DEBUG"] = "fatal_warnings"
        orig_exe = env.get("EXE", None)
        if orig_exe and orig_exe not in ("oio-meta0-server", "beanstalkd"):
            if options.get(PROFILE) == "valgrind":
                new_exe = (
                    "valgrind --leak-check=full --leak-resolution=high    "
                    " --trace-children=yes --log-file=/tmp/%q{ORIG_EXE}.%p.valgrind "
                    + orig_exe
                )
                env["env.ORIG_EXE"] = orig_exe
                env["EXE"] = new_exe
                env["env.G_DEBUG"] = "gc-friendly"
                env["env.G_SLICE"] = "always-malloc"
            elif options.get(PROFILE) == "callgrind":
                new_exe = (
                    "valgrind --tool=callgrind --collect-jumps=yes    "
                    " --collect-systime=yes --trace-children=yes    "
                    " --callgrind-out-file=/tmp/callgrind.out.%q{ORIG_EXE}.%p "
                    + orig_exe
                )
                env["env.ORIG_EXE"] = orig_exe
                env["EXE"] = new_exe
                env.pop("env.G_SLICE", None)
        return env

    def subenv(add):
        env = merge_env(add)
        if options["random_service_id"] == 1:
            env["WANT_SERVICE_ID"] = ""
            options["random_service_id"] = 2
        elif options["random_service_id"] == 2:
            env["WANT_SERVICE_ID"] = "#"
            options["random_service_id"] = 1

        # remove Service Id from env for test.yml
        if "SERVICE_ID" in env and env["WANT_SERVICE_ID"] == "#":
            del env["SERVICE_ID"]
        env["VOLUME"] = "{DATADIR}/{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
        return env

    def build_location(ip, num):
        return "rack.%s.%d" % (ip.replace(".", "-"), num)

    targets = dict()
    systemd_prefix = "oio-"

    Target = namedtuple("Target", ["name", "systemd_name", "parent", "deps"])

    def add_service(env):
        t = env["SRVTYPE"]
        if t not in final_services:
            final_services[t] = []

        num = int(env["SRVNUM"])
        out = {"num": str(num)}
        if "IP" not in env:
            _h = tuple(hosts)
            if t in options and isinstance(options[t], dict):
                _h = ensure(options[t].get(SVC_HOSTS), hosts)
            env["IP"] = _h[(num - 1) % len(_h)]
        if "LOC" not in env:
            env["LOC"] = build_location(env["IP"], env["SRVNUM"])
        if "PORT" in env:
            out["addr"] = "%s:%s" % (env["IP"], env["PORT"])
        if "TLS_PORT" in env:
            out["tls_addr"] = "%s:%s" % (env["IP"], env["TLS_PORT"])
        if "VOLUME" in env:
            out["path"] = env["VOLUME"]
        if "SYSTEMD_UNIT" in env:
            out["unit"] = env["SYSTEMD_UNIT"]
        # For some types of services, SERVICE_ID is always there, but we do
        # not want it in the test configuration file if service IDs are not
        # globally enabled.
        if (
            "SERVICE_ID" in env
            and options.get("with_service_id")
            and env.get("WANT_SERVICE_ID") != "#"
        ):
            out["service_id"] = env["SERVICE_ID"]
        final_services[t].append(out)

    def register_target(name, parent=None):
        if not name in targets:
            env = subenv({"PREFIX": systemd_prefix, "SRVTYPE": name, "SRVNUM": 1})
            targets[name] = Target(
                name,
                systemd_target(env),
                parent.systemd_name if parent else None,
                list(),
            )
        if parent:
            parent.deps.append(targets[name].systemd_name)
        return targets[name]

    def register_service(
        env, template_name, target, add_service_to_conf=True, coverage_wrapper=""
    ):
        env.update(
            {
                "PREFIX": systemd_prefix,
                "PARENT": target.systemd_name if target else "",
                "SERVICEUSER": "User={}".format(env["USER"])
                if is_systemd_system()
                else "",
                "SERVICEGROUP": "Group={}".format(env["GROUP"])
                if is_systemd_system()
                else "",
            }
        )
        service_name = systemd_service(env)
        if add_service_to_conf:
            env.update({"SYSTEMD_UNIT": service_name})
            add_service(env)
        if "EXE" in env:
            env["EXE"] = shutil.which(env["EXE"])
            if COVERAGE and env["EXE"]:
                env["EXE"] = coverage_wrapper + env["EXE"]
        if target:
            target.deps.append(service_name)
        service_path = "{}/{}".format(env["SYSTEMDDIR"], service_name)
        environment = list()
        for key in (k for k in iterkeys(env) if k.startswith("env.")):
            environment.append("Environment=%s=%s" % (key[4:], env[key]))
        env.update({"ENVIRONMENT": "\n".join(environment)})
        with open(service_path, "w+") as f:
            tpl = Template(template_name)
            f.write(tpl.safe_substitute(env))
        return service_name

    def generate_target(target):
        env = subenv(
            {
                "PREFIX": systemd_prefix,
                "SRVTYPE": target.name,
                "SRVNUM": 1,
                "PARTOF": "",
                "WANTEDBY": "",
                "WANTS": "\n".join(["Wants=%s" % t for t in target.deps]),
                "AFTER": "\n".join(["After=%s" % t for t in target.deps]),
            }
        )
        if target.parent:
            env["PARTOF"] = "PartOf={}".format(target.parent)
            env["WANTEDBY"] = "WantedBy={}".format(target.parent)
        target_path = "{}/{}".format(env["SYSTEMDDIR"], target.systemd_name)
        with open(target_path, "w+") as f:
            tpl = Template(template_systemd_target)
            f.write(tpl.safe_substitute(env))

    ENV["LOC_PROXYD"] = build_location(hosts[0], ENV["PORT_PROXYD"])
    ENV["MONITOR_PERIOD"] = getint(
        options.get(MONITOR_PERIOD), defaults[MONITOR_PERIOD]
    )
    if options.get(ZOOKEEPER):
        ENV["NOZK"] = ""
    else:
        ENV["NOZK"] = "#"

    mkdir_noerror(SDSDIR)
    mkdir_noerror(CODEDIR)
    mkdir_noerror(DATADIR)
    mkdir_noerror(CFGDIR)
    mkdir_noerror(systemd_dir())
    mkdir_noerror(WATCHDIR)
    mkdir_noerror(RUNDIR)
    mkdir_noerror(LOGDIR)
    mkdir_noerror(LOGDIRFDB)
    # create root target
    root_target = register_target("cluster")

    # conscience
    nb_conscience = getint(options["conscience"].get(SVC_NB), defaults["NB_CS"])
    if nb_conscience:
        cs = list()
        # This is to trigger "content.perfectible" events during tests
        ENV["WARN_DIST"] = 1 if len(hosts) > 1 else 0
        with open("{CFGDIR}/{NS}-policies.conf".format(**ENV), "w+") as f:
            tpl = Template(template_conscience_policies)
            f.write(tpl.safe_substitute(ENV))
        with open("{CFGDIR}/{NS}-service-pools.conf".format(**ENV), "w+") as f:
            tpl = Template(template_service_pools)
            f.write(tpl.safe_substitute(ENV))
        with open("{CFGDIR}/{NS}-service-types.conf".format(**ENV), "w+") as f:
            tpl = Template(template_service_types)
            f.write(tpl.safe_substitute(ENV))
        # Prepare a list of consciences
        for num in range(nb_conscience):
            h = hosts[num % len(hosts)]
            cs.append((num + 1, h, next(ports), next(ports)))
        ENV.update(
            {
                "CS_ALL_PUB": ",".join(
                    [str(host) + ":" + str(port) for _, host, port, _ in cs]
                ),
                "CS_ALL_HUB": ",".join(
                    ["tcp://" + str(host) + ":" + str(hub) for _, host, _, hub in cs]
                ),
            }
        )
        # generate the conscience files
        conscience_target = register_target("conscience", root_target)
        for num, host, port, hub in cs:
            env = subenv(
                {
                    "SRVTYPE": "conscience",
                    "SRVNUM": num,
                    "PORT": port,
                    "PORT_HUB": hub,
                    "EXE": "oio-daemon",
                }
            )
            register_service(
                env, template_systemd_service_conscience, conscience_target
            )
            with open(config(env), "w+") as f:
                tpl = Template(template_conscience_service)
                f.write(tpl.safe_substitute(env))

    # beanstalkd
    all_beanstalkd = []
    nb_beanstalkd = getint(options["beanstalkd"].get(SVC_NB), 1)
    if nb_beanstalkd:
        # prepare a list of all the beanstalkd
        for num in range(nb_beanstalkd):
            h = hosts[num % len(hosts)]
            all_beanstalkd.append((num + 1, h, next(ports)))
        # generate the files
        beanstalkd_target = register_target("beanstalkd", root_target)
        for num, host, port in all_beanstalkd:
            env = subenv(
                {
                    "SRVTYPE": "beanstalkd",
                    "SRVNUM": num,
                    "IP": host,
                    "PORT": port,
                    "EXE": "beanstalkd",
                }
            )
            register_service(
                env, template_systemd_service_beanstalkd, beanstalkd_target
            )
            # watcher
            tpl = Template(template_beanstalkd_watch)
            with open(watch(env), "w+") as f:
                f.write(tpl.safe_substitute(env))

        beanstalkd_cnxstring = ";".join(
            "beanstalk://" + str(h) + ":" + str(p) for _, h, p in all_beanstalkd
        )
        ENV.update({"EVENT_CNXSTRING": beanstalkd_cnxstring, "NOBS": ""})
    else:
        ENV.update({"EVENT_CNXSTRING": "***disabled***", "NOBS": "#"})

    # If a RabbitMQ endpoint is configured, configure it only for meta2
    if "endpoint" in options["rabbitmq"]:
        ENV.update({"EVENT_CNXSTRING_M2": options["rabbitmq"]["endpoint"]})
        env = subenv(
            {
                "SRVNUM": 1,
                "SRVTYPE": "event-forwarder",
                "EXE": "oio-rabbitmq-to-beanstalkd",
            }
        )
        rabbitmq_target = register_target("rabbitmq-to-beanstalkd", root_target)
        register_service(
            env,
            template_systemd_rabbitmq_to_beanstalkd,
            rabbitmq_target,
            coverage_wrapper=shutil.which("coverage") + " run -p ",
        )
    else:
        ENV.update({"EVENT_CNXSTRING_M2": ENV["EVENT_CNXSTRING"]})

    meta2_volumes = []

    # meta*
    def generate_meta(t, n, tpl, parent_target, ext_opt="", service_id=False):
        env = subenv(
            {
                "SRVTYPE": t,
                "SRVNUM": n,
                "PORT": next(ports),
                "EXE": "oio-" + t + "-server",
                "EXTRA": ext_opt,
            }
        )
        if service_id:
            env["WANT_SERVICE_ID"] = ""
            env["SERVICE_ID"] = "{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
            env["OPTARGS"] = "-O ServiceId=%s" % env["SERVICE_ID"]
        else:
            env["WANT_SERVICE_ID"] = "#"
            env["OPTARGS"] = ""
        register_service(env, tpl, parent_target)
        # watcher
        tpl = Template(template_meta_watch)
        with open(watch(env), "w+") as f:
            f.write(tpl.safe_substitute(env))

        if t == "meta2":
            meta2_volumes.append("{DATADIR}/{NS}-{SRVTYPE}-{SRVNUM}".format(**env))

    # meta0
    nb_meta0 = max(
        getint(options["meta0"].get(SVC_NB), defaults["NB_M0"]), meta1_replicas
    )
    if nb_meta0:
        meta0_target = register_target("meta0", root_target)
        for i in range(nb_meta0):
            generate_meta(
                "meta0",
                i + 1,
                template_systemd_service_meta,
                meta0_target,
                options["meta0"].get(SVC_PARAMS, ""),
            )

    # meta1
    nb_meta1 = max(
        getint(options["meta1"].get(SVC_NB), defaults["NB_M1"]), meta1_replicas
    )
    if nb_meta1:
        meta1_target = register_target("meta1", root_target)
        for i in range(nb_meta1):
            generate_meta(
                "meta1",
                i + 1,
                template_systemd_service_meta,
                meta1_target,
                options["meta1"].get(SVC_PARAMS, ""),
            )

    # meta2
    nb_meta2 = max(
        getint(options["meta2"].get(SVC_NB), defaults["NB_M2"]), meta2_replicas
    )
    if nb_meta2:
        meta2_target = register_target("meta2", root_target)
        for i in range(nb_meta2):
            generate_meta(
                "meta2",
                i + 1,
                template_systemd_service_meta,
                meta2_target,
                options["meta2"].get(SVC_PARAMS, ""),
                service_id=options["with_service_id"],
            )

    # oio-meta2-indexer
    _tmp_env = subenv(
        {
            "META2_VOLUMES": ",".join(meta2_volumes),
            "SRVTYPE": "meta2-indexer",
            "SRVNUM": 1,
            "GROUPTYPE": "indexer",
            "EXE": "oio-meta2-indexer",
        }
    )
    indexer_target = register_target("indexer", root_target)
    crawler_target = register_target("crawler", root_target)
    # first the conf
    tpl = Template(template_meta2_indexer_service)
    to_write = tpl.safe_substitute(_tmp_env)
    path = "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf".format(**_tmp_env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(
        _tmp_env, template_systemd_service_meta2_indexer, indexer_target, False
    )

    # oio-meta2-crawler
    _tmp_env = subenv(
        {
            "META2_VOLUMES": ",".join(meta2_volumes),
            "SRVTYPE": "meta2-crawler",
            "SRVNUM": "1",
            "GROUPTYPE": "crawler",
            "EXE": "oio-meta2-crawler",
        }
    )
    # first the conf
    tpl = Template(template_meta2_crawler_service)
    to_write = tpl.safe_substitute(_tmp_env)
    path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**_tmp_env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(
        _tmp_env, template_systemd_service_meta2_crawler, crawler_target, False
    )

    # oio-meta2-placement-checker-crawler
    _tmp_env = subenv(
        {
            "META2_VOLUMES": ",".join(meta2_volumes),
            "SRVTYPE": "meta2-crawler",
            "SRVNUM": "2",
            "GROUPTYPE": "crawler",
            "EXE": "oio-meta2-crawler",
        }
    )
    # first the conf
    tpl = Template(template_meta2_placement_checker_crawler_service)
    to_write = tpl.safe_substitute(_tmp_env)
    path = "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf".format(**_tmp_env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(
        _tmp_env,
        template_systemd_service_placement_checker_crawler,
        None,
        False,
    )

    # RAWX
    srvtype = "rawx"
    nb_rawx = getint(options[srvtype].get(SVC_NB), defaults["NB_RAWX"])
    if nb_rawx:
        rawx_volumes = []
        rawx_target = register_target("rawx", root_target)
        for i in range(nb_rawx):
            env = subenv(
                {
                    "SRVTYPE": srvtype,
                    "SRVNUM": i + 1,
                    "EXE": "oio-rawx",
                    "PORT": next(ports),
                    "COMPRESSION": ENV["COMPRESSION"] if i % 2 else "off",
                    "EXTRASLOT": ("rawx-even" if i % 2 else "rawx-odd"),
                    "FSYNC": ("enabled" if options[FSYNC_RAWX] else "disabled"),
                    "HASH_WIDTH": defaults[HASH_WIDTH],
                    "HASH_DEPTH": defaults[HASH_DEPTH],
                }
            )
            rawx_volumes.append(env["VOLUME"])
            env["SERVICE_ID"] = "{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
            if options.get("use_tls", False):
                env["TLS_CERT_FILE"] = ENV["TLS_CERT_FILE"]
                env["TLS_KEY_FILE"] = ENV["TLS_KEY_FILE"]
                env["TLS_PORT"] = next(ports)
                env["USE_TLS"] = ""
            else:
                env["USE_TLS"] = "#"
            register_service(
                env,
                template_systemd_service_rawx % template_systemd_rawx_command_options,
                rawx_target,
            )

            # service
            tpl = Template(template_rawx_service)
            to_write = tpl.safe_substitute(env)
            with open(httpd_config(env), "w+") as f:
                f.write(to_write)
            # watcher
            tpl = Template(template_rawx_watch)
            to_write = tpl.safe_substitute(env)
            with open(watch(env), "w+") as f:
                f.write(to_write)

        # oio-rdir-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "rdir-crawler",
                "EXE": "oio-rdir-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
                "HASH_WIDTH": defaults[HASH_WIDTH],
                "HASH_DEPTH": defaults[HASH_DEPTH],
            }
        )
        # first the conf
        tpl = Template(template_rdir_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        register_service(
            env, template_systemd_service_rdir_crawler, crawler_target, False
        )

        # oio-rawx-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "rawx-crawler",
                "EXE": "oio-rawx-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
            }
        )
        tpl = Template(template_rawx_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        tpl = Template(template_systemd_service_rawx_crawler)
        register_service(
            env, template_systemd_service_rawx_crawler, crawler_target, False
        )

        # oio-checksum-checker-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "checksum-checker-crawler",
                "EXE": "oio-rawx-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
            }
        )
        tpl = Template(template_checksum_checker_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        tpl = Template(template_systemd_service_checksum_checker_crawler)
        register_service(
            env,
            template_systemd_service_checksum_checker_crawler,
            crawler_target,
            False,
        )

        # oio-placement-improver-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "placement-improver-crawler",
                "EXE": "oio-placement-improver-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
            }
        )
        tpl = Template(template_placement_improver_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        tpl = Template(template_systemd_service_placement_improver_crawler)
        register_service(
            env,
            template_systemd_service_placement_improver_crawler,
            crawler_target,
            False,
        )
    # redis
    if options.get(ALLOW_REDIS):
        redis_server = shutil.which("redis-server")
        env = subenv(
            {
                "SRVTYPE": "redis",
                "SRVNUM": 1,
                "PORT": 6379,
                "redis_server": redis_server,
            }
        )
        register_service(env, template_systemd_service_redis, root_target)
        with open(config(env), "w+") as f:
            tpl = Template(template_redis)
            f.write(tpl.safe_substitute(env))
        with open(config(env), "w+") as f:
            tpl = Template(template_redis)
            f.write(tpl.safe_substitute(env))
        with open(watch(env), "w+") as f:
            tpl = Template(template_redis_watch)
            f.write(tpl.safe_substitute(env))

    # foundationdb
    srvtype = "foundationdb"
    env = subenv(
        {
            "SRVTYPE": srvtype,
            "SRVNUM": 1,
            "EXE": "fdbmonitor",
            "PORT": 4600,
            "DESCRIPTION": "".join([choice(ascii_letters + digits) for _ in range(8)]),
            "RANDOMSTR": "".join([choice(ascii_letters + digits) for _ in range(8)]),
        }
    )
    cluster_file = cluster(env)
    env.update({"CLUSTERFILE": cluster_file})

    fdbserver = shutil.which("fdbserver")
    backup_agent = shutil.which(
        "backup_agent", path=PATH + ":" + "/usr/lib/foundationdb/backup_agent"
    )
    fdbcli = shutil.which("fdbcli")
    fdbmonitor = shutil.which("fdbmonitor", path=PATH + ":" + "/usr/lib/foundationdb")

    env.update({"fdbserver": fdbserver})
    env.update({"backup_agent": backup_agent})
    env.update({"fdbcli": fdbcli})
    env.update({"fdbmonitor": fdbmonitor})

    if options.get(ALLOW_FDB):
        register_service(env, template_systemd_service_foundationdb, root_target)
        with open(config(env), "w+") as f:
            tpl = Template(template_foundationdb)
            f.write(tpl.safe_substitute(env))
        with open(watch(env), "w+") as f:
            tpl = Template(template_foundationdb_watch)
            f.write(tpl.safe_substitute(env))
        with open(cluster_file, "w+") as f:
            tpl = Template(template_foundationdb_cluster)
            f.write(tpl.safe_substitute(env))

    # proxy
    env = subenv(
        {
            "SRVTYPE": "proxy",
            "SRVNUM": 1,
            "PORT": port_proxy,
            "EXE": "oio-proxy",
            "LOC": ENV["LOC_PROXYD"],
        }
    )
    register_service(env, template_systemd_service_proxy, root_target)

    with open(watch(env), "w+") as f:
        tpl = Template(template_proxy_watch)
        f.write(tpl.safe_substitute(env))

    # account
    env = subenv(
        {
            "SRVTYPE": "account",
            "SRVNUM": 1,
            "PORT": port_account,
            "EXE": "oio-account-server",
        }
    )
    if options.get(ALLOW_FDB):
        cluster_file = cluster(env)
        env.update({"CLUSTERFILE": cluster_file})
    register_service(env, template_systemd_service_account, root_target)
    with open(config(env), "w+") as f:
        tpl = Template(template_account)
        f.write(tpl.safe_substitute(env))
    if not options.get(REMOTE_ACCOUNT):
        with open(watch(env), "w+") as f:
            tpl = Template(template_account_watch)
            f.write(tpl.safe_substitute(env))

    # rdir
    nb_rdir = getint(options["rdir"].get(SVC_NB), 3)
    rdir_target = register_target("rdir", root_target)
    for num in range(nb_rdir):
        env = subenv(
            {
                "SRVTYPE": "rdir",
                "SRVNUM": num + 1,
                "PORT": next(ports),
                "EXE": "oio-rdir-server",
            }
        )
        env["SERVICE_ID"] = "{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
        register_service(env, template_systemd_service_rdir, rdir_target)
        with open(config(env), "w+") as f:
            tpl = Template(template_rdir)
            f.write(tpl.safe_substitute(env))
        with open(watch(env), "w+") as f:
            tpl = Template(template_rdir_watch)
            f.write(tpl.safe_substitute(env))

    # For testing purposes, some events must go to the main queue
    if all_beanstalkd:
        _, host, port = all_beanstalkd[0]
        ENV["MAIN_QUEUE_URL"] = "beanstalk://{0}:{1}".format(host, port)

    event_target = register_target("event", root_target)
    conscience_agents_target = register_target("event-agent", event_target)
    xcute_agents_target = register_target("xcute-event-agent", event_target)

    # Event agent configuration -> one per beanstalkd
    for num, host, port in all_beanstalkd:
        bnurl = "beanstalk://{0}:{1}".format(host, port)

        env = subenv(
            {
                "SRVTYPE": "event-agent",
                "SRVNUM": num,
                "QUEUE_URL": bnurl,
                "EXE": "oio-event-agent",
            }
        )
        register_service(
            env, template_systemd_service_event_agent, conscience_agents_target
        )
        with open(config(env), "w+") as f:
            tpl = Template(template_event_agent)
            f.write(tpl.safe_substitute(env))
        with open(CFGDIR + "/event-handlers-" + str(num) + ".conf", "w+") as f:
            tpl = Template(template_event_agent_handlers)
            f.write(tpl.safe_substitute(env))

        env = subenv(
            {
                "SRVTYPE": "xcute-event-agent",
                "SRVNUM": num,
                "QUEUE_URL": bnurl,
                "EXE": "oio-event-agent",
            }
        )
        register_service(
            env, template_systemd_service_xcute_event_agent, xcute_agents_target, False
        )
        with open(config(env), "w+") as f:
            tpl = Template(template_xcute_event_agent)
            f.write(tpl.safe_substitute(env))
        with open(CFGDIR + "/xcute-event-handlers-" + str(num) + ".conf", "w+") as f:
            tpl = Template(template_xcute_event_agent_handlers)
            f.write(tpl.safe_substitute(env))

    # xcute
    env = subenv(
        {
            "SRVTYPE": "xcute",
            "SRVNUM": 1,
            "PORT": next(ports),
            "REDIS_PORT": 6379,
            "QUEUE_URL": bnurl,
            "EXE": "oio-xcute",
        }
    )
    register_service(env, template_systemd_service_xcute, root_target)
    with open(config(env), "w+") as f:
        tpl = Template(template_xcute)
        f.write(tpl.safe_substitute(env))
    with open(watch(env), "w+") as f:
        tpl = Template(template_xcute_watch)
        f.write(tpl.safe_substitute(env))

    # billing buckets
    crawler_target = register_target("billing", root_target)
    env = subenv(
        {
            "SRVTYPE": "billing-agent",
            "GROUPTYPE": "billing",
            "EXE": "oio-billing-agent",
            "SRVNUM": 1,
        }
    )
    cluster_file = cluster(env)
    env.update({"CLUSTERFILE": cluster_file})
    tpl = Template(template_billing_agent_service)
    to_write = tpl.safe_substitute(env)
    path = "{CFGDIR}/{SRVTYPE}.conf".format(**env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(env, template_systemd_service_billing_agent, crawler_target, False)

    # blob-rebuilder configuration -> one per beanstalkd
    rebuilder_target = register_target("blob-rebuilder", root_target)
    for num, host, port in all_beanstalkd:
        bnurl = "beanstalk://{0}:{1}".format(host, port)
        env = subenv(
            {
                "SRVTYPE": "blob-rebuilder",
                "SRVNUM": num,
                "QUEUE_URL": bnurl,
                "EXE": "oio-blob-rebuilder",
            }
        )
        register_service(env, template_systemd_service_blob_rebuilder, rebuilder_target)

    # webhook test server
    if WEBHOOK:
        env = subenv(
            {
                "SRVTYPE": "webhook",
                "SRVNUM": 1,
                "PORT": 9081,
                "EXE": "oio-webhook-test.py",
            }
        )
        register_service(env, template_systemd_service_webhook_server, root_target)

    # Conscience agent configuration
    env = subenv({"SRVTYPE": "conscience-agent", "SRVNUM": 1})
    with open(CFGDIR + "/" + "conscience-agent.yml", "w+") as f:
        tpl = Template(template_conscience_agent)
        f.write(tpl.safe_substitute(env))

    env = subenv(
        {"SRVTYPE": "conscience-agent", "SRVNUM": 1, "EXE": "oio-conscience-agent"}
    )
    cluster_file = cluster(env)
    env.update({"CLUSTERFILE": cluster_file})
    register_service(env, template_systemd_service_ns, root_target, False)

    # system config
    with open("{OIODIR}/sds.conf".format(**ENV), "w+") as f:
        env = merge_env({"IP": hosts[0], "REDIS_PORT": 6379})
        cluster_file = cluster(env)
        env.update({"CLUSTERFILE": cluster_file})
        tpl = Template(template_local_header)
        f.write(tpl.safe_substitute(env))
        tpl = Template(template_local_ns)
        f.write(tpl.safe_substitute(env))
        # Now dump the configuration
        for k, v in iteritems(options["config"]):
            strv = str(v)
            if isinstance(v, bool):
                strv = strv.lower()
            f.write("{0}={1}\n".format(k, strv))

    for _, v in targets.items():
        generate_target(v)

    # ensure volumes for srvtype in final_services:
    for srvtype in final_services:
        for rec in final_services[srvtype]:
            if "path" in rec:
                mkdir_noerror(rec["path"])
            if "path" in rec and "addr" in rec:
                cmd = (
                    "oio-tool",
                    "init",
                    rec["path"],
                    ENV["NS"],
                    srvtype,
                    rec.get("service_id", rec["addr"]),
                )
                import subprocess

                subprocess.check_call(cmd)

    final_conf["services"] = final_services
    final_conf["namespace"] = ns
    final_conf["storage_policy"] = stgpol
    final_conf["account"] = "test_account"
    final_conf["sds_path"] = SDSDIR
    # TODO(jfs): remove this line only required by some tests cases
    final_conf["chunk_size"] = options["config"]["ns.chunk_size"]
    final_conf["proxy"] = final_services["proxy"][0]["addr"]
    final_conf[M2_REPLICAS] = meta2_replicas
    final_conf[M1_REPLICAS] = meta1_replicas
    final_conf[M1_DIGITS] = meta1_digits
    final_conf["compression"] = compression
    for k in (
        APPLICATION_KEY,
        BUCKET_NAME,
        ACCOUNT_ID,
        PORT_START,
        PROFILE,
        MONITOR_PERIOD,
    ):
        if k in ENV:
            final_conf[k] = ENV[k]
        elif k in defaults:
            final_conf[k] = defaults[k]
    final_conf["config"] = options["config"]
    final_conf["with_service_id"] = options["with_service_id"]
    final_conf["random_service_id"] = bool(options["random_service_id"])
    final_conf["webhook"] = WEBHOOK_ENDPOINT
    final_conf["use_tls"] = bool(options.get("use_tls"))
    with open("{CFGDIR}/test.yml".format(**ENV), "w+") as f:
        f.write(yaml.dump(final_conf))
    return final_conf


def dump_config(conf):
    print("PROXY=%s" % conf["proxy"])
    print("REPLI_CONTAINER=%s" % conf[M2_REPLICAS])
    print("REPLI_DIRECTORY=%s" % conf[M1_REPLICAS])
    print("M1_DIGITS=%s" % conf[M1_DIGITS])


def merge_config(base, inc):
    for k, v in iteritems(inc):
        if isinstance(v, dict):
            if k not in base:
                base[k] = v
            elif isinstance(base[k], dict):
                base[k] = merge_config(base[k], v)
            else:
                raise Exception("What the fuck!? You fucking basterd!")
        else:
            base[k] = v
    return base


def main():
    if COVERAGE:
        global template_systemd_rawx_command_options
        template_systemd_rawx_command_options = (
            "-test.coverprofile "
            "${HOME}/go_coverage.output.${NS}.${SRVTYPE}.${SRVNUM}.${IP}.${PORT} "
            "-test.syslog OIO,${NS},${SRVTYPE},${SRVNUM} "
            "-test.conf ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.httpd.conf"
        )

    parser = argparse.ArgumentParser(description="OpenIO bootstrap tool")
    parser.add_argument(
        "-c",
        "--conf",
        action="append",
        dest="config",
        help="Bootstrap configuration file",
    )
    parser.add_argument(
        "-d",
        "--dump",
        action="store_true",
        default=False,
        dest="dump_config",
        help="Dump results",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=6000,
        help="Specify the first port of the range",
    )

    parser.add_argument(
        "-u",
        "--with-service-id",
        action="store_true",
        default=False,
        help="generate service IDs for services supporting them",
    )
    parser.add_argument(
        "--random-service-id",
        action="store_true",
        default=False,
        help="generate services service IDs randomly (implies --with--service-id)",
    )
    parser.add_argument(
        "--region",
        "-r",
        default="localhost",
        help="Specify the region the namespace is running in",
    )

    parser.add_argument(
        "--profile",
        choices=["default", "valgrind", "callgrind"],
        help="Launch SDS with specific tool",
    )
    parser.add_argument(
        "-D",
        "--data",
        action="store",
        type=str,
        default=None,
        help="Specify a DATA directory",
    )
    parser.add_argument(
        "namespace", action="store", type=str, default=None, help="Namespace name"
    )
    parser.add_argument(
        "ip", metavar="<ip>", nargs="*", help="set of IP to use (repeatable option)"
    )

    opts = {}
    opts["config"] = {}
    opts["config"]["proxy.cache.enabled"] = False
    opts["config"]["ns.chunk_size"] = 1024 * 1024
    opts[ZOOKEEPER] = False
    opts[REMOTE_ACCOUNT] = False
    opts["conscience"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["meta0"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["meta1"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["meta2"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["rawx"] = {SVC_NB: None, SVC_HOSTS: None}
    opts[GO_RAWX] = False
    opts[FSYNC_RAWX] = False
    opts["rdir"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["beanstalkd"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["rabbitmq"] = {}

    options = parser.parse_args()

    if options.data:
        opts["DATADIR"] = options.data

    if options.config:
        for path in options.config:
            with open(path, "r") as infile:
                data = yaml.load(infile, Loader=yaml.Loader)
                if data:
                    opts = merge_config(opts, data)

    opts["port"] = int(options.port)
    opts["with_service_id"] = options.with_service_id or options.random_service_id
    opts["random_service_id"] = options.random_service_id
    opts["config"]["ns.region"] = options.region

    # Remove empty strings, then apply the default if no value remains
    options.ip = [str(x) for x in options.ip if x]
    if len(options.ip) > 0:
        opts[SVC_HOSTS] = tuple(options.ip)

    opts["ZK"] = os.environ.get("ZK", defaults["ZK"])
    opts["ns"] = options.namespace
    opts[PROFILE] = options.profile
    final_conf = generate(opts)
    if options.dump_config:
        dump_config(final_conf)


if __name__ == "__main__":
    main()
