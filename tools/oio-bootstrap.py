#!/usr/bin/env python3

# oio-bootstrap.py
# Copyright (C) 2015 Conrad Kleinespel
# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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
from string import ascii_letters, digits, Template
import sys
import argparse
from collections import namedtuple
import shutil
from urllib.parse import parse_qsl, urlsplit, urlunsplit

C_LANG_SERVICES = (
    "oio-daemon",
    "oio-meta0-server",
    "oio-meta1-server",
    "oio-meta2-server",
    "oio-proxy",
    "oio-rdir-server",
)

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
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${redis_server} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""
template_systemd_service_beanstalkd = """
[Unit]
Description=[OpenIO] Service beanstalkd ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=/usr/bin/beanstalkd -l ${IP} -p ${PORT} -b ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM} -f 1000 -s 10240000
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

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
restart_delay = 15
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
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
Environment=PATH=${PATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
#ExecStartPre=/usr/sbin/service foundationdb stop
ExecStart=${fdbmonitor} --conffile ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf --lockfile ${RUNDIR}/${NS}-${SRVTYPE}-${SRVNUM}.pid
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
ExecStartPost=/bin/sleep 5 ; ${fdbcli} -C ${CLUSTERFILE} --exec "configure new ssd single"
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_account = """
[Unit]
Description=[OpenIO] Service account
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_kms = """
[Unit]
Description=[OpenIO] Service KMS (KMSAPI Mock Server)
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_xcute = """
[Unit]
Description=[OpenIO] Service xcute ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_billing_agent = """
[Unit]
Description=[OpenIO] Service billing agent
PartOf=${PARENT}
OioGroup=${GROUPTYPE},${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_rdir = """
[Unit]
Description=[OpenIO] Service rdir ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_statsd = """
[Unit]
Description=[OpenIO] Fake statsd server
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${STATSD_PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=bash -c "nc -kuld ${IP} ${STATSD_PORT} | sed -E -e 's/(\\|c|\\|s|\\|ms|\\|g)(.)/\\1\\\\n\\2/g' > ${DATADIR}/statsd_${STATSD_PORT}.txt"
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_proxy = """
[Unit]
Description=[OpenIO] Service proxy ${SRVNUM}
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
NotifyAccess=main
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=${EXE} -s OIO,${NS},proxy ${IP}:${PORT} ${NS}
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_meta2_crawler_service = """
[meta2-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${META2_VOLUMES}

wait_random_time_before_starting = True
use_eventlet = True
use_marker = False
interval = 1200
report_interval = 300
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300

log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger check_integrity draining auto_vacuum auto_sharding indexer copy_cleaner

[filter:indexer]
use = egg:oio#indexer
check_orphan = True
remove_orphan = False

[filter:auto_sharding]
use = egg:oio#auto_sharding
sharding_db_size = 104857600
sharding_strategy = shard-with-partition
sharding_threshold = 1000
sharding_partition = 50,50
sharding_preclean_new_shards = True
sharding_preclean_timeout = 60
sharding_replicated_clean_timeout = 30
sharding_create_shard_timeout = 60
sharding_save_writes_timeout = 60
shrinking_db_size = 26214400
sharding_step_timeout = 960

[filter:auto_vacuum]
use = egg:oio#auto_vacuum
min_waiting_time_after_last_modification = 30
soft_max_unused_pages_ratio = 0.1
hard_max_unused_pages_ratio = 0.2

[filter:check_integrity]
use = egg:oio#check_integrity

[filter:draining]
use = egg:oio#draining
drain_limit = 1000
drain_limit_per_pass = 100000
kafka_cluster_health_metrics_endpoints = ${KAFKA_METRICS_URL}
kafka_cluster_health_topics = oio,oio-chunks,oio-delete-*

[filter:copy_cleaner]
use = egg:oio#copy_cleaner
keywords = VerifyChunkPlacement-
delay = 172800

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
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
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

template_meta2_lifecycle_crawler_service = """
[meta2-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${META2_VOLUMES}

wait_random_time_before_starting = False
use_eventlet = True
use_marker = False
interval = 300
report_interval = 300
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300

log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}

[pipeline:main]
pipeline = logger lifecycle

[filter:lifecycle]
use = egg:oio#lifecycle
lifecycle_batch_size = 5000
redis_host = ${IP}:${REDIS_PORT}
# Lifecycle backup
lifecycle_configuration_backup_account = AUTH_demo
lifecycle_configuration_backup_bucket = lc-bucket

[filter:logger]
use = egg:oio#logger
"""

template_placement_improver_crawler_service = """
[rawx-crawler]
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
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}
working_dir = non_optimal_placement

[pipeline:main]
pipeline = logger changelocation

[filter:logger]
use = egg:oio#logger

[filter:changelocation]
use = egg:oio#changelocation
# Minimum time after the creation of non optimal symlink before
# improver process it, to make sure that all meta2 entry are updated.
# By default equals to 300 seconds.
min_delay_secs = 300
# Delay in second before next attempt by the improver to move
# a chunk that we were not able to move at previous pass.
# first attempt -> 15 min
# second attempt -> 30 min
# third attempt -> 1h
# fourth attempt -> 2h
# fifth attempt -> 2h
# sixth attempt -> 2h ...
new_attempt_delay = 900
# Time interval after which service data are updated
service_update_interval = 3600
"""

template_rdir_crawler_service = """
[rdir-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${VOLUMES}
volume_type = ${VOLUME_TYPE}

# How many hexdigits must be used to name the indirection directories
hash_width = ${HASH_WIDTH}
# How many levels of directories are used to store chunks
hash_depth = ${HASH_DEPTH}

wait_random_time_before_starting = True
interval = 1200
report_interval = 300
items_per_second = 10
conscience_cache = 30
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}
"""

template_rawx_crawler_service = """
[rawx-crawler]
namespace = ${NS}
user = ${USER}
volume_list = ${RAWX_VOLUMES}

wait_random_time_before_starting = True
use_eventlet = True
use_marker = False
interval = 1200
report_interval = 300
scanned_per_second = 10
# represents 30 seconds at max rate
# scanned_between_markers = 300
log_level = INFO
log_facility = LOG_LOCAL0
log_address = /dev/log
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}
excluded_dirs = non_optimal_placement, orphans

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

# How many hexdigits must be used to name the indirection directories
hash_width = ${HASH_WIDTH}
# How many levels of directories are used to store chunks
hash_depth = ${HASH_DEPTH}

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
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
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

template_cleanup_orphaned_crawler_service = """
[rawx-crawler]
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
statsd_host = ${STATSD_HOST}
statsd_port = ${STATSD_PORT}
syslog_prefix = OIO,${NS},${SRVTYPE}
working_dir = orphans

[pipeline:main]
pipeline = logger cleanup_orphaned

[filter:cleanup_orphaned]
use = egg:oio#cleanup_orphaned
# Delay in seconds we have to wait before deleting an orphan chunk
delete_delay = 604800
# Delay in second before next attempt to check orphan chunk location
# first attempt -> 15 min
# second attempt -> 30 min
# third attempt -> 1h
# fourth attempt -> 2h
# fifth attempt -> 2h
# sixth attempt -> 2h ...
new_attempt_delay = 900
# Time interval after which service data are updated
service_update_interval = 3600

[filter:logger]
use = egg:oio#logger
"""

template_lifecycle_collector_service = """
[checkpoint-collector]
namespace = ${NS}
user = ${USER}
concurrency = 1
endpoint = ${EVENT_CNXSTRING}
topic = oio-lifecycle-checkpoint
redis_host = ${IP}:${REDIS_PORT}

lifecycle_configuration_backup_account = AUTH_demo
lifecycle_configuration_backup_bucket = lc-bucket

"""

template_rawx_service = """
listen ${IP}:${PORT}

docroot           ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
namespace         ${NS}
${WANT_SERVICE_ID}service_id        ${SERVICE_ID}

statsd_addr       ${STATSD_ADDR}

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
# Event log
log_event_format "level_name:INFO	X-OVH-TOKEN:my_token	topic:{{ .Topic }}	event:{{ .Event }}"

# Don't know why, but there is a risk our test suites do not pass
# if we set a lower number of connections.
max_connections 80
shallow_copy ${SHALLOW_COPY}
#tcp_keepalive disabled
#timeout_read_header 10
#timeout_read_request 10
#timeout_write_reply 30
#timeout_idle 10
#headers_buffer_size 32768

${USE_TLS}tls_cert_file ${SRCDIR}/${TLS_CERT_FILE}
${USE_TLS}tls_key_file ${SRCDIR}/${TLS_KEY_FILE}
${USE_TLS}tls_rawx_url ${IP}:${TLS_PORT}

events true
topic  ${TOPIC}
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

template_account_xcute_watch = """
host: ${IP}
port: ${PORT}
type: ${SRVTYPE}
location: ${LOC}
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
internal_port: ${INTERNAL_PORT}
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
service_id: ${SERVICE_ID}
checks:
    - {type: tcp}
slots:
    - oioproxy
stats:
    - {type: oioproxy}
    - {type: system}
    - {type: static, stats: {"pi": 3.14}, tags: {"stateless": true}}
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
[Server.conscience]
listen=${IP}:${PORT}

[Plugin.conscience]
param_namespace=${NS}

# Multi-conscience
param_hub.me=tcp://${IP}:${PORT_HUB}
param_hub.group=${CS_ALL_HUB}
# When a service is locked, but has not been updated for a while,
# publish it on the inter-conscience hub.
# Minimum 5 seconds, set to 0 to disable the feature.
param_hub.publish_stale_delay=15
# Number of seconds to wait before starting serving requests
param_hub.startup_delay=1
# Number of threads dealing with inter-conscience messages
# (set to 0 to disable the thread pool)
param_hub.threads=${CS_HUB_THREADS}

flush_stats_on_refresh=True

service_cache.enable=${CS_CACHE_SERVICES}
service_cache.enable_full=${CS_CACHE_SERVICES}
service_cache.interval=0.5

# When starting, if an inter-conscience hub is configured,
# try to load a full list of services from another conscience.
synchronize_at_startup=true

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
EC=NONE:E63
EC21=NONE:E21
ECX21=NONE:EX21

JUSTENOUGH=justenoughrawx:E63
NOTENOUGH=notenoughrawx:E63
ANY-E93=rawx_12:E93

[DATA_SECURITY]
# Data security definitions
# --------------------------
#
# The first word is the kind of data security ("plain" or "ec"),
# after the '/' are the parameters of the data security.

DUPONETWO=plain/min_dist=1,nb_copy=2
DUPONETHREE=plain/max_dist=2,min_dist=1,nb_copy=3
DUP17=plain/min_dist=1,nb_copy=17

E93=ec/k=9,m=3,algo=liberasurecode_rs_vand,min_dist=1
E63=ec/k=6,m=3,algo=liberasurecode_rs_vand,min_dist=1
E21=ec/k=2,m=1,algo=liberasurecode_rs_vand,min_dist=1,warn_dist=${WARN_DIST}
EX21=ec/k=2,m=1,algo=liberasurecode_rs_vand,min_dist=0,max_dist=2,warn_dist=0

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
# These values have been chosen for testing purposes
fair_location_constraint = 2.2.1.1
strict_location_constraint = ${M2_REPLICAS}.${M2_REPLICAS}.${M2_REPLICAS}.1

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

# Special pools for placement tests
[pool:rawx_12]
targets=12,rawx
min_dist=1
max_dist=3
fair_location_constraint=12.12.3.1
strict_location_constraint=12.12.4.1
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
put_score_expr=(num tag.up) * root(4, (pow(2, (clamp((((num stat.space) - 1) * 1.010101), 0, 100))) * clamp((((num stat.cpu) - 5) * 6.666667), 1, 100) * clamp((((num stat.io) - 5) * 1.333333), 1, 100)))
get_score_expr=(num tag.up) * root(2, (clamp((((num stat.cpu) - 5) * 6.666667), 0, 100) * clamp((((num stat.io) - 5) * 1.333333), 0, 100)))
score_timeout=120
score_variation_bound=50

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
put_score_expr=root(4, (pow(2, (clamp((((num stat.space) - 20) * 1.25), 0, 100))) * clamp((((num stat.cpu) - 5) * 6.666667), 1, 100) * clamp((((num stat.io) - 5) * 1.333333), 1, 100))) * (num stat.unknown_stat:"1")
get_score_expr=root(2, (clamp((((num stat.cpu) - 5) * 6.666667), 0, 100) * clamp((((num stat.io) - 5) * 1.333333), 0, 100))) * (num stat.unknown_stat:"1")
score_timeout=10
score_variation_bound=50
lock_at_first_register=false

[type:oioproxy]
score_expr=(1 + (num stat.cpu))
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
OioGroup=${NS},conscience,conscience-agent

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/conscience-agent.yml
Environment=LD_LIBRARY_PATH=${LIBDIR}
Environment=PYTHONPATH=${PYTHONPATH}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_conscience = """
[Unit]
Description=[OpenIO] Service conscience ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} -O PersistencePath=${DATADIR}/${NS}-conscience-${SRVNUM}/conscience.dat -O PersistencePeriod=15 -s OIO,${NS},cs,${SRVNUM} ${CFGDIR}/${NS}-conscience-${SRVNUM}.conf
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

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
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} -s OIO,${NS},${SRVTYPE},${SRVNUM} -O Endpoint=${IP}:${PORT} ${OPTARGS} ${EXTRA} ${NS} ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_meta2_crawler = """
[Unit]
Description=[OpenIO] Service meta2 crawler
After=network.target
PartOf=${PARENT}
OioGroup=${NS},crawler,meta2-crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_lifecycle_crawler = """
[Unit]
Description=[OpenIO] Service lifecycle crawler
After=network.target
PartOf=${PARENT}
OioGroup=${NS},crawler,meta2-crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_placement_checker_crawler = """
[Unit]
Description=[OpenIO] Service meta2 crawler to check chunks placement
After=network.target
OioGroup=${NS},crawler,meta2-crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=oneshot
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
"""

template_systemd_service_rdir_crawler = """
[Unit]
Description=[OpenIO] Service rdir crawler
PartOf=${PARENT}
OioGroup=${NS},crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_rawx_crawler = """
[Unit]
Description=[OpenIO] Service rawx crawler
PartOf=${PARENT}
OioGroup=${NS},crawler,rawx-crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_cleanup_orphaned_crawler = """
[Unit]
Description=[OpenIO] Service cleanup orphaned crawler
After=network.target
PartOf=${PARENT}
OioGroup=${NS},crawler,rawx-crawler,${SRVTYPE}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}.conf
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_rawx_command_options = (
    "-s OIO,${NS},${SRVTYPE},${SRVNUM} "
    "-f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.httpd.conf"
)

template_systemd_service_rawx = """
[Unit]
Description=[OpenIO] Service rawx ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} %s
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}
${SET_NICE}Nice=${NICE}
${SET_IONICE}IOSchedulingClass=${IO_SCHEDULING_CLASS}
${SET_IONICE}IOSchedulingPriority=${IO_SCHEDULING_PRIORITY}

[Install]
WantedBy=${PARENT}
"""

template_systemd_service_httpd = """
[Unit]
Description=[OpenIO] Service ${SRVTYPE} ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${HTTPD_BINARY} -D FOREGROUND -f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.httpd.conf -E /tmp/httpd-startup-failures.log
ExecStartPost=/usr/bin/timeout 30 sh -c 'while ! ss -H -t -l -n sport = :${PORT} | grep -q "^LISTEN.*:${PORT}"; do sleep 1; done'
Environment=PATH=${PATH}
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

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
${NOBS}beanstalk=${BEANSTALK_CNXSTRING}

core.lb.try_fair_constraints_first=true

ns.meta1_digits=${M1_DIGITS}

# Small pagination to avoid time-consuming tests
meta2.flush_limit=64
meta2.sharding.max_entries_merged=10
meta2.sharding.max_entries_cleaned=10

# Lifecycle
lifecycle.redis_host=${IP}:${REDIS_PORT}

admin=${IP}:${PORT_ADMIN}
"""

template_meta_config = """
[${NS}]
events.kafka.options=client.id=${SERVICE_ID}
"""

template_systemd_service_event_agent = """
[Unit]
Description=[OpenIO] Service event agent ${SRVNUM}
After=network.target
PartOf=${PARENT}
OioGroup=${NS},event

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_event_agent = """
[event-agent]
namespace = ${NS}
user = ${USER}
workers = ${EVENT_WORKERS}
concurrency = 5

handlers_conf = ${HANDLER_CONF}

log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}

broker_endpoint = ${QUEUE_URL}
topic = ${QUEUE_NAME}
group_id = ${GROUP_ID}
event_queue_type = ${QUEUE_TYPE}
event_queue_ids = ${QUEUE_IDS}

kafka_consumer_group.instance.id = ${SRVTYPE}.${SRVNUM}

rdir_connection_timeout = 0.5
rdir_read_timeout = 5.0

${TCP_CORK_COMMENT}use_tcp_cork = ${TCP_CORK}
"""

template_event_agent_handlers = """
[handler:storage.content.new]
pipeline = ${REPLICATION} ${WEBHOOK} ${PRESERVE}

[handler:storage.content.update]
pipeline = ${REPLICATION} ${WEBHOOK} ${PRESERVE}

[handler:storage.content.append]
pipeline = ${WEBHOOK} ${PRESERVE}

[handler:storage.content.broken]
pipeline = content_rebuild ${PRESERVE}

[handler:storage.content.deleted]
# New pipeline with a separate oio-event-agent doing deletions
pipeline = ${WEBHOOK} notify_deleted

[handler:storage.content.drained]
pipeline = notify_deleted

[handler:storage.container.new]
pipeline = account_update ${PRESERVE}

[handler:storage.container.update]
pipeline = account_update ${PRESERVE}

[handler:storage.container.deleted]
pipeline = account_update ${PRESERVE}

[handler:storage.container.state]
pipeline = account_update ${PRESERVE}

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
broker_endpoint = ${QUEUE_URL}
topic = oio-rebuild

[filter:account_update]
use = egg:oio#account_update
connection_timeout=1.0
read_timeout=15.0
features_whitelist=lifecycle,website,replication,cors

[filter:volume_index]
use = egg:oio#volume_index
retry_delay = 5
write_quorum = 0

[filter:webhook]
use = egg:oio#webhook
endpoint = ${WEBHOOK_ENDPOINT}

[filter:async_replication]
use = egg:oio#notify
broker_endpoint = ${QUEUE_URL}
topic = oio-replication
required_fields = repli

[filter:bury]
use = egg:oio#bury

[filter:dump]
use = egg:oio#dump

[filter:noop]
use = egg:oio#noop

[filter:notify_deleted]
# Forward storage.content.deleted events to another queue. Another
# oio-event-agent will read this queue and delete chunks at a limited rate.
use = egg:oio#delete
broker_endpoint = ${QUEUE_URL}
topic_prefix = oio-delete-

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s

[filter:preserve]
# Preserve all events in the oio-preserved topic. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = ${QUEUE_URL}
"""

template_event_agent_delete_handlers = """
[handler:storage.content.deleted]
pipeline = content_cleaner ${PRESERVE}

[handler:storage.content.drained]
pipeline = content_cleaner ${PRESERVE}

[filter:content_cleaner]
use = egg:oio#content_cleaner

# These values are changed only for testing purposes.
# The default values are good for most use cases.
concurrency = 4
pool_connections = 16
pool_maxsize = 16
timeout = 4.5

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s

[filter:preserve]
# Preserve all events in the oio-preserved topic. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = ${QUEUE_URL}
"""

template_event_agent_chunks_handlers = """
### handlers
[handler:storage.chunk.new]
pipeline = volume_index ${PRESERVE}

[handler:storage.chunk.deleted]
pipeline = volume_index ${PRESERVE}

### filters
[filter:volume_index]
use = egg:oio#volume_index
retry_delay = 2
write_quorum = 0

[filter:preserve]
# Preserve all events in the oio-preserved topic. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = ${QUEUE_URL}
"""

template_event_agent_delay_handlers = """
[handler:delayed]
pipeline = delay

[filter:delay]
use = egg:oio#delay
topic = oio-delayed

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s
"""

template_event_agent_replication_delay_handlers = """
[handler:delayed]
pipeline = delay

[filter:delay]
use = egg:oio#delay
topic = oio-replication-delayed

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s
"""

template_event_agent_rebuilder_handlers = """
[handler:storage.content.broken]
pipeline = rebuild

[filter:rebuild]
use = egg:oio#blob_rebuilder
topic = oio-rebuild

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s
"""

template_event_agent_lifecycle_checkpoint_handlers = """
[handler:lifecycle.checkpoint]
pipeline = checkpoint

[filter:checkpoint]
use = egg:oio#checkpoint_creator
topic = oio-lifecycle-checkpoint
redis_host = ${IP}:${REDIS_PORT}
checkpoint_prefix = lifecycle

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s
"""

template_event_agent_lifecycle_actions_handlers = """
[handler:storage.lifecycle.action]
pipeline = lifecycle_actions ${PRESERVE}

[filter:lifecycle_actions]
use = egg:oio#lifecycle_actions
redis_host = ${IP}:${REDIS_PORT}

[filter:preserve]
# Preserve all events in the oio-preserved topic.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = ${QUEUE_URL}
"""

template_event_agent_mpu_parts_handlers = """
[handler:storage.manifest.deleted]
pipeline = log mpu_cleaner ${PRESERVE}

[filter:mpu_cleaner]
use = egg:oio#mpu_cleaner
# Note that this value should not be higher because deleting too many objects at
# the same time is a high consumer.
object_deletion_concurrency = 100
retry_delay = 60
# Delay when there is some remaining parts for this MPU.
# 0 means the event will be emitted in the same topic again.
retry_delay_remaining_parts = 0
# Event will be retried if the manifest still exists until this timeout is reached.
timeout_manifest_still_exists = 900

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s

[filter:preserve]
# Preserve all events in the oio-preserved topic.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = ${QUEUE_URL}
"""

template_xcute_event_agent = """
[event-agent]
topic = ${QUEUE_NAME}
namespace = ${NS}
user = ${USER}
workers = ${EVENT_WORKERS}
concurrency = 5
handlers_conf = ${HANDLER_CONF}
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}
broker_endpoint = ${QUEUE_URL}
group_id = ${GROUP_ID}
${TCP_CORK_COMMENT}use_tcp_cork = ${TCP_CORK}
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
amqp_url = ${AMQP_URL}
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
fdb_max_retries = 4

time_window_clear_deleted = 60
allow_empty_policy_name = False

# KMS API
kmsapi_enabled = True
kmsapi_mock_server = True
kmsapi_domains = domain1, domain2
kmsapi_domain1_endpoint = http://${KMSIP}:${PORT_KMSAPI_MOCK_SERVER}/domain1
kmsapi_domain1_key_id = abcdefgh-aaaa-bbbb-cccc-123456789abc
kmsapi_domain2_endpoint = http://${KMSIP}:${PORT_KMSAPI_MOCK_SERVER}/domain2
kmsapi_domain2_key_id = abcdefgh-aaaa-bbbb-cccc-123456789def

# GROUPS FOR REGION BACKUPS
region_backup_local = LOCALHOST,LOCALHOSTBIS 
region_backup_numbers = REGIONONE,REGIONTWO,REGIONTHREE
backup_pepper = this-is-not-really-a-random-string-but-should-be-in-prod
"""

template_kms = """
[kmsapi-mock-server]
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
graceful_timeout = 2
workers = 2

[xcute-orchestrator]
orchestrator_id = orchestrator-${SRVNUM}
broker_endpoint = ${QUEUE_URL}
jobs_topic = oio-xcute-job
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
OioGroup=${NS},${SRVTYPE},${IP}:${PORT}

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} --port 9081
Environment=PATH=${PATH}
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

[Install]
WantedBy=${PARENT}
"""

template_systemd_rabbitmq_to_beanstalkd = """
[Unit]
Description=[OpenIO] Forward messages from RabbitMQ to Beanstalkd
After=oio-meta2-1.service
PartOf=${PARENT}
OioGroup=${NS},event

[Service]
${SERVICEUSER}
${SERVICEGROUP}
Type=simple
ExecStart=${EXE} --ns ${NS} --workers 2 --input-queue-argument x-queue-type=quorum
Environment=PYTHONPATH=${PYTHONPATH}
Environment=LD_LIBRARY_PATH=${LIBDIR}
${ENVIRONMENT}
Environment=OIO_RABBITMQ_ENDPOINT=amqp://guest:guest@127.0.0.1:56666/%%2F;amqp://guest:guest@127.0.0.1:5672/%%2F
TimeoutStopSec=${SYSTEMCTL_TIMEOUT_STOP_SEC}

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
ZOOKEEPER = "zookeeper"
REMOTE_ACCOUNT = "remote_account"
GO_RAWX = "go_rawx"
FSYNC_RAWX = "rawx_fsync"
SHALLOW_COPY = "shallow_copy"
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
# Fill with "#" to comment the line out of the config files
# or leave empty to activate the option on config files
TCP_CORK_COMMENT = "#"
TCP_CORK = "false"
TLS_CERT_FILE = None
TLS_KEY_FILE = None
HASH_WIDTH = "hash_width"
HASH_DEPTH = "hash_depth"
KAFKA_ENDPOINT = "kafka_endpoint"
KAFKA_METRICS_ENDPOINTS = "kafka_metrics_endpoints"


defaults = {
    "NS": "OPENIO",
    SVC_HOSTS: ("127.0.0.1",),
    KAFKA_ENDPOINT: "127.0.0.1:19092",
    KAFKA_METRICS_ENDPOINTS: "127.0.0.1:19644",
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
    # After being stopped (SIGTERM), timeout before sending a SIGKILL
    "SYSTEMCTL_TIMEOUT_STOP_SEC": 30,  # systemctl default value
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


def httpd_config(env, internal=False):
    if internal:
        return "{CFGDIR}/{NS}-internal-{SRVTYPE}-{SRVNUM}.httpd.conf".format(**env)
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


def get_rawx_slot(idx):
    return "even" if idx % 2 == 0 else "odd"


def generate(options):
    global first_port

    def ensure(v, default):
        if v is None:
            return default
        return v

    def getint(v, default):
        try:
            return int(ensure(v, default))
        except Exception:
            return default

    final_conf = {}
    final_services = {}

    ports = (x for x in xrange(options["port"], 60000))
    port_proxy = next(ports)
    port_account = next(ports)
    port_admin = next(ports)
    port_kmsapi_mock_server = next(ports)

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

    systemctl_timeout_stop_sec = defaults["SYSTEMCTL_TIMEOUT_STOP_SEC"]

    statsd_host = options.get("statsd", {}).get("host", "")
    statsd_port = options.get("statsd", {}).get("port", "8125")
    if statsd_host:
        statsd_addr = f"{statsd_host}:{statsd_port}"
    else:
        statsd_addr = ""

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
        PORT_KMSAPI_MOCK_SERVER=port_kmsapi_mock_server,
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
        REPLICATION="async_replication" if options.get("replication_events") else "",
        STATSD_HOST=statsd_host,
        STATSD_PORT=statsd_port,
        STATSD_ADDR=statsd_addr,
        SYSTEMCTL_TIMEOUT_STOP_SEC=systemctl_timeout_stop_sec,
        TCP_CORK=TCP_CORK,
        TCP_CORK_COMMENT=TCP_CORK_COMMENT,
        TLS_CERT_FILE=TLS_CERT_FILE,
        TLS_KEY_FILE=TLS_KEY_FILE,
        WANT_SERVICE_ID=want_service_id,
        WEBHOOK=WEBHOOK,
        WEBHOOK_ENDPOINT=WEBHOOK_ENDPOINT,
        REDIS_PORT=6379,
    )
    ENV["env.HOME"] = HOME

    def merge_env(add):
        env = dict(ENV)
        env.update(add)
        env["env.G_DEBUG"] = "fatal_warnings"
        orig_exe = env.get("EXE", None)
        if orig_exe and orig_exe in C_LANG_SERVICES:
            if options.get(PROFILE) == "valgrind":
                new_exe = (
                    "valgrind --leak-check=full --leak-resolution=high    "
                    " --trace-children=yes --log-file=/tmp/%%q{ORIG_EXE}.%%p.valgrind "
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
                    " --callgrind-out-file=/tmp/callgrind.out.%%q{ORIG_EXE}.%%p "
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
        dcnum = int(ip.split(".")[-1]) % 2
        return f"dc{dcnum}.rack.{ip.replace('.', '-')}.{num}"

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
        if name not in targets:
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
                "SERVICEUSER": (
                    "User={}".format(env["USER"]) if is_systemd_system() else ""
                ),
                "SERVICEGROUP": (
                    "Group={}".format(env["GROUP"]) if is_systemd_system() else ""
                ),
            }
        )
        service_name = systemd_service(env)
        if add_service_to_conf:
            env.update({"SYSTEMD_UNIT": service_name})
            add_service(env)
        if env.get("EXE"):
            env["EXE"] = shutil.which(env["EXE"]) or env["EXE"]
            if COVERAGE and not PROFILE and env["EXE"]:
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
        cache_service_lists = bool(options["conscience"].get("cache_service_lists"))
        hub_threads = getint(options["conscience"].get("hub_threads"), 0)
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
                "CS_HUB_THREADS": str(hub_threads),
                "CS_CACHE_SERVICES": str(cache_service_lists),
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
        ENV.update(
            {
                "BEANSTALK_CNXSTRING": beanstalkd_cnxstring,
                "EVENT_CNXSTRING": beanstalkd_cnxstring,
                "NOBS": "",
            }
        )
    else:
        ENV.update(
            {
                "EVENT_CNXSTRING": "***disabled***",
                "BEANSTALK_CNXSTRING": "***disabled***",
                "NOBS": "#",
            }
        )

    # Kafka
    endpoints = options["kafka"]["endpoint"] or defaults[KAFKA_ENDPOINT]
    if isinstance(endpoints, str):
        endpoints = [endpoints]
    kafka_cnxstring = ",".join((f"kafka://{endpoint}" for endpoint in endpoints))
    ENV.update({"EVENT_CNXSTRING": kafka_cnxstring, "NOBS": ""})
    ENV["KAFKA_QUEUE_URL"] = kafka_cnxstring
    # Kafka metrics
    metrics_endpoints = (
        options["kafka"]["metrics_endpoints"] or defaults[KAFKA_METRICS_ENDPOINTS]
    )
    if isinstance(metrics_endpoints, str):
        metrics_endpoints = [metrics_endpoints]
    metrics_cnxstring = ",".join(metrics_endpoints)
    ENV.update(
        {
            "KAFKA_METRICS_URL": metrics_cnxstring,
        }
    )

    # For testing purposes, some events must go to the main queue
    if all_beanstalkd:
        _, host, port = all_beanstalkd[0]
        ENV["MAIN_QUEUE_URL"] = f"beanstalk://{host}:{port}"

    event_target = register_target("event", root_target)

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
                "OPTARGS": "",
            }
        )
        if service_id:
            env["WANT_SERVICE_ID"] = ""
            env["SERVICE_ID"] = "{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
            env["OPTARGS"] = "-O ServiceId=%s" % env["SERVICE_ID"]
        else:
            env["WANT_SERVICE_ID"] = "#"
        if t in ("meta1", "meta2"):
            if env.get("SERVICE_ID"):
                tpl_meta = Template(template_meta_config)
                with open(config(env), "w+") as f:
                    f.write(tpl_meta.safe_substitute(env))
                env["OPTARGS"] += " -O Config=%s" % config(env)
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

    crawler_target = register_target("crawler", root_target)

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
        _tmp_env,
        template_systemd_service_meta2_crawler,
        crawler_target,
        add_service_to_conf=False,
        coverage_wrapper=shutil.which("coverage")
        + " run --context meta2-crawler --concurrency=eventlet -p ",
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
        add_service_to_conf=False,
        coverage_wrapper=shutil.which("coverage")
        + " run --context meta2-crawler --concurrency=eventlet -p ",
    )

    # oio-meta2-lifecycle-crawler
    _tmp_env = subenv(
        {
            "IP": host,
            "META2_VOLUMES": ",".join(meta2_volumes),
            "SRVTYPE": "meta2-lifecycle-crawler",
            "SRVNUM": "1",
            "GROUPTYPE": "crawler",
            "EXE": "oio-meta2-crawler",
        }
    )
    # first the conf
    tpl = Template(template_meta2_lifecycle_crawler_service)
    to_write = tpl.safe_substitute(_tmp_env)
    path = "{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf".format(**_tmp_env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(
        _tmp_env,
        template_systemd_service_lifecycle_crawler,
        crawler_target,
        add_service_to_conf=False,
        coverage_wrapper=shutil.which("coverage")
        + " run --context meta2-crawler --concurrency=eventlet -p ",
    )

    # oio-rdir-crawler-meta2
    env.update(
        {
            "VOLUMES": ",".join(meta2_volumes),
            "VOLUME_TYPE": "meta2",
            "SRVTYPE": "rdir-crawler-meta2",
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
        env,
        template_systemd_service_rdir_crawler,
        crawler_target,
        add_service_to_conf=False,
        # coverage_wrapper=shutil.which("coverage")
        # + " run --context rdir-crawler --concurrency=multiprocessing -p ",
    )

    # RAWX
    srvtype = "rawx"
    nb_rawx = getint(options[srvtype].get(SVC_NB), defaults["NB_RAWX"])
    rawx_per_host = {}
    if nb_rawx:
        rawx_volumes = []
        rawx_target = register_target("rawx", root_target)
        for i in range(nb_rawx):
            host_idx = i % len(hosts)
            host = hosts[host_idx]
            slot = get_rawx_slot(i)
            env = subenv(
                {
                    "IP": host,
                    "SRVTYPE": srvtype,
                    "SRVNUM": i + 1,
                    "EXE": "oio-rawx",
                    "PORT": next(ports),
                    "NICE": 0,
                    "IO_SCHEDULING_PRIORITY": 0,
                    "IO_SCHEDULING_CLASS": 2,
                    "INTERNAL_PORT": next(ports),
                    "COMPRESSION": ENV["COMPRESSION"] if i % 2 else "off",
                    "EXTRASLOT": f"rawx-{slot}",
                    "FSYNC": ("enabled" if options[FSYNC_RAWX] else "disabled"),
                    "HASH_WIDTH": defaults[HASH_WIDTH],
                    "HASH_DEPTH": defaults[HASH_DEPTH],
                    "SHALLOW_COPY": (
                        "enabled" if options[SHALLOW_COPY] else "disabled"
                    ),
                    "TOPIC": f"oio-chunks-{host}",
                }
            )
            rawx_volumes.append(env["VOLUME"])
            env["SERVICE_ID"] = "{NS}-{SRVTYPE}-{SRVNUM}".format(**env)
            host_rawxs = rawx_per_host.setdefault(host, [])
            host_rawxs.append(env["SERVICE_ID"])
            if options.get("use_tls", False):
                env["TLS_CERT_FILE"] = ENV["TLS_CERT_FILE"]
                env["TLS_KEY_FILE"] = ENV["TLS_KEY_FILE"]
                env["TLS_PORT"] = next(ports)
                env["USE_TLS"] = ""
            else:
                env["USE_TLS"] = "#"
            if options.get("set_nice", False):
                env["SET_NICE"] = ""
            else:
                env["SET_NICE"] = "#"
            if options.get("set_ionice", False):
                env["SET_IONICE"] = ""
            else:
                env["SET_IONICE"] = "#"
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
            # Internal rawx service
            env["PORT"] = env["INTERNAL_PORT"]
            env["SRVTYPE"] = "internal-" + srvtype
            if options.get("use_tls", False):
                # Don't use tls in case of internal rawx
                env["USE_TLS"] = "#"
            # No need to set these values for internal rawx
            # for dev environment
            # env["NICE_VALUE"] = 7
            # env["IO_SCHEDULING_PRIORITY"] = 4
            register_service(
                env,
                template_systemd_service_rawx % template_systemd_rawx_command_options,
                rawx_target,
            )
            # The service type is used to name the volume linked to the rawx.
            # Considering that the internal rawx is set to use the same volume
            # as a regular rawx service, here we change the service type of
            # the internal rawx to match the one used by the regular rawx.
            env["SRVTYPE"] = srvtype
            tpl = Template(template_rawx_service)
            to_write = tpl.safe_substitute(env)
            with open(httpd_config(env, True), "w+") as f:
                f.write(to_write)
            # No need to add a watcher for an internal rawx

        # oio-rdir-crawler-rawx
        env.update(
            {
                "VOLUMES": ",".join(rawx_volumes),
                "VOLUME_TYPE": "rawx",
                "SRVTYPE": "rdir-crawler-rawx",
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
            env,
            template_systemd_service_rdir_crawler,
            crawler_target,
            add_service_to_conf=False,
            # coverage_wrapper=shutil.which("coverage")
            # + " run --context rdir-crawler --concurrency=multiprocessing -p ",
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
            env,
            template_systemd_service_rawx_crawler,
            crawler_target,
            add_service_to_conf=False,
            coverage_wrapper=shutil.which("coverage")
            + " run --context rawx-crawler --concurrency=eventlet -p ",
        )

        # oio-checksum-checker-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "checksum-checker-crawler",
                "EXE": "oio-rawx-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
                "HASH_WIDTH": defaults[HASH_WIDTH],
                "HASH_DEPTH": defaults[HASH_DEPTH],
            }
        )
        tpl = Template(template_checksum_checker_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        register_service(
            env,
            template_systemd_service_rawx_crawler,
            crawler_target,
            add_service_to_conf=False,
            coverage_wrapper=shutil.which("coverage")
            + " run --context rawx-crawler --concurrency=eventlet -p ",
        )

        # oio-placement-improver-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "placement-improver-crawler",
                "EXE": "oio-rawx-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
            }
        )
        tpl = Template(template_placement_improver_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        register_service(
            env,
            template_systemd_service_rawx_crawler,
            crawler_target,
            add_service_to_conf=False,
            coverage_wrapper=shutil.which("coverage")
            + " run --context rawx-crawler --concurrency=eventlet -p ",
        )

        # oio-cleanup-orphaned-crawler
        env.update(
            {
                "RAWX_VOLUMES": ",".join(rawx_volumes),
                "SRVTYPE": "cleanup-orphaned-crawler",
                "EXE": "oio-rawx-crawler",
                "GROUPTYPE": "crawler",
                "SRVNUM": "1",
            }
        )
        tpl = Template(template_cleanup_orphaned_crawler_service)
        to_write = tpl.safe_substitute(env)
        path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
        with open(path, "w+") as f:
            f.write(to_write)
        register_service(
            env,
            template_systemd_service_cleanup_orphaned_crawler,
            crawler_target,
            add_service_to_conf=False,
            coverage_wrapper=shutil.which("coverage")
            + " run --context rawx-crawler --concurrency=eventlet -p ",
        )

    # Lifecycle collector
    env.update(
        {
            "SRVTYPE": "lifecycle-collector",
            "SRVNUM": "1",
        }
    )
    tpl = Template(template_lifecycle_collector_service)
    to_write = tpl.safe_substitute(env)
    path = "{CFGDIR}/{NS}-{SRVTYPE}.conf".format(**env)
    with open(path, "w+") as f:
        f.write(to_write)

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
            "SERVICE_ID": "proxy-1",
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

    # kmsapi-mock-server
    env = subenv(
        {
            "SRVTYPE": "kmsapi-mock-server",
            "SRVNUM": 1,
            "EXE": "oio-kmsapi-mock-server",
            "PORT": port_kmsapi_mock_server,
        }
    )
    register_service(env, template_systemd_service_kms, root_target)
    with open(config(env), "w+") as f:
        tpl = Template(template_kms)
        f.write(tpl.safe_substitute(env))
    ENV["KMSIP"] = env["IP"]

    # fake statsd server
    if options.get("statsd", {}).get("host", ""):
        env = subenv(
            {
                "SRVTYPE": "statsd-server",
                "SRVNUM": 1,
            }
        )
        register_service(env, template_systemd_service_statsd, root_target)
        with open(config(env), "w+") as f:
            tpl = Template(template_kms)
            f.write(tpl.safe_substitute(env))

    # account
    nb_account = getint(options["account"].get(SVC_NB), 1)
    for num in range(nb_account):
        env = subenv(
            {
                "SRVTYPE": "account",
                "SRVNUM": num,
                "PORT": port_account if num == 0 else next(ports),
                "EXE": "oio-account-server",
            }
        )
        if options.get(ALLOW_FDB):
            env.update({"CLUSTERFILE": cluster_file})
        register_service(
            env,
            template_systemd_service_account,
            root_target,
            coverage_wrapper=shutil.which("coverage")
            + " run --context account --concurrency=gevent -p ",
        )
        with open(config(env), "w+") as f:
            tpl = Template(template_account)
            f.write(tpl.safe_substitute(env))
        if not options.get(REMOTE_ACCOUNT):
            with open(watch(env), "w+") as f:
                tpl = Template(template_account_xcute_watch)
                f.write(tpl.safe_substitute(env))
        elif num == 0:
            options["config"]["account"] = f"http://{env['IP']}:{port_account}"

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

    event_agents_target = register_target("event-agent", event_target)
    event_agents_delete_target = register_target("event-agent-delete", event_target)

    event_agent_bin = "oio-event-agent"
    event_agent_count = getint(options["event-agent"].get(SVC_NB), len(all_beanstalkd))

    def get_event_agent_details():
        for i in range(event_agent_count):
            yield i + 1, ENV["KAFKA_QUEUE_URL"], "oio-event-agent-kafka"

    def add_event_agent_conf(
        num,
        queue_name,
        url,
        workers,
        group_id,
        template_handler,
        handler_prefix="handlers-",
        context="event-agent",
        queue_type="default",
        queue_ids="",
        srv_type="event-agent",
        template_agent=template_event_agent,
        target=event_agents_target,
    ):
        handler_path = f"{CFGDIR}/{handler_prefix}{srv_type}-{num}.conf"

        env = subenv(
            {
                "SRVTYPE": srv_type,
                "SRVNUM": num,
                "QUEUE_NAME": queue_name,
                "QUEUE_URL": url,
                "EXE": event_agent_bin,
                "EVENT_WORKERS": workers,
                "GROUP_ID": group_id,
                "QUEUE_TYPE": queue_type,
                "QUEUE_IDS": queue_ids,
                "HANDLER_CONF": handler_path,
            }
        )
        register_service(
            env,
            template_systemd_service_event_agent,
            target,
            coverage_wrapper=(
                shutil.which("coverage")
                + " run --context "
                + context
                + " --concurrency=eventlet -p "
            ),
        )
        with open(config(env), "w+", encoding="utf-8") as f:
            tpl = Template(template_agent)
            f.write(tpl.safe_substitute(env))
        with open(handler_path, "w+", encoding="utf-8") as f:
            tpl = Template(template_handler)
            f.write(tpl.safe_substitute(env))

    # Event agent configuration -> one per beanstalkd
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio",
            url,
            workers="2",
            group_id="event-agent",
            template_handler=template_event_agent_handlers,
        )

    # Configure a special oio-event-agent dedicated to chunk deletions per host
    # -------------------------------------------------------------------------
    num = 0
    for _, url, event_agent_bin in get_event_agent_details():
        for i, host in enumerate(hosts):
            for j in range(2):
                slot = get_rawx_slot(j)
                num += 1
                add_event_agent_conf(
                    num,
                    f"oio-delete-{host}-{slot}",
                    url,
                    srv_type="event-agent-delete",
                    workers=len(rawx_per_host[host]),
                    group_id="event-agent-delete",
                    queue_type="per_service",
                    queue_ids=";".join(rawx_per_host[host]).lower(),
                    template_handler=template_event_agent_delete_handlers,
                    target=event_agents_delete_target,
                )

        break

    # Configure a special oio-event-agent dedicated to chunk events per host
    # -------------------------------------------------------------------------
    num = 0
    for _, url, event_agent_bin in get_event_agent_details():
        for host in hosts:
            num += 1
            add_event_agent_conf(
                num,
                f"oio-chunks-{host}",
                url,
                srv_type="event-agent-chunks",
                workers=len(rawx_per_host[host]),
                group_id="event-agent-chunks",
                template_handler=template_event_agent_chunks_handlers,
            )

        break

    # Configure a special oio-event-agent dedicated to delayed events
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio-delayed",
            url,
            workers="1",
            srv_type="event-agent-delay",
            group_id="event-agent-delay",
            template_handler=template_event_agent_delay_handlers,
        )

        # We need only one service
        break
    if options.get("replication_events"):
        # Configure oio-event-agent dedicated to delayed events from replicator
        # -----------------------------------------------------------------------
        for num, url, event_agent_bin in get_event_agent_details():
            add_event_agent_conf(
                num,
                "oio-replication-delayed",
                url,
                workers="1",
                srv_type="event-agent-replication-delay",
                group_id="event-agent-replication-delay",
                template_handler=template_event_agent_replication_delay_handlers,
            )

            # We need only one service
            break

    # Configure a special oio-event-agent dedicated to content broken events
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio-rebuild",
            url,
            workers="1",
            srv_type="event-agent-rebuild",
            group_id="event-agent-rebuild",
            template_handler=template_event_agent_rebuilder_handlers,
        )

        # We need only one service
        break

    # Configure a special oio-event-agent dedicated to lifecycle checkpoint events
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio-lifecycle-checkpoint",
            url,
            workers="1",
            srv_type="event-agent-lifecycle-checkpoint",
            group_id="event-agent-lifecycle-checkpoint",
            template_handler=template_event_agent_lifecycle_checkpoint_handlers,
        )

        # We need only one service
        break

    # Configure a special oio-event-agent dedicated to mpu-parts deletion
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio-delete-mpu-parts",
            url,
            workers="1",
            srv_type="event-agent-delete-mpu-parts",
            group_id="event-agent-delete-mpu-parts",
            template_handler=template_event_agent_mpu_parts_handlers,
        )
        # We need only one service
        break

    # Configure a special oio-event-agent dedicated to lifecycle actions events
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            "oio-lifecycle",
            url,
            workers="1",
            srv_type="event-agent-lifecycle-actions",
            group_id="event-agent-lifecycle-actions",
            template_handler=template_event_agent_lifecycle_actions_handlers,
        )

        # We need only one service
        break

    # Xcute event-agents
    # -------------------------------------------------------------------------
    for num, url, event_agent_bin in get_event_agent_details():
        add_event_agent_conf(
            num,
            queue_name="oio-xcute-job",
            workers="2",
            url=url,
            srv_type="xcute-event-agent",
            context="xcute",
            handler_prefix="xcute-event-handlers-",
            group_id="event-agent-xcute",
            template_handler=template_xcute_event_agent_handlers,
            template_agent=template_xcute_event_agent,
        )
    num = 0
    for _, url, event_agent_bin in get_event_agent_details():
        for host in hosts:
            num += 1
            add_event_agent_conf(
                num,
                queue_name=f"oio-xcute-job-{host}",
                workers="2",
                url=url,
                srv_type="xcute-event-agent-local",
                context="xcute",
                handler_prefix="xcute-event-handlers-",
                group_id="event-agent-xcute-per-host",
                template_handler=template_xcute_event_agent_handlers,
                template_agent=template_xcute_event_agent,
            )

        break

    # -------------------------------------------------------------------------

    env = subenv(
        {
            "SRVTYPE": "xcute",
            "SRVNUM": 1,
            "PORT": next(ports),
            "REDIS_PORT": 6379,
            "QUEUE_URL": ENV["KAFKA_QUEUE_URL"],
            "EXE": "oio-xcute",
        }
    )
    register_service(
        env,
        template_systemd_service_xcute,
        root_target,
        coverage_wrapper=shutil.which("coverage")
        + " run --context xcute --concurrency=eventlet -p ",
    )
    with open(config(env), "w+") as f:
        tpl = Template(template_xcute)
        f.write(tpl.safe_substitute(env))
    with open(watch(env), "w+", encoding="utf8") as f:
        tpl = Template(template_account_xcute_watch)
        f.write(tpl.safe_substitute(env))

    # billing buckets
    crawler_target = register_target("billing", root_target)
    env = subenv(
        {
            "SRVTYPE": "billing-agent",
            "GROUPTYPE": "billing",
            "EXE": "oio-billing-agent",
            "SRVNUM": 1,
            "AMQP_URL": options["billing"]["amqp_url"],
        }
    )
    cluster_file = cluster(env)
    env.update({"CLUSTERFILE": cluster_file})
    tpl = Template(template_billing_agent_service)
    to_write = tpl.safe_substitute(env)
    path = "{CFGDIR}/{SRVTYPE}.conf".format(**env)
    with open(path, "w+") as f:
        f.write(to_write)
    register_service(
        env,
        template_systemd_service_billing_agent,
        crawler_target,
        add_service_to_conf=False,
    )

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
    register_service(
        env, template_systemd_service_ns, root_target, add_service_to_conf=False
    )

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

    # Generate topics declaration file
    topics_to_declare = [
        "oio",
        "oio-deadletter",
        "oio-delayed",
        "oio-delete-mpu-parts",
        "oio-drained",
        "oio-lifecycle-checkpoint",
        "oio-lifecycle",
        "oio-preserved",
        "oio-rebuild",
        "oio-replication",
        "oio-xcute-job",
        "oio-xcute-job-reply",
    ]
    if options.get("replication_events"):
        topics_to_declare.append("oio-replication-delayed")

    rawx_hosts = hosts[:nb_rawx]
    # Add delete topics per host
    for i in range(2):
        slot = get_rawx_slot(i)
        topics_to_declare.extend([f"oio-delete-{h}-{slot}" for h in rawx_hosts])
    # Add chunks topics per host
    topics_to_declare.extend([f"oio-chunks-{h}" for h in rawx_hosts])
    # Add xcute-job topic per host, to gather delete events from blob mover
    topics_to_declare.extend([f"oio-xcute-job-{h}" for h in rawx_hosts])

    with open(f"{CFGDIR}/topics.yml", "w+") as f:
        f.write(
            yaml.dump(
                {
                    "brokers": options["kafka"]["endpoint"],
                    "topics": {k: None for k in topics_to_declare},
                }
            )
        )

    # ensure volumes for srvtype in final_services:
    for srvtype, services in final_services.items():
        for rec in services:
            if "path" in rec:
                mkdir_noerror(rec["path"])
            if "path" in rec and "addr" in rec:
                if "internal" not in srvtype:
                    # No need to initialize volume of internal rawx
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
    # For kafka
    final_conf["kafka_endpoints"] = kafka_cnxstring
    final_conf["kafka_metrics_endpoints"] = metrics_cnxstring
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
    final_conf["shallow_copy"] = options[SHALLOW_COPY]
    final_conf["with_service_id"] = options["with_service_id"]
    final_conf["random_service_id"] = bool(options["random_service_id"])
    final_conf["webhook"] = WEBHOOK_ENDPOINT
    final_conf["use_tls"] = bool(options.get("use_tls"))
    final_conf["set_nice"] = bool(options.get("set_nice"))
    final_conf["set_ionice"] = bool(options.get("set_ionice"))
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
    opts["account"] = {SVC_NB: None}
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
    opts[SHALLOW_COPY] = False
    opts["beanstalkd"] = {SVC_NB: None, SVC_HOSTS: None}
    opts["billing"] = {"amqp_url": "amqp://guest:guest@localhost:5672/"}
    opts["kafka"] = {"endpoint": None, "metrics_endpoints": None}
    opts["event-agent"] = {SVC_NB: None}
    opts["rebuilder"] = {SVC_NB: None}

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
