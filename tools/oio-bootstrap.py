#!/usr/bin/env python

# @EXE_PREFIX@-bootstrap.py, a script initating a local configuration
# of OpenIO SDS.
# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

import errno
import grp
import yaml
import os
import pwd
from string import Template
import re
import argparse


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

template_redis_gridinit = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
command=redis-server ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
"""

template_account_gridinit = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-${SRVTYPE}-server ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages
"""

template_rdir_gridinit = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-${SRVTYPE}-server ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages
"""

template_proxy_gridinit = """
[service.${NS}-proxy]
group=${NS},localhost,proxy,${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
#command=${EXE_PREFIX}-proxy -s OIO,${NS},proxy -O Bind=${RUNDIR}/${NS}-proxy.sock ${IP}:${PORT} ${NS}
command=${EXE_PREFIX}-proxy -O Cache=off -s OIO,${NS},proxy ${IP}:${PORT} ${NS}
"""

template_rawx_service = """
LoadModule mpm_worker_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mpm_worker.so
LoadModule authz_core_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_authz_core.so
LoadModule setenvif_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_setenvif.so
LoadModule dav_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_dav.so
LoadModule mime_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mime.so
LoadModule alias_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_alias.so
LoadModule dav_rawx_module @APACHE2_MODULES_DIRS@/mod_dav_rawx.so

<IfModule !unixd_module>
  LoadModule unixd_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_unixd.so
</IfModule>
<IfModule !log_config_module>
  LoadModule log_config_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_log_config.so
</IfModule>

Listen ${IP}:${PORT}
PidFile ${RUNDIR}/${NS}-${SRVTYPE}-${SRVNUM}.pid
ServerRoot ${TMPDIR}
ServerName ${IP}
ServerSignature Off
ServerTokens Prod
DocumentRoot ${RUNDIR}
TypesConfig /etc/mime.types

User  ${USER}
Group ${GROUP}

LogFormat "%h %l %t \\"%r\\" %>s %b %D" log/common
ErrorLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-errors.log
SetEnvIf Request_URI "/(stat|info)$" nolog
CustomLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-access.log log/common env=!nolog
LogLevel info

<IfModule prefork.c>
StartServers 5
MaxClients 40
MinSpareServers 2
MaxSpareServers 40
</IfModule>

<IfModule worker.c>
StartServers 2
MaxClients 40
MinSpareThreads 2
MaxSpareThreads 40
ThreadsPerChild 20
MaxRequestsPerChild 0
</IfModule>

DavDepthInfinity Off

grid_docroot           ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
grid_namespace         ${NS}
grid_dir_run           ${RUNDIR}

# How many hexdigits must be used to name the indirection directories
grid_hash_width        3

# How many levels of directories are used to store chunks.
grid_hash_depth        1

# At the end of an upload, perform a fsync() on the chunk file itself
grid_fsync             disabled

# At the end of an upload, perform a fsync() on the directory holding the chunk
grid_fsync_dir         enabled

# Preallocate space for the chunk file (enabled by default)
#grid_fallocate enabled

# Triggers Access Control List (acl)
# DO NOT USE, this is broken
#grid_acl disabled

# Enable compression ('zlib' or 'lzo' or 'off')
grid_compression ${COMPRESSION}

Alias / /x/

<Directory />
DAV rawx
AllowOverride None
Require all granted
Options -SymLinksIfOwnerMatch -FollowSymLinks -Includes -Indexes
</Directory>

<VirtualHost ${IP}:${PORT}>
# DO NOT REMOVE (even if empty) !
</VirtualHost>
"""

template_wsgi_service_host = """
LoadModule mpm_worker_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mpm_worker.so
LoadModule authz_core_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_authz_core.so
LoadModule wsgi_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_wsgi.so

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

LogFormat "%h %l %t \\"%r\\" %>s %b %D" log/common
ErrorLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-errors.log
CustomLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-access.log log/common env=!nolog
LogLevel info

WSGIDaemonProcess ${SRVTYPE}-${SRVNUM} processes=2 threads=1 user=${USER} group=${GROUP}
#WSGIProcessGroup ${SRVTYPE}-${SRVNUM}
WSGIApplicationGroup ${SRVTYPE}-${SRVNUM}
WSGIScriptAlias / ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.wsgi
WSGISocketPrefix ${RUNDIR}/
WSGIChunkedRequest On
LimitRequestFields 200

<VirtualHost ${IP}:${PORT}>
# Leave Empty
</VirtualHost>
"""

template_wsgi_service_descr = """
conf = {'key_file': '${KEY_FILE}'}
from oio.${SRVTYPE}.app import create_app
application = create_app(conf)
"""

template_meta_watch = """
host: ${IP}
port: ${PORT}
type: ${SRVTYPE}
location: hem.oio.vol${SRVNUM}
slots:
    - ${SRVTYPE}
checks:
    - {type: tcp}

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

template_rawx_watch = """
host: ${IP}
port: ${PORT}
type: rawx
location: hem.oio.vol${SRVNUM}
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
location: hem.oio.db${SRVNUM}
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: volume, path: ${VOLUME}}
    - {type: http, path: /status, parser: json}
    - {type: system}
"""

template_redis_watch = """
host: ${IP}
port: ${PORT}
type: redis
location: hem.oio.db${SRVNUM}
checks:
    - {type: tcp}
slots:
    - ${SRVTYPE}
stats:
    - {type: volume, path: ${VOLUME}}
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
param_chunk_size=${CHUNK_SIZE}

param_hub.me=tcp://${IP}:${PORT_HUB}
param_hub.group=${CS_ALL_HUB}

param_option.events-max-pending=10000
param_option.meta2.events-max-pending=1000
param_option.sqlx.events-max-pending=1000
param_option.meta1.events-max-pending=100
param_option.meta2.events-buffer-delay=5

param_option.service_update_policy=meta2=KEEP|${M2_REPLICAS}|${M2_DISTANCE};sqlx=KEEP|${SQLX_REPLICAS}|${SQLX_DISTANCE}|;rdir=KEEP|1|1|user_is_a_service=1
param_option.lb.rawx=WRR?shorten_ratio=1.0&standard_deviation=no&reset_delay=60
param_option.meta2_max_versions=${VERSIONING}
param_option.meta2_keep_deleted_delay=86400
param_option.compression=on
param_option.container_max_size=50000000
param_option.FLATNS_hash_offset=0
param_option.FLATNS_hash_size=0
param_option.FLATNS_hash_bitlength=17
param_option.storage_policy=${STGPOL}

# Storage policies definitions
param_storage_conf=${CFGDIR}/${NS}-policies.conf

# Service scoring and pools definitions
param_service_conf=${CFGDIR}/${NS}-services.conf

# For an easy transition, it is still possible to define
# service score expression, variation, timeout and lock here.
#
#param_service.meta0.lock_at_first_register=false
#param_service.meta0.score_timeout=3600
#param_service.meta0.score_variation_bound=5
#param_service.meta0.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
"""

template_conscience_policies = """
[STORAGE_POLICY]
# Storage policy definitions
# ---------------------------
#
# The first word is the service pool to use,
# the second word is the data security to use.

SINGLE=NONE:NONE
TWOCOPIES=rawxevenodd:DUPONETWO
THREECOPIES=rawx3:DUPONETHREE
17COPIES=rawx17:DUP17
EC=NONE:EC
BACKBLAZE=NONE:BACKBLAZE

[DATA_SECURITY]
# Data security definitions
# --------------------------
#
# The first word is the kind of data security ("plain", "ec" or "backblaze"),
# after the '/' are the parameters of the data security.

DUPONETWO=plain/distance=1,nb_copy=2
DUPONETHREE=plain/distance=1,nb_copy=3
DUP17=plain/distance=1,nb_copy=17

EC=ec/k=6,m=3,algo=liberasurecode_rs_vand,distance=1

# List of possible values for the "algo" parameter of "ec" data security:
# "jerasure_rs_vand"       EC_BACKEND_JERASURE_RS_VAND
# "jerasure_rs_cauchy"     EC_BACKEND_JERASURE_RS_CAUCHY
# "flat_xor_hd"            EC_BACKEND_FLAT_XOR_HD
# "isa_l_rs_vand"          EC_BACKEND_ISA_L_RS_VAND
# "shss"                   EC_BACKEND_SHSS
# "liberasurecode_rs_vand" EC_BACKEND_LIBERASURECODE_RS_VAND

BACKBLAZE=backblaze/account_id=${BACKBLAZE_ACCOUNT_ID},bucket_name=${BACKBLAZE_BUCKET_NAME},distance=0,nb_copy=1
"""

template_credentials = """
[backblaze]
${BACKBLAZE_ACCOUNT_ID}.${BACKBLAZE_BUCKET_NAME}.application_key=${BACKBLAZE_APPLICATION_KEY}
"""

template_conscience_services = """[pools]
# Pools for each service type
# ----------------------------
#
# The value is a ';'-separated of targets.
# Each target is a ','-separated list of:
# - the number of services to pick,
# - the name of a slot where to pick the services,
# - the name of a slot where to pick services if there is
#   not enough in the previous slot
# - and so on...
#
# Pool are automatically created if not defined in configuration.

meta2=${M2_REPLICAS},meta2
rdir=1,rdir
account=1,account


# Pools of rawx services for storage policies
# --------------------------------------------

# Pick 3 SSD rawx, or any rawx if SSD is not available
fastrawx3=3,rawx-ssd,rawx

# Pick one "even" and one "odd" rawx
rawxevenodd=1,rawx-even;1,rawx-odd

# Try to pick one "even" and one "odd" rawx, and a generic one
rawx3=1,rawx-even,rawx;1,rawx-odd,rawx;1,rawx

# Pick one rawx in Europe, one in USA, one in Asia, or anywhere if none available
zonedrawx3=1,rawx-europe,rawx;1,rawx-usa,rawx;1,rawx-asia,rawx


[score_expr]
meta0=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
meta1=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
meta2=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
rawx=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
sqlx=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
rdir=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
redis=(num stat.cpu)
account=(num stat.cpu)
echo=(num stat.cpu)
oiofs=(num stat.cpu)

[score_timeout]
# Defaults to 300s
meta0=3600
meta1=120
meta2=120
rawx=120
sqlx=120
rdir=120
redis=120
oiofs=120
account=120
echo=30

[score_variation_bound]
# Defaults to 5s

[score_lock_at_first_register]
meta0=false
meta1=false
oiofs=false
"""

template_gridinit_header = """
[Default]
listen=${RUNDIR}/gridinit.sock
pidfile=${RUNDIR}/gridinit.pid
uid=${UID}
gid=${GID}
working_dir=${TMPDIR}
inherit_env=1
#env.PATH=${PATH}:${HOME}/.local/bin:${CODEDIR}/bin:/bin:/usr/bin:/usr/local/bin
env.LD_LIBRARY_PATH=${HOME}/.local/@LD_LIBDIR@:${LIBDIR}

#limit.core_size=-1
#limit.max_files=2048
#limit.stack_size=256

#include=${CFGDIR}/*-gridinit.conf

"""

template_gridinit_ns = """

[service.${NS}-event-agent]
group=${NS},localhost,event
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-event-agent ${CFGDIR}/event-agent.conf
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages

[service.${NS}-conscience-agent]
group=${NS},localhost,conscience,conscience-agent
on_die=respawn
enabled=true
start_at_boot=true
command=${EXE_PREFIX}-conscience-agent ${CFGDIR}/conscience-agent.yml
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages
"""

template_conscience_gridinit = """
[service.${NS}-conscience-${SRVNUM}]
group=${NS},localhost,conscience,${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=true
command=${EXE_PREFIX}-daemon -s OIO,${NS},cs,${SRVNUM} ${CFGDIR}/${NS}-conscience-${SRVNUM}.conf
"""

template_gridinit_meta = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE} -s OIO,${NS},${SRVTYPE},${SRVNUM} -O Endpoint=${IP}:${PORT} ${NS} ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
"""

template_gridinit_sqlx = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE} -s OIO,${NS},${SRVTYPE},${SRVNUM} -O DirectorySchemas=${CFGDIR}/sqlx/schemas -O Endpoint=${IP}:${PORT} ${NS} ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
"""

template_gridinit_httpd = """
[Service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
command=${HTTPD_BINARY} -D FOREGROUND -f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
enabled=true
start_at_boot=false
on_die=respawn
"""

template_local_header = """
[default]
"""

template_local_ns = """
[${NS}]
${NOZK}zookeeper=${IP}:2181
#proxy-local=${RUNDIR}/${NS}-proxy.sock
proxy=${IP}:${PORT_PROXYD}
ecd=${IP}:${PORT_ECD}
event-agent=beanstalk://127.0.0.1:11300
#event-agent=ipc://${RUNDIR}/event-agent.sock
conscience=${CS_ALL_PUB}
"""

template_event_agent = """
[event-agent]
tube = oio
namespace = ${NS}
user = ${USER}
workers = 2
concurrency = 5
handlers_conf = ${CFGDIR}/event-handlers.conf
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},event-agent
"""

template_event_agent_handlers = """
[handler:storage.content.new]

[handler:storage.content.deleted]
pipeline = content_cleaner

[handler:storage.container.new]
pipeline = account_update

[handler:storage.container.deleted]
pipeline = account_update

[handler:storage.container.state]
pipeline = account_update

[handler:storage.chunk.new]
pipeline = volume_index

[handler:storage.chunk.deleted]
pipeline = volume_index

[filter:content_cleaner]
use = egg:oio#content_cleaner
key_file = ${KEY_FILE}

[filter:account_update]
use = egg:oio#account_update

[filter:volume_index]
use = egg:oio#volume_index

[filter:logger]
use = egg:oio#logger

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
workers = 2
autocreate = true
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},${SRVTYPE},${SRVNUM}

# Let this option empty to connect directly to redis_host
#sentinel_hosts = 127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381
sentinel_master_name = oio
"""

template_rdir = """
[rdir-server]
bind_addr = ${IP}
bind_port = ${PORT}
namespace = ${NS}
db_path= ${VOLUME}
# Currently, only 1 worker is allowed to avoid concurrent access to leveldb
workers = 1
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},rdir,1
"""

sqlx_schemas = (
    ("sqlx", ""),
    ("sqlx.mail", """
CREATE TABLE IF NOT EXISTS box (
   name TEXT NOT NULL PRIMARY KEY,
   ro INT NOT NULL DEFAULT 0,
   messages INT NOT NULL DEFAULT 0,
   recent INT NOT NULL DEFAULT 0,
   unseen INT NOT NULL DEFAULT 0,
   uidnext INT NOT NULL DEFAULT 1,
   uidvalidity INT NOT NULL DEFAULT 0,
   keywords TEXT);

CREATE TABLE IF NOT EXISTS boxattr (
   box TEXT NOT NULL,
   k TEXT NOT NULL,
   v TEXT NOT NULL,
   PRIMARY KEY (box,k));

CREATE TABLE IF NOT EXISTS mail (
   seq INTEGER PRIMARY KEY AUTOINCREMENT,
   box_uid INTEGER NOT NULL,
   uid TEXT NOT NULL,
   guid TEXT NOT NULL,
   box TEXT NOT NULL,
   oiourl TEXT NOT NULL,
   len INTEGER NOT NULL,
   hlen INTEGER NOT NULL,
   flags INTEGER NOT NULL,
   header TEXT NOT NULL);

CREATE INDEX IF NOT EXISTS boxattr_index_by_box ON boxattr(box);
CREATE INDEX IF NOT EXISTS mail_index_by_box ON mail(box);

CREATE TRIGGER IF NOT EXISTS mail_after_add AFTER INSERT ON mail
BEGIN
   UPDATE mail SET box_uid = (SELECT uidnext FROM box WHERE name = new.box) WHERE guid = new.guid AND box = new.box AND uid = new.uid;
   UPDATE box SET
      messages = messages + 1,
      recent = recent + 1,
      unseen = unseen + 1,
      uidnext = uidnext + 1
   WHERE name = new.box ;
END ;

CREATE TRIGGER IF NOT EXISTS mail_after_delete AFTER DELETE ON mail
BEGIN
   UPDATE box SET
      messages = messages - 1
   WHERE name = old.box ;
END ;

CREATE TRIGGER IF NOT EXISTS mail_after_update AFTER UPDATE OF flags ON mail
BEGIN
   UPDATE mail SET flags = flags & ~(32) WHERE box = new.box;
   UPDATE box SET
      recent = 0,
      unseen = unseen + ((old.flags & 8) AND ((new.flags & 8) != (old.flags & 8))) - ((new.flags & 8) AND ((new.flags & 8) != (old.flags & 8)))
   WHERE name = old.box ;
END ;

INSERT OR REPLACE INTO box (name,ro) VALUES ('INBOX', 0);
"""),
)

HOME = str(os.environ['HOME'])
EXE_PREFIX = "@EXE_PREFIX@"
OIODIR = HOME + '/.oio'
SDSDIR = OIODIR + '/sds'
CFGDIR = SDSDIR + '/conf'
RUNDIR = SDSDIR + '/run'
LOGDIR = SDSDIR + '/logs'
SPOOLDIR = SDSDIR + '/spool'
DATADIR = SDSDIR + '/data'
WATCHDIR = SDSDIR + '/conf/watch'
TMPDIR = '/tmp'
CODEDIR = '@CMAKE_INSTALL_PREFIX@'
LIBDIR = CODEDIR + '/@LD_LIBDIR@'
PATH = HOME+"/.local/bin:@CMAKE_INSTALL_PREFIX@/bin:/usr/sbin"
port = 6000

# Constants for the configuration of oio-bootstrap
NS = 'ns'
IP = 'ip'
SVC_NB = 'count'
ALLOW_REDIS = 'redis'
OPENSUSE = 'opensuse'
ZOOKEEPER = 'zookeeper'
MONITOR_PERIOD = 'monitor_period'
M1_REPLICAS = 'directory_replicas'
M2_REPLICAS = 'container_replicas'
M2_VERSIONS = 'container_versions'
M2_STGPOL = 'storage_policy'
SQLX_REPLICAS = 'sqlx_replicas'
PROFILE = 'profile'
PORT_START = 'port_start'
CHUNK_SIZE = 'chunk_size'
ACCOUNT_ID = 'account_id'
BUCKET_NAME = 'bucket_name'
COMPRESSION = 'compression'
APPLICATION_KEY = 'application_key'
KEY_FILE='key_file'

defaults = {
    'NS': 'OPENIO',
    'IP': '127.0.0.1',
    'NB_CS': 1,
    'NB_M0': 1,
    'NB_M1': 1,
    'NB_M2': 1,
    'NB_SQLX': 1,
    'NB_RAWX': 3,
    'NB_RAINX': 0,
    'NB_ECD': 1,
    'REPLI_SQLX': 1,
    'REPLI_M2': 1,
    'REPLI_M1': 1,
    'COMPRESSION': "off"}

# XXX When /usr/sbin/httpd is present we suspect a Redhat/Centos/Fedora
# environment. If not, we consider being in a Ubuntu/Debian environment.
# Sorry for the others, we cannot manage everything in this helper script for
# developers, so consider using the standard deployment tools for your
# prefered Linux distribution.
HTTPD_BINARY = '/usr/sbin/httpd'
APACHE2_MODULES_SYSTEM_DIR = ''
if not os.path.exists('/usr/sbin/httpd'):
    HTTPD_BINARY = '/usr/sbin/apache2'
    APACHE2_MODULES_SYSTEM_DIR = '/usr/lib/apache2/'


def config(env):
    return '{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf'.format(**env)


def watch(env):
    return '{WATCHDIR}/{NS}-{SRVTYPE}-{SRVNUM}.yml'.format(**env)


def wsgi(env):
    return '{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.wsgi'.format(**env)


def gridinit(env):
    return '{CFGDIR}/gridinit.conf'.format(**env)


def mkdir_noerror(d):
    try:
        os.makedirs(d, 0700)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise e


def type2exe(t):
    return EXE_PREFIX + '-' + str(t) + '-server'


def next_port():
    global port
    res, port = port, port + 1
    return res


def generate(options):
    def getint(v, default):
        if v is None:
            return int(default)
        return int(v)

    global port
    port = getint(options.get('port-start'), 6000)

    final_conf = {}
    final_services = {}

    port_proxy = next_port()
    port_ecd = next_port()

    versioning = 1
    stgpol = "SINGLE"

    meta1_replicas = getint(options.get(M1_REPLICAS), defaults['REPLI_M1'])
    meta2_replicas = getint(options.get(M2_REPLICAS), defaults['REPLI_M2'])
    sqlx_replicas = getint(options.get(SQLX_REPLICAS), defaults['REPLI_SQLX'])

    if options.get(M2_VERSIONS):
        versioning = options[M2_VERSIONS]
    if options.get(M2_STGPOL):
        stgpol = options[M2_STGPOL]
    ns = options.get('ns') or defaults['NS']
    ip = options.get('ip') or defaults['IP']
    backblaze_account_id = options.get('backblaze', {}).get(ACCOUNT_ID)
    backblaze_bucket_name = options.get('backblaze', {}).get(BUCKET_NAME)
    backblaze_app_key = options.get('backblaze', {}).get(APPLICATION_KEY)
    key_file = options.get(KEY_FILE, CFGDIR + '/' + 'application_keys.cfg')
    ENV = dict(IP=ip,
               NS=ns,
               HOME=HOME,
               EXE_PREFIX=EXE_PREFIX,
               PATH=PATH,
               LIBDIR=LIBDIR,
               OIODIR=OIODIR,
               SDSDIR=SDSDIR,
               TMPDIR=TMPDIR,
               DATADIR=DATADIR,
               CFGDIR=CFGDIR,
               RUNDIR=RUNDIR,
               SPOOLDIR=SPOOLDIR,
               LOGDIR=LOGDIR,
               CODEDIR=CODEDIR,
               WATCHDIR=WATCHDIR,
               UID=str(os.geteuid()),
               GID=str(os.getgid()),
               USER=str(pwd.getpwuid(os.getuid()).pw_name),
               GROUP=str(grp.getgrgid(os.getgid()).gr_name),
               VERSIONING=versioning,
               STGPOL=stgpol,
               PORT_PROXYD=port_proxy,
               PORT_ECD=port_ecd,
               M2_REPLICAS=meta2_replicas,
               M2_DISTANCE=str(1),
               SQLX_REPLICAS=sqlx_replicas,
               SQLX_DISTANCE=str(1),
               APACHE2_MODULES_SYSTEM_DIR=APACHE2_MODULES_SYSTEM_DIR,
               BACKBLAZE_ACCOUNT_ID=backblaze_account_id,
               BACKBLAZE_BUCKET_NAME=backblaze_bucket_name,
               BACKBLAZE_APPLICATION_KEY=backblaze_app_key,
               KEY_FILE=key_file,
               HTTPD_BINARY=HTTPD_BINARY)

    def merge_env(add):
        env = dict(ENV)
        env.update(add)
        if options.get(PROFILE) == "valgrind":
            orig_exe = env.get('EXE', env['EXE_PREFIX'])
            new_exe = "valgrind --leak-check=full --leak-resolution=high\
 --trace-children=yes --log-file=/tmp/%q{ORIG_EXE}.%p.valgrind " + orig_exe
            env['env.ORIG_EXE'] = orig_exe
            env['EXE'] = new_exe
            env['env.G_DEBUG'] = "gc-friendly"
            env['env.G_SLICE'] = "always-malloc"
        return env

    def subenv(add):
        env = merge_env(add)
        env['VOLUME'] = '{DATADIR}/{NS}-{SRVTYPE}-{SRVNUM}'.format(**env)
        return env

    ENV['CHUNK_SIZE'] = getint(options.get(CHUNK_SIZE), 1024*1024)
    ENV['MONITOR_PERIOD'] = getint(options.get(MONITOR_PERIOD), 5)
    if options.get(ZOOKEEPER):
        ENV['NOZK'] = ''
    else:
        ENV['NOZK'] = '#'

    mkdir_noerror(SDSDIR)
    mkdir_noerror(CODEDIR)
    mkdir_noerror(DATADIR)
    mkdir_noerror(CFGDIR)
    mkdir_noerror(WATCHDIR)
    mkdir_noerror(RUNDIR)
    mkdir_noerror(LOGDIR)

    def add_service(env):
        t = env['SRVTYPE']
        if t not in final_services:
            final_services[t] = []

        out = {'num': env['SRVNUM']}
        if 'PORT' in env:
            out['addr'] = '%s:%s' % (env['IP'], env['PORT'])
        if 'VOLUME' in env:
            out['path'] = env['VOLUME']
        final_services[t].append(out)

    # gridinit header
    with open(gridinit(ENV), 'w+') as f:
        tpl = Template(template_gridinit_header)
        f.write(tpl.safe_substitute(ENV))

    # conscience
    nb_conscience = getint(options['conscience'].get(SVC_NB),
                           defaults['NB_CS'])
    if nb_conscience:
        cs = list()
        with open('{CFGDIR}/{NS}-policies.conf'.format(**ENV), 'w+') as f:
            tpl = Template(template_conscience_policies)
            f.write(tpl.safe_substitute(ENV))
        with open('{CFGDIR}/{NS}-services.conf'.format(**ENV), 'w+') as f:
            tpl = Template(template_conscience_services)
            f.write(tpl.safe_substitute(ENV))
        # Prepare a list of consciences
        for num in range(nb_conscience):
            cs.append((num + 1, next_port(), next_port()))
        ENV.update({
            'CS_ALL_PUB': ','.join(
                [str(ip)+':'+str(pub) for _, pub, _ in cs]),
            'CS_ALL_HUB': ','.join(
                ['tcp://'+str(ip)+':'+str(hub) for _, _, hub in cs]),
        })

        for num, pub, hub in cs:
            env = subenv({'SRVTYPE': 'conscience', 'SRVNUM': num,
                          'PORT': pub, 'PORT_HUB': hub})
            add_service(env)
            with open(gridinit(env), 'a+') as f:
                tpl = Template(template_conscience_gridinit)
                f.write(tpl.safe_substitute(env))
            with open(config(env), 'w+') as f:
                tpl = Template(template_conscience_service)
                f.write(tpl.safe_substitute(env))

    # meta* + sqlx
    def generate_meta(t, n, tpl):
        env = subenv({'SRVTYPE': t, 'SRVNUM': n, 'PORT': next_port(),
                      'EXE': ENV['EXE_PREFIX'] + '-' + t + '-server'})
        add_service(env)
        # gridinit config
        tpl = Template(tpl)
        with open(gridinit(env), 'a+') as f:
            f.write(tpl.safe_substitute(env))
            for key in (k for k in env.iterkeys() if k.startswith("env.")):
                f.write("%s=%s\n" % (key, env[key]))
        # watcher
        tpl = Template(template_meta_watch)
        with open(watch(env), 'w+') as f:
            f.write(tpl.safe_substitute(env))

    # meta0
    nb_meta0 = max(getint(options['meta0'].get(SVC_NB), defaults['NB_M0']),
                   defaults['NB_M0'])
    if nb_meta0:
        for i in range(nb_meta0):
            generate_meta('meta0', i + 1, template_gridinit_meta)

    # meta1
    nb_meta1 = max(getint(options['meta1'].get(SVC_NB), defaults['NB_M1']),
                   meta1_replicas)
    if nb_meta1:
        for i in range(nb_meta1):
            generate_meta('meta1', i + 1, template_gridinit_meta)

    # meta2
    nb_meta2 = max(getint(options['meta2'].get(SVC_NB), defaults['NB_M2']),
                   meta2_replicas)
    if nb_meta2:
        for i in range(nb_meta2):
            generate_meta('meta2', i + 1, template_gridinit_meta)

    # sqlx
    nb_sqlx = getint(options['sqlx'].get(SVC_NB), sqlx_replicas)
    if nb_sqlx:
        for i in range(nb_sqlx):
            generate_meta('sqlx', i + 1, template_gridinit_sqlx)

    # RAWX
    nb_rawx = getint(options['rawx'].get(SVC_NB), defaults['NB_RAWX'])
    compression = options['rawx'].get(COMPRESSION, "off")
    if nb_rawx:
        for num in range(nb_rawx):
            env = subenv({'SRVTYPE': 'rawx',
                          'SRVNUM': num + 1,
                          'PORT': next_port(),
                          'COMPRESSION': compression,
                          'EXTRASLOT': ('rawx-even' if num % 2 else 'rawx-odd')
                          })
            add_service(env)
            # gridinit
            tpl = Template(template_gridinit_httpd)
            with open(gridinit(env), 'a+') as f:
                f.write(tpl.safe_substitute(env))
            # service
            tpl = Template(template_rawx_service)
            to_write = tpl.safe_substitute(env)
            if options.get(OPENSUSE, None):
                to_write = re.sub(r"LoadModule.*mpm_worker.*", "", to_write)
            with open(config(env), 'w+') as f:
                f.write(to_write)
            # watcher
            tpl = Template(template_rawx_watch)
            to_write = tpl.safe_substitute(env)
            with open(watch(env), 'w+') as f:
                f.write(to_write)

    # redis
    env = subenv({'SRVTYPE': 'redis', 'SRVNUM': 1, 'PORT': 6379})
    add_service(env)
    if options.get(ALLOW_REDIS):
        with open(gridinit(env), 'a+') as f:
            tpl = Template(template_redis_gridinit)
            f.write(tpl.safe_substitute(env))
        with open(config(env), 'w+') as f:
            tpl = Template(template_redis)
            f.write(tpl.safe_substitute(env))
        with open(watch(env), 'w+') as f:
            tpl = Template(template_redis_watch)
            f.write(tpl.safe_substitute(env))

    # proxy
    env = subenv({'SRVTYPE': 'proxy', 'SRVNUM': 1, 'PORT': port_proxy})
    add_service(env)
    with open(gridinit(env), 'a+') as f:
        tpl = Template(template_proxy_gridinit)
        f.write(tpl.safe_substitute(env))

    # ecd
    env = subenv({'SRVTYPE': 'ecd', 'SRVNUM': 1, 'PORT': port_ecd})
    add_service(env)
    tpl = Template(template_gridinit_httpd)
    with open(gridinit(env), 'a+') as f:
        f.write(tpl.safe_substitute(env))
    # service
    tpl = Template(template_wsgi_service_host)
    to_write = tpl.safe_substitute(env)
    if options.get(OPENSUSE, False):
        to_write = re.sub(r"LoadModule.*mpm_worker.*", "", to_write)
    with open(config(env), 'w+') as f:
        f.write(to_write)
    # service desc
    tpl = Template(template_wsgi_service_descr)
    to_write = tpl.safe_substitute(env)
    with open(wsgi(env), 'w+') as f:
        f.write(to_write)

    # account
    env = subenv({'SRVTYPE': 'account', 'SRVNUM': 1, 'PORT': next_port()})
    add_service(env)
    with open(gridinit(env), 'a+') as f:
        tpl = Template(template_account_gridinit)
        f.write(tpl.safe_substitute(env))
    with open(config(env), 'w+') as f:
        tpl = Template(template_account)
        f.write(tpl.safe_substitute(env))
    with open(watch(env), 'w+') as f:
        tpl = Template(template_account_watch)
        f.write(tpl.safe_substitute(env))

    # rdir
    env = subenv({'SRVTYPE': 'rdir', 'SRVNUM': 1, 'PORT': next_port()})
    add_service(env)
    with open(gridinit(env), 'a+') as f:
        tpl = Template(template_rdir_gridinit)
        f.write(tpl.safe_substitute(env))
    with open(config(env), 'w+') as f:
        tpl = Template(template_rdir)
        f.write(tpl.safe_substitute(env))
    with open(watch(env), 'w+') as f:
        tpl = Template(template_rdir_watch)
        f.write(tpl.safe_substitute(env))

    # Event agent configuration
    env = subenv({'SRVTYPE': 'event-agent', 'SRVNUM': 1})
    add_service(env)
    with open(CFGDIR + '/' + 'event-agent.conf', 'w+') as f:
        tpl = Template(template_event_agent)
        f.write(tpl.safe_substitute(env))
    with open(CFGDIR + '/' + 'event-handlers.conf', 'w+') as f:
        tpl = Template(template_event_agent_handlers)
        f.write(tpl.safe_substitute(env))

    # Conscience agent configuration
    env = subenv({'SRVTYPE': 'conscience-agent', 'SRVNUM': 1})
    with open(CFGDIR + '/' + 'conscience-agent.yml', 'w+') as f:
        tpl = Template(template_conscience_agent)
        f.write(tpl.safe_substitute(env))

    # sqlx schemas
    base = '{CFGDIR}/sqlx/schemas'.format(**ENV)
    mkdir_noerror(base)
    for name, content in sqlx_schemas:
        with open(base + '/' + name, 'w+') as f:
            f.write(content)

    # gridinit header
    with open(gridinit(ENV), 'a+') as f:
        tpl = Template(template_gridinit_ns)
        f.write(tpl.safe_substitute(ENV))
    # system config
    with open('{OIODIR}/sds.conf'.format(**ENV), 'w+') as f:
        tpl = Template(template_local_header)
        f.write(tpl.safe_substitute(ENV))
        tpl = Template(template_local_ns)
        f.write(tpl.safe_substitute(ENV))

    with open('{KEY_FILE}'.format(**ENV), 'w+') as f:
        tpl = Template(template_credentials)
        f.write(tpl.safe_substitute(ENV))
        
    # ensure volumes
    for srvtype in final_services:
        for rec in final_services[srvtype]:
            if 'path' in rec:
                mkdir_noerror(rec['path'])

    final_conf["services"] = final_services
    final_conf["namespace"] = ns
    final_conf["chunk_size"] = ENV['CHUNK_SIZE']
    final_conf["storage_policy"] = stgpol
    final_conf["account"] = 'test_account'
    final_conf["sds_path"] = SDSDIR
    final_conf["proxy"] = final_services['proxy'][0]['addr']
    final_conf[M2_REPLICAS] = meta2_replicas
    final_conf[M1_REPLICAS] = meta1_replicas
    with open('{CFGDIR}/test.yml'.format(**ENV), 'w+') as f:
        f.write(yaml.dump(final_conf))
    return final_conf


def dump_config(conf):
    print 'PROXY=%s' % conf['proxy']
    print 'REPLI_CONTAINER=%s' % conf[M2_REPLICAS]
    print 'REPLI_DIRECTORY=%s' % conf[M1_REPLICAS]


def main():
    parser = argparse.ArgumentParser(description='OpenIO bootstrap tool')

    parser.add_argument("namespace", help="Namespace name")
    parser.add_argument("ip", help="IP to use")
    parser.add_argument("-c", "--conf", action="store", dest='config',
                        help="Bootstrap configuration file")
    parser.add_argument("-d", "--dump", action="store_true", default=False,
                        dest='dump_config', help="Dump results")

    options = parser.parse_args()
    opts = {}
    opts[ZOOKEEPER] = True
    opts['conscience'] = {SVC_NB: None}
    opts['meta0'] = {SVC_NB: None}
    opts['meta1'] = {SVC_NB: None}
    opts['meta2'] = {SVC_NB: None}
    opts['sqlx'] = {SVC_NB: None}
    opts['rawx'] = {SVC_NB: None}

    if options.config:
        with open(options.config, 'r') as f:
            data = yaml.load(f)
            if data:
                opts.update(data)
    opts['ns'] = options.namespace
    opts['ip'] = options.ip
    final_conf = generate(opts)
    if options.dump_config:
        dump_config(final_conf)


if __name__ == '__main__':
    main()
