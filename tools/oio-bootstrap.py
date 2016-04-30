#!/usr/bin/env python

# @EXE_PREFIX@-bootstrap.py, a script initating a local configuration of OpenIO SDS.
# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
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
import json
import os
import pwd
from string import Template
import re

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
MaxClients 10
StartServers 5
MinSpareServers 5
MaxSpareServers 10
</IfModule>

<IfModule worker.c>
StartServers 1
MaxClients 10
MinSpareThreads 2
MaxSpareThreads 10
ThreadsPerChild 10
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

template_rainx_service = """
LoadModule mpm_worker_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mpm_worker.so
LoadModule authz_core_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_authz_core.so
LoadModule setenvif_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_setenvif.so
LoadModule dav_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_dav.so
# Do not chang
LoadModule mime_module ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mime.so
LoadModule dav_rainx_module @APACHE2_MODULES_DIRS@/mod_dav_rainx.so

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
TypesConfig /etc/mime.types

User  ${USER}
Group ${GROUP}

LogFormat "%h %l %t \\"%r\\" %>s %b %D" log/common
ErrorLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-errors.log
SetEnvIf Request_URI "/(stat|info)$" nolog
CustomLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-${SRVNUM}-access.log log/common env=!nolog
LogLevel info

<IfModule mod_env.c>
SetEnv nokeepalive 1
SetEnv downgrade-1.0 1
SetEnv force-response-1.0 1
</IfModule>

<IfModule prefork.c>
MaxClients 10
StartServers 5
MinSpareServers 5
MaxSpareServers 10
</IfModule>

<IfModule worker.c>
StartServers 1
MaxClients 10
MinSpareThreads 2
MaxSpareThreads 10
ThreadsPerChild 10
MaxRequestsPerChild 0
</IfModule>

DavDepthInfinity Off

grid_namespace ${NS}
grid_dir_run ${RUNDIR}

<Directory />
DAV rainx
AllowOverride None
Require all granted
</Directory>

<VirtualHost ${IP}:${PORT}>
# DO NOT REMOVE (even if empty) !
</VirtualHost>
"""

template_meta_watch = """
host: ${IP}
port: ${PORT}
type: ${SRVTYPE}
location: hem.oio.vol${SRVNUM}
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

stats:
    - {type: http, path: /status, parser: json}
    - {type: system}
"""

template_rainx_watch = """
host: ${IP}
port: ${PORT}
type: rainx
checks:
    - {type: http, uri: /info}

stats:
    - {type: rawx, path: /stat}
    - {type: system}
"""

template_rawx_watch = """
host: ${IP}
port: ${PORT}
type: rawx
location: hem.oio.vol${SRVNUM}
checks:
    - {type: http, uri: /info}

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
param_option.compression=none
param_option.container_max_size=50000000
param_option.FLATNS_hash_offset=0
param_option.FLATNS_hash_size=0
param_option.FLATNS_hash_bitlength=17
param_option.storage_policy=${STGPOL}

param_storage_conf=${CFGDIR}/${NS}-policies.conf

param_service.meta0.score_timeout=3600
param_service.meta0.score_variation_bound=5
param_service.meta0.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.meta1.score_timeout=120
param_service.meta1.score_variation_bound=5
param_service.meta1.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.meta2.score_timeout=120
param_service.meta2.score_variation_bound=5
param_service.meta2.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.rawx.score_timeout=120
param_service.rawx.score_variation_bound=5
param_service.rawx.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.sqlx.score_timeout=120
param_service.sqlx.score_variation_bound=5
param_service.sqlx.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.rdir.score_timeout=120
param_service.rdir.score_variation_bound=5
param_service.rdir.score_expr=((num stat.cpu)>0) * ((num stat.io)>0) * ((num stat.space)>1) * root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))

param_service.rainx.score_timeout=120
param_service.rainx.score_variation_bound=5
param_service.rainx.score_expr=(num stat.cpu)

param_service.redis.score_timeout=120
param_service.redis.score_variation_bound=5
param_service.redis.score_expr=(num stat.cpu)

param_service.oiofs.score_timeout=120
param_service.oiofs.score_variation_bound=5
param_service.oiofs.score_expr=(num stat.cpu)

param_service.account.score_timeout=120
param_service.account.score_variation_bound=5
param_service.account.score_expr=(num stat.cpu)

param_service.echo.score_timeout=120
param_service.echo.score_variation_bound=5
param_service.echo.score_expr=(num stat.cpu)
"""

template_conscience_policies = """
[STORAGE_POLICY]
SINGLE=NONE:NONE:NONE
TWOCOPIES=NONE:DUPONETWO:NONE
THREECOPIES=NONE:DUPONETHREE:NONE
FIVECOPIES=NONE:DUPONEFIVE:NONE
RAIN=NONE:RAIN:NONE

[STORAGE_CLASS]
# <CLASS> = FALLBACK[,FALLBACK]...
SUPERFAST=PRETTYGOOD,REASONABLYSLOW,NONE
PRETTYGOOD=REASONABLYSLOW,NONE
REASONABLYSLOW=NONE

[DATA_SECURITY]
DUPONETWO=DUP:distance=1|nb_copy=2
DUPONETHREE=DUP:distance=1|nb_copy=3
DUPONEFIVE=DUP:distance=1|nb_copy=5
RAIN=RAIN:k=6|m=2|algo=liber8tion|distance=1

[DATA_TREATMENTS]
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

template_gridinit_rawx = """
[Service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE},${IP}:${PORT}
command=${HTTPD_BINARY} -D FOREGROUND -f ${CFGDIR}/${NS}-${SRVTYPE}-${SRVNUM}.conf
enabled=true
start_at_boot=false
on_die=respawn
"""

template_gridinit_rainx = """
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
event-agent=beanstalk://127.0.0.1:11300
#event-agent=ipc://${RUNDIR}/event-agent.sock
conscience=${CS_ALL_PUB}
"""

template_event_agent = """
[event-agent]
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

[filter:account_update]
use = egg:oio#account_update

[filter:volume_index]
use = egg:oio#volume_index

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
   uidvalidity INT NOT NULL DEFAULT 0);

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

CREATE TABLE IF NOT EXISTS mailattr (
   guid TEXT NOT NULL,
   k TEXT NOT NULL,
   v TEXT NOT NULL,
   PRIMARY KEY (guid,k));

CREATE INDEX IF NOT EXISTS boxattr_index_by_box ON boxattr(box);
CREATE INDEX IF NOT EXISTS mail_index_by_box ON mail(box);
CREATE INDEX IF NOT EXISTS mailattr_index_by_mail ON mailattr(guid);

CREATE TRIGGER IF NOT EXISTS mail_after_add AFTER INSERT ON mail
BEGIN
   UPDATE box SET
      messages = messages + 1,
      recent = recent + 1,
      unseen = unseen + 1,
      uidnext = uidnext + 1
   WHERE name = new.box ;
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

defaults_small = {'NB_CS':1, 'NB_M0':1, 'NB_M1':1, 'NB_M2':1, 'NB_SQLX':1,
            'NB_RAWX':2, 'NB_RAINX':1}

defaults_multi = {'NB_CS':3, 'NB_M0':1, 'NB_M1':5, 'NB_M2':5, 'NB_SQLX':5,
            'NB_RAWX':7, 'NB_RAINX':3}

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


def record(env):
    out = {'addr':str(env['IP']) + ':' + str(env['PORT']), 'num':env['SRVNUM']}
    if 'VOLUME' in env:
        out['path'] = env['VOLUME']
    return out

def config(env):
    return '{CFGDIR}/{NS}-{SRVTYPE}-{SRVNUM}.conf'.format(**env)

def watch(env):
    return '{WATCHDIR}/{NS}-{SRVTYPE}-{SRVNUM}.yml'.format(**env)

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


def generate(ns, ip, options={}, defaults={}):
    def getint(v, default):
        if v is None:
            return int(default)
        return int(v)

    global port
    port = getint(options.PORT_START, 6000)

    all_services = {}

    port_proxy = next_port()
    port_event_agent = next_port()
    port_rdir = next_port()

    versioning = 1
    stgpol = "SINGLE"

    meta2_replicas = getint(options.M2_REPLICAS, defaults['NB_M2'])
    sqlx_replicas = getint(options.SQLX_REPLICAS, defaults['NB_SQLX'])

    if options.M2_VERSIONS is not None:
        versioning = int(options.M2_VERSIONS)
    if options.M2_STGPOL is not None:
        stgpol = str(options.M2_STGPOL)

    ENV = dict(IP=ip, NS=ns, HOME=HOME, EXE_PREFIX=EXE_PREFIX,
               PATH=PATH, LIBDIR=LIBDIR,
               OIODIR=OIODIR, SDSDIR=SDSDIR, TMPDIR=TMPDIR,
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
               M2_REPLICAS=meta2_replicas,
               M2_DISTANCE=str(1),
               SQLX_REPLICAS=sqlx_replicas,
               SQLX_DISTANCE=str(1),
               APACHE2_MODULES_SYSTEM_DIR=APACHE2_MODULES_SYSTEM_DIR,
               HTTPD_BINARY=HTTPD_BINARY)

    def merge_env(add):
        env = dict(ENV)
        env.update(add)
        return env
    def subenv(add):
        env = merge_env(add)
        env['VOLUME'] = '{DATADIR}/{NS}-{SRVTYPE}-{SRVNUM}'.format(**env)
        return env

    ENV['CHUNK_SIZE'] = getint(options.CHUNK_SIZE, 1024*1024)
    ENV['MONITOR_PERIOD'] = getint(options.MONITOR_PERIOD, 5)
    if options.NO_ZOOKEEPER is not None:
        ENV['NOZK'] = '#'
    else:
        ENV['NOZK'] = ''

    mkdir_noerror(SDSDIR)
    mkdir_noerror(CODEDIR)
    mkdir_noerror(DATADIR)
    mkdir_noerror(CFGDIR)
    mkdir_noerror(WATCHDIR)
    mkdir_noerror(RUNDIR)
    mkdir_noerror(LOGDIR)

    def add_service(env):
        t = env['SRVTYPE']
        if t not in all_services:
            all_services[t] = []
        all_services[t].append(record(env))

    # gridinit header
    with open(gridinit(ENV), 'w+') as f:
        tpl = Template(template_gridinit_header)
        f.write(tpl.safe_substitute(ENV))

    # consciences
    if options.NO_CS is None:
        cs = list()
        with open('{CFGDIR}/{NS}-policies.conf'.format(**ENV), 'w+') as f:
            tpl = Template(template_conscience_policies)
            f.write(tpl.safe_substitute(ENV))
        # Prepare a list of consciences
        for num in range(1, 1+getint(options.NB_CS, defaults['NB_CS'])):
            cs.append((num, next_port(), next_port()))
        ENV.update({
                    'CS_ALL_PUB': ','.join([str(ip)+':'+str(pub) for _,pub,_ in cs]),
                    'CS_ALL_HUB': ','.join(['tcp://'+str(ip)+':'+str(hub) for _,_,hub in cs]),
        })
        for num, pub, hub in cs:
            env = subenv({'SRVTYPE':'conscience', 'SRVNUM':num, 'PORT':pub, 'PORT_HUB':hub})
            add_service(env)
            with open(gridinit(env), 'a+') as f:
                tpl = Template(template_conscience_gridinit)
                f.write(tpl.safe_substitute(env))
            with open(config(env), 'w+') as f:
                tpl = Template(template_conscience_service)
                f.write(tpl.safe_substitute(env))

    # meta* + sqlx
    def generate_meta(t,n,tpl):
        env = subenv({'SRVTYPE':t, 'SRVNUM':n, 'PORT':next_port(),
                      'EXE':EXE_PREFIX + '-' + t + '-server'})
        add_service(env)
        # gridinit config
        tpl = Template(tpl)
        with open(gridinit(env), 'a+') as f:
            f.write(tpl.safe_substitute(env))
        # watcher
        tpl = Template(template_meta_watch)
        with open(watch(env), 'w+') as f:
            f.write(tpl.safe_substitute(env))

    if options.NO_META0 is None:
        for i in range(1, 1+getint(options.NB_META0, defaults['NB_M0'])):
            generate_meta('meta0', i, template_gridinit_meta)
    if options.NO_META1 is None:
        for i in range(1, 1+getint(options.NB_META1, defaults['NB_M1'])):
            generate_meta('meta1', i, template_gridinit_meta)
    if options.NO_META2 is None:
        for i in range(1, 1+getint(options.NB_META2, meta2_replicas)):
            generate_meta('meta2', i, template_gridinit_meta)
    if options.NO_SQLX is None:
        for i in range(1, 1+getint(options.NB_SQLX, sqlx_replicas)):
            generate_meta('sqlx', i, template_gridinit_sqlx)

    # RAWX
    if options.NO_RAWX is None:
        for num in range(1, 1+getint(options.NB_RAWX, defaults['NB_RAWX'])):
            env = subenv({'SRVTYPE':'rawx', 'SRVNUM':num, 'PORT':next_port()})
            add_service(env)
            # gridinit
            tpl = Template(template_gridinit_rawx)
            with open(gridinit(env), 'a+') as f:
                f.write(tpl.safe_substitute(env))
            # service
            tpl = Template(template_rawx_service)
            to_write = tpl.safe_substitute(env)
            if options.OPENSUSE:
                to_write = re.sub(r"LoadModule.*mpm_worker.*", "", to_write)
            with open(config(env), 'w+') as f:
                f.write(to_write)
            # watcher
            tpl = Template(template_rawx_watch)
            to_write = tpl.safe_substitute(env)
            with open(watch(env), 'w+') as f:
                f.write(to_write)

    # rainx
    if options.NO_RAINX is None:
        for num in range(1, 1+getint(options.NB_RAINX, defaults['NB_RAINX'])):
            env = subenv({'SRVTYPE':'rainx', 'SRVNUM':num, 'PORT':next_port()})
            add_service(env)
            # gridinit
            tpl = Template(template_gridinit_rainx)
            with open(gridinit(env), 'a+') as f:
                f.write(tpl.safe_substitute(env))
            # service
            tpl = Template(template_rainx_service)
            to_write = tpl.safe_substitute(env)
            if options.OPENSUSE:
                to_write = re.sub(r"LoadModule.*mpm_worker.*", "", to_write)
            with open(config(env), 'w+') as f:
                f.write(to_write)
            # watcher
            tpl = Template(template_rainx_watch)
            to_write = tpl.safe_substitute(env)
            with open(watch(env), 'w+') as f:
                f.write(to_write)

    # redis
    env = subenv({'SRVTYPE':'redis', 'SRVNUM':1, 'PORT':6379})
    add_service(env)
    if options.ALLOW_REDIS is not None:
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
    env = subenv({'SRVTYPE':'proxy', 'SRVNUM': 1, 'PORT':port_proxy})
    add_service(env)
    with open(gridinit(env), 'a+') as f:
        tpl = Template(template_proxy_gridinit)
        f.write(tpl.safe_substitute(env))

    # account
    env = subenv({'SRVTYPE':'account','SRVNUM':1, 'PORT':next_port()})
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
    env = subenv({'SRVTYPE':'rdir', 'SRVNUM':1, 'PORT':next_port()})
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
    env = subenv({'SRVTYPE':'event-agent', 'SRVNUM':1, 'PORT': port_event_agent})
    add_service(env)
    with open(CFGDIR + '/' + 'event-agent.conf', 'w+') as f:
        tpl = Template(template_event_agent)
        f.write(tpl.safe_substitute(env))
    with open(CFGDIR + '/' + 'event-handlers.conf', 'w+') as f:
        tpl = Template(template_event_agent_handlers)
        f.write(tpl.safe_substitute(env))

    # Conscience agent configuration
    env = subenv({'SRVTYPE':'conscience-agent', 'SRVNUM':1, 'PORT': port_event_agent})
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

    # ensure the services'es volumes
    for srvtype in all_services:
        for rec in all_services[srvtype]:
            if 'path' in rec:
                mkdir_noerror(rec['path'])

    all_services["namespace"] = ns
    all_services["chunk_size"] = ENV['CHUNK_SIZE']
    all_services["stgpol"] = stgpol
    all_services["account"] = 'test_account'
    all_services["sds_path"] = SDSDIR
    with open('{CFGDIR}/test.conf'.format(**ENV), 'w+') as f:
        f.write(json.dumps(all_services, indent=2, sort_keys=True))


def main():
    from optparse import OptionParser as OptionParser
    parser = OptionParser()

    parser.add_option("-b", "--big",
                      action="store_true", dest="BIG",
                      help="By default, deploy manny services")

    parser.add_option("-B", "--bucket-replicas",
                      action="store", type="int", dest="M2_REPLICAS",
                      help="Number of containers replicas")
    parser.add_option("-X", "--sqlx-replicas",
                      action="store", type="int", dest="SQLX_REPLICAS",
                      help="Number of bases replicas")
    parser.add_option("-V", "--versioning",
                      action="store", type="int", dest="M2_VERSIONS",
                      help="Number of contents versions")
    parser.add_option("-S", "--stgpol",
                      action="store", type="string", dest="M2_STGPOL",
                      help="How many replicas for META2")
    parser.add_option("--opensuse",
                      action="store_true", dest="OPENSUSE",
                      help="Customize some config files for Opensuse")

    parser.add_option("--port",
                      action="store", type="int", dest="PORT_START")
    parser.add_option("--chunk-size",
                      action="store", type="int", dest="CHUNK_SIZE")
    parser.add_option("--no-zookeeper",
                      action="store_true", dest="NO_ZOOKEEPER")
    parser.add_option("--allow-redis",
                      action="store_true", dest="ALLOW_REDIS")
    parser.add_option("--monitor-period",
                      action="store", type="int", dest="MONITOR_PERIOD")

    parser.add_option("--no-conscience",
                      action="store_true", dest="NO_CS")
    parser.add_option("--no-meta0",
                      action="store_true", dest="NO_META0")
    parser.add_option("--no-meta1",
                      action="store_true", dest="NO_META1")
    parser.add_option("--no-meta2",
                      action="store_true", dest="NO_META2")
    parser.add_option("--no-sqlx",
                      action="store_true", dest="NO_SQLX")
    parser.add_option("--no-rawx",
                      action="store_true", dest="NO_RAWX")
    parser.add_option("--no-rainx",
                      action="store_true", dest="NO_RAINX")

    parser.add_option("--nb-conscience",
                      action="store", type="int", dest="NB_CS")
    parser.add_option("--nb-meta0",
                      action="store", type="int", dest="NB_META0")
    parser.add_option("--nb-meta1",
                      action="store", type="int", dest="NB_META1")
    parser.add_option("--nb-meta2",
                      action="store", type="int", dest="NB_META2")
    parser.add_option("--nb-sqlx",
                      action="store", type="int", dest="NB_SQLX")
    parser.add_option("--nb-rawx",
                      action="store", type="int", dest="NB_RAWX")
    parser.add_option("--nb-rainx",
                      action="store", type="int", dest="NB_RAINX")

    options, args = parser.parse_args()
    if options.BIG is not None:
        generate(args[0], args[1], options, defaults_multi)
    else:
        generate(args[0], args[1], options, defaults_small)


if __name__ == '__main__':
    main()
