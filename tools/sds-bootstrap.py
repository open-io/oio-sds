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

from string import Template
import os, errno, pwd, json

template_redis = """
daemonize no
pidfile ${RUNDIR}/redis.pid
port ${PORT_REDIS}
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
# slaveof <masterip> <masterport>
# masterauth <master-password>
slave-serve-stale-data yes
slave-read-only yes
repl-diskless-sync no
repl-diskless-sync-delay 5
# repl-ping-slave-period 10
# repl-timeout 60
repl-disable-tcp-nodelay no
# repl-backlog-size 1mb
# repl-backlog-ttl 3600
slave-priority 100
# min-slaves-to-write 3
# min-slaves-max-lag 10
# rename-command CONFIG ""
maxclients 100
maxmemory 10m
maxmemory-policy volatile-lru
# maxmemory-samples 3
appendonly no
# The name of the append only file (default: "appendonly.aof")
appendfilename "appendonly.aof"
# appendfsync always
appendfsync everysec
# appendfsync no
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
lua-time-limit 5000
slowlog-log-slower-than 10000
slowlog-max-len 128
latency-monitor-threshold 0
notify-keyspace-events ""
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-entries 512
list-max-ziplist-value 64
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
aof-rewrite-incremental-fsync yes
"""

template_redis_gridinit = """
[service.${NS}-redis-${SRVNUM}]
group=${NS},localhost,redis
on_die=respawn
enabled=true
start_at_boot=false
command=redis-server ${CFGDIR}/${NS}-redis-${SRVNUM}.conf
"""

template_flask_gridinit = """
[service.${NS}-flask]
group=${NS},localhost,flask
on_die=respawn
enabled=true
start_at_boot=false
command=/usr/bin/gunicorn --preload -w 2 -b ${IP}:${PORT} oio.sds.admin-flask:app
"""

template_account_server_gridinit = """
[service.${NS}-account-server]
group=${NS},localhost,account-server
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-svc-monitor -s OIO,${NS},account,1 -p 1 -m '${EXE_PREFIX}-account-monitor.py' -i '${NS}|account|${IP}:${PORT}' -c '${EXE_PREFIX}-account-server ${CFGDIR}/${NS}-account-server.conf'
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages
"""

template_proxy_gridinit = """
[service.${NS}-proxy]
group=${NS},localhost,proxy
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-proxy -s OIO,${NS},proxy -O Bind=${RUNDIR}/${NS}-proxy.sock ${IP}:${PORT} ${NS}
"""

template_nginx_gridinit = """
[service.${NS}-endpoint]
group=${NS},localhost,endpoint
on_die=respawn
enabled=true
start_at_boot=true
command=/usr/sbin/nginx -p ${CFGDIR} -c ${NS}-endpoint.conf
"""

template_rawx_service = """
LoadModule mpm_worker_module   ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mpm_worker.so
LoadModule authz_core_module   ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_authz_core.so
LoadModule dav_module          ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_dav.so
LoadModule mime_module         ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_mime.so
LoadModule dav_rawx_module     @APACHE2_MODULES_DIRS@/mod_dav_rawx.so

<IfModule !unixd_module>
	LoadModule unixd_module        ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_unixd.so
</IfModule>
<IfModule !log_config_module>
	LoadModule log_config_module   ${APACHE2_MODULES_SYSTEM_DIR}modules/mod_log_config.so
</IfModule>

Listen ${IP}:${PORT}
PidFile ${RUNDIR}/${NS}-${SRVTYPE}-httpd-${SRVNUM}.pid
ServerRoot ${TMPDIR}
ServerName localhost
ServerSignature Off
ServerTokens Prod
DocumentRoot ${RUNDIR}
TypesConfig /etc/mime.types

User  ${USER}
Group ${USER}

LogFormat "%h %l %t \\"%r\\" %>s %b %D" log/common
ErrorLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-httpd-${SRVNUM}-errors.log
CustomLog ${SDSDIR}/logs/${NS}-${SRVTYPE}-httpd-${SRVNUM}-access.log log/common
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

grid_hash_width 2
grid_hash_depth 1
grid_docroot ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
grid_namespace NS
grid_dir_run ${RUNDIR}
#grid_upload_blocksize 65536
#grid_upload_fileflags DIRECT|SYNC|NOATIME

<Directory />
DAV rawx
AllowOverride None
Require all granted
</Directory>

<VirtualHost ${IP}:${PORT}>
# DO NOT REMOVE (even if empty) !
</VirtualHost>
"""

template_agent = """
[General]
user=${UID}
group=${GID}

service_check_freq=1
cluster_update_freq=1

period_get_ns=1
period_get_srv=1
period_get_srvtype=1
period_push_srv=1

[server.inet]
port=${PORT}

[server.unix]
mode=0666
uid=${UID}
gid=${GID}
path=${RUNDIR}/agent.sock
"""

template_conscience = """
[General]
### Now is 'daemon' ignored (this is managed at the CLI)
### Now is 'pidfile' ingnored (managed at CLI too)
# Timeout on read operations
to_op=1000
# Timeout on accepting connections
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
plugins=conscience,stats,fallback

[Service]
namespace=${NS}
type=conscience
register=false
load_ns_info=false

[Plugin.stats]
path=${LIBDIR}/grid/msg_stats.so

[Plugin.fallback]
path=${LIBDIR}/grid/msg_fallback.so

[Plugin.conscience]
path=${LIBDIR}/grid/msg_conscience.so
param_namespace=${NS}
param_chunk_size=${CHUNK_SIZE}
param_score_timeout=86400

param_option.ns_status=MASTER
param_option.WORM=false
param_option.service_update_policy=meta2=NONE|${M2_REPLICAS}|${M2_DISTANCE};sqlx=KEEP|${SQLX_REPLICAS}|${SQLX_DISTANCE}|
param_option.automatic_open=true
param_option.meta2_max_versions=${VERSIONING}
param_option.storage_policy=${STGPOL}

param_option.meta2_check.put.GAPS=false
param_option.meta2_check.put.DISTANCE=false
param_option.meta2_check.put.STGCLASS=false
param_option.meta2_check.put.SRVINFO=false

param_storage_conf=${CFGDIR}/${NS}-conscience-policies.conf

param_service.default.score_timeout=30
param_service.default.score_variation_bound=5
param_service.default.score_expr=100

param_service.meta0.score_timeout=3600
param_service.meta0.score_variation_bound=5
param_service.meta0.score_expr=(num stat.cpu)

param_service.meta1.score_timeout=120
param_service.meta1.score_variation_bound=5
param_service.meta1.score_expr=(num stat.cpu)

param_service.meta2.score_timeout=120
param_service.meta2.score_variation_bound=5
param_service.meta2.score_expr=(num stat.cpu)

param_service.rawx.score_timeout=120
param_service.rawx.score_variation_bound=5
param_service.rawx.score_expr=(num stat.cpu)

param_service.sqlx.score_timeout=120
param_service.sqlx.score_variation_bound=5
param_service.sqlx.score_expr=(num stat.cpu)

param_service.echo.score_timeout=120
param_service.echo.score_variation_bound=5
param_service.echo.score_expr=(num stat.cpu)

param_service.account.score_timeout=120
param_service.account.score_variation_bound=5
param_service.account.score_expr=(num stat.cpu)
"""

template_conscience_policies = """
[STORAGE_POLICY]
SINGLE=NONE:NONE:NONE
TWOCOPIES=NONE:DUPONETWO:NONE
FIVECOPIES=NONE:DUPONEFIVE:NONE
RAIN=NONE:RAIN:NONE

[STORAGE_CLASS]
# <CLASS> = FALLBACK[,FALLBACK]...
SUPERFAST=PRETTYGOOD,REASONABLYSLOW,NONE
PRETTYGOOD=REASONABLYSLOW,NONE
REASONABLYSLOW=NONE

[DATA_SECURITY]
DUPONETWO=DUP:distance=1|nb_copy=2
DUPONEFIVE=DUP:distance=1|nb_copy=5
RAIN=RAIN:k=6|m=2|algo=liber8tion

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
env.PATH=${PATH}:${HOME}/.local/bin:${CODEDIR}/bin:/bin:/usr/bin:/usr/local/bin
env.LD_LIBRARY_PATH=${HOME}/.local/@LD_LIBDIR@:${LIBDIR}

#limit.core_size=-1
#limit.max_files=2048
#limit.stack_size=256

#include=${CFGDIR}/*-gridinit.conf

[service.gridagent]
group=common,localhost,agent
on_die=respawn
enabled=true
start_at_boot=true
command=${EXE_PREFIX}-cluster-agent -s OIO,${NS},agent ${CFGDIR}/agent.conf

"""

template_gridinit_ns = """

[service.${NS}-conscience]
group=${NS},localhost,conscience
on_die=respawn
enabled=true
start_at_boot=true
#command=${EXE_PREFIX}-daemon -s OIO,${NS},conscience ${CFGDIR}/${NS}-conscience.conf
command=${EXE_PREFIX}-daemon -q ${CFGDIR}/${NS}-conscience.conf

[service.${NS}-event-agent]
group=${NS},localhost,event
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE_PREFIX}-event-agent ${CFGDIR}/event-agent.conf
env.PYTHONPATH=${CODEDIR}/@LD_LIBDIR@/python2.7/site-packages
"""

template_gridinit_service = """
[service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE}
on_die=respawn
enabled=true
start_at_boot=false
command=${EXE} -s OIO,${NS},${SRVTYPE},${SRVNUM} -O Endpoint=${IP}:${PORT} ${NS} ${DATADIR}/${NS}-${SRVTYPE}-${SRVNUM}
"""

template_gridinit_rawx = """
[Service.${NS}-${SRVTYPE}-${SRVNUM}]
group=${NS},localhost,${SRVTYPE}
command=${EXE_PREFIX}-svc-monitor -s OIO,${NS},${SRVTYPE},${SRVNUM} -p 1 -m '${EXE_PREFIX}-rawx-monitor.py' -i '${NS}|${SRVTYPE}|${IP}:${PORT}' -c '${HTTPD_BINARY} -D FOREGROUND -f ${CFGDIR}/${NS}-${SRVTYPE}-httpd-${SRVNUM}.conf'
enabled=true
start_at_boot=false
on_die=respawn
"""

template_local_header = """
[default]
agent=${RUNDIR}/agent.sock
"""

template_local_ns = """
[${NS}]
${NOZK}zookeeper=${IP}:2181
conscience=${IP}:${PORT_CS}
proxy-local=${RUNDIR}/${NS}-proxy.sock
proxy=${IP}:${PORT_PROXYD}
event-agent=ipc://${RUNDIR}/event-agent.sock
"""

template_event_agent = """
[event-agent]
namespace = ${NS}
user = ${USER}
bind_addr = ipc://${RUNDIR}/event-agent.sock
workers = 5
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,NS,event-agent
"""

template_account_server = """
[account-server]
bind_addr = ${IP}
bind_port = ${PORT}
workers = 2
autocreate = true
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,${NS},account,1
"""

HOME = str(os.environ['HOME'])
EXE_PREFIX = "@EXE_PREFIX@"
OIODIR = HOME + '/.oio'
SDSDIR = OIODIR + '/sds'
CFGDIR = SDSDIR + '/conf'
RUNDIR = SDSDIR + '/run'
LOGDIR = SDSDIR + '/logs'
SPOOLDIR = SDSDIR + '/spool'
DATADIR = SDSDIR + '/data'
TMPDIR = '/tmp'
CODEDIR = '@CMAKE_INSTALL_PREFIX@'
LIBDIR = CODEDIR + '/@LD_LIBDIR@'
PATH = HOME+"/.local/bin:@CMAKE_INSTALL_PREFIX@/bin"
port = 6000

# XXX When /usr/sbin/httpd is present we suspect a Redhat/Centos/Fedora
# environment. If not, we consider being in a Ubuntu/Debian environment.
# Sorry for the others, we cannot manage everything in this helper script for
# developers, so consider using the standard deployment tools for your
# prefered Linux distribution.
HTTPD_BINARY = '/usr/sbin/httpd' if os.path.exists('/usr/sbin/httpd') else '/usr/sbin/apache2'
APACHE2_MODULES_SYSTEM_DIR = '' if os.path.exists('/usr/sbin/httpd') else '/usr/lib/apache2/'

def mkdir_noerror (d):
	try:
		os.makedirs (d, 0700)
	except OSError as e:
		if e.errno != errno.EEXIST:
			raise e

def type2exe (t):
	return EXE_PREFIX + '-' + str(t) + '-server'

def next_port ():
	global port
	res, port = port, port + 1
	return res

def generate (ns, ip, options={}):
	def getint(v,default):
		if v is None:
			return int(default)
		return int(v)

	global port
	port = getint(options.PORT_START, 6000)

	port_cs = next_port()
	port_agent = next_port() # for TCP connection is use by Java applications
	port_proxy = next_port()
	port_flask = next_port()
	port_account = next_port()
	port_event_agent = next_port()
	rawx = []
	services = []

	versioning = 1
	stgpol = "SINGLE"

	meta2_replicas = getint(options.M2_REPLICAS, 3)
	sqlx_replicas = getint(options.SQLX_REPLICAS, 1)

	if options.M2_VERSIONS is not None:
		versioning = int(options.M2_VERSIONS)
	if options.M2_STGPOL is not None:
		stgpol = str(options.M2_STGPOL)

	if options.NO_META0 is None:
		for i in range(1, 1+getint(options.NB_META0, 1)):
			services.append(('meta0', EXE_PREFIX + '-meta0-server', i, next_port()))
	if options.NO_META1 is None:
		for i in range(1, 1+getint(options.NB_META1, 3)):
			services.append(('meta1', EXE_PREFIX + '-meta1-server', i, next_port()))
	if options.NO_META2 is None:
		for i in range(1, 1+getint(options.NB_META2, meta2_replicas)):
			services.append(('meta2', EXE_PREFIX + '-meta2-server', i, next_port()))
	if options.NO_SQLX is None:
		for i in range(1, 1+getint(options.NB_SQLX, sqlx_replicas)):
			services.append(('sqlx',  EXE_PREFIX + '-sqlx-server', i, next_port()))
	if options.NO_RAWX is None:
		for i in range(1, 1+getint(options.NB_RAWX, 3)):
			rawx.append((i, next_port()))

	print "Deploying", repr(services)

	env = dict(IP=ip, NS=ns, HOME=HOME, EXE_PREFIX=EXE_PREFIX,
			PATH=PATH, LIBDIR=LIBDIR,
			SDSDIR=SDSDIR, TMPDIR=TMPDIR,
			DATADIR=DATADIR, CFGDIR=CFGDIR, RUNDIR=RUNDIR, SPOOLDIR=SPOOLDIR,
			LOGDIR=LOGDIR, CODEDIR=CODEDIR,
			UID=str(os.geteuid()), GID=str(os.getgid()), USER=str(pwd.getpwuid(os.getuid()).pw_name),
			VERSIONING=versioning, STGPOL=stgpol,
			PORT_CS=port_cs,
			PORT_PROXYD=port_proxy,
			M2_REPLICAS=meta2_replicas, M2_DISTANCE=str(1),
			SQLX_REPLICAS=sqlx_replicas, SQLX_DISTANCE=str(1),
			APACHE2_MODULES_SYSTEM_DIR=APACHE2_MODULES_SYSTEM_DIR,
			HTTPD_BINARY=HTTPD_BINARY)

	env['CHUNK_SIZE'] = getint(options.CHUNK_SIZE, 1024*1024)
	env['PORT_REDIS'] = 6379

	if options.NO_ZOOKEEPER is not None:
		env['NOZK'] = '#'
	else:
		env['NOZK'] = ''

	mkdir_noerror(SDSDIR)
	mkdir_noerror(CODEDIR)
	mkdir_noerror(DATADIR)
	mkdir_noerror(CFGDIR)
	mkdir_noerror(RUNDIR)
	mkdir_noerror(LOGDIR)

	# Global SDS configuration
	with open(OIODIR + '/'+ 'sds.conf', 'w+') as f:
		tpl = Template(template_local_header)
		f.write(tpl.safe_substitute(env))
		tpl = Template(template_local_ns)
		f.write(tpl.safe_substitute(env))

	# Conscience configuration
	with open(CFGDIR + '/'+ns+'-conscience.conf', 'w+') as f:
		env['PORT'] = port_cs
		tpl = Template(template_conscience)
		f.write(tpl.safe_substitute(env))
	with open(CFGDIR + '/' + ns + '-conscience-policies.conf', 'w+') as f:
		tpl = Template(template_conscience_policies)
		f.write(tpl.safe_substitute(env))

	# Generate the "GRIDD-like" services
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		tpl = Template(template_gridinit_header)
		f.write(tpl.safe_substitute(env))
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		env['PORT'] = port_proxy
		tpl = Template(template_gridinit_ns)
		f.write(tpl.safe_substitute(env))
		tpl = Template(template_gridinit_service)
		for t, e, n, p in services:
			mkdir_noerror(DATADIR + '/' + ns + '-' + t + '-' + str(n))
			env['SRVTYPE'] = t
			env['SRVNUM'] = n
			env['PORT'] = p
			env['EXE'] = e
			f.write(tpl.safe_substitute(env))

	# Generate the RAWX services
	tpl = Template(template_gridinit_rawx)
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		for n,p in rawx:
			mkdir_noerror(DATADIR + '/' + ns + '-rawx-' + str(n))
			env['SRVTYPE'] = 'rawx'
			env['SRVNUM'] = n
			env['PORT'] = p
			f.write(tpl.safe_substitute(env))
	tpl = Template(template_rawx_service)
	for n,p in rawx:
		env['SRVTYPE'] = 'rawx'
		env['SRVNUM'] = n
		env['PORT'] = p
		with open(CFGDIR + '/' + ns + '-rawx-httpd-' + str(n) + '.conf', 'w+') as f:
			f.write(tpl.safe_substitute(env))

	# administration flask
	env['PORT'] = port_flask
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		tpl = Template(template_flask_gridinit)
		f.write(tpl.safe_substitute(env))

	# redis
	if options.ALLOW_REDIS is not None:
		env['PORT'] = port_proxy
		env['SRVNUM'] = 1
		mkdir_noerror(DATADIR + '/' + str(env['NS']) + '-' + 'redis' + '-' + str(env['SRVNUM']))
		with open(CFGDIR + '/' + ns + '-redis-'+ str(env['SRVNUM']) +'.conf', 'w+') as f:
			tpl = Template(template_redis)
			f.write(tpl.safe_substitute(env))
		with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
			tpl = Template(template_redis_gridinit)
			f.write(tpl.safe_substitute(env))

	# proxy
	env['PORT'] = port_proxy
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		tpl = Template(template_proxy_gridinit)
		f.write(tpl.safe_substitute(env))

	# account-server
	env['PORT'] = port_account
	with open(CFGDIR + '/' + ns + '-account-server.conf', 'w+') as f:
		tpl = Template(template_account_server)
		f.write(tpl.safe_substitute(env))
	with open(CFGDIR + '/' + 'gridinit.conf', 'a+') as f:
		tpl = Template(template_account_server_gridinit)
		f.write(tpl.safe_substitute(env))

	# Event agent configuration
	env['PORT'] = port_event_agent
	with open(CFGDIR + '/' + 'event-agent.conf', 'w+') as f:
		tpl = Template(template_event_agent)
		f.write(tpl.safe_substitute(env))

	# Central agent configuration
	env['PORT'] = port_agent
	with open(CFGDIR + '/'+ 'agent.conf', 'w+') as f:
		tpl = Template(template_agent)
		f.write(tpl.safe_substitute(env))

        # Test agent configuration
        listing = {}
        with open(CFGDIR + '/' + 'test.conf', 'w+') as f:
                listing["namespace"] = ns
                listing["account"] = 'test_account'
                listing["account_addr"] = [str(ip) + ":" + str(port_account)]
                listing["proxyd_uri"] = "http://" + str(ip) + ":" + str(port_proxy)
                listing["meta0"] = [str(ip) + ':' + str(m[3]) for m in services
                                    if
                                    m[0] == 'meta0']
                listing["meta1"] = [str(ip) + ':' + str(m[3]) for m in services
                                    if
                                    m[0] == 'meta1']
                listing["meta2"] = [str(ip) + ':' + str(m[3]) for m in services
                                    if
                                    m[0] == 'meta2']
                listing["rawx"] = [str(ip) + ':' + str(p[1]) for p in rawx]
                f.write(json.dumps(listing))

def main ():
	from optparse import OptionParser as OptionParser
	parser = OptionParser()

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

	parser.add_option("--port", action="store", type="int", dest="PORT_START")
	parser.add_option("--chunk-size", action="store", type="int", dest="CHUNK_SIZE")
	parser.add_option("--no-zookeeper", action="store_true", dest="NO_ZOOKEEPER")
	parser.add_option("--allow-redis", action="store_true", dest="ALLOW_REDIS")

	parser.add_option("--no-meta0", action="store_true", dest="NO_META0")
	parser.add_option("--no-meta1", action="store_true", dest="NO_META1")
	parser.add_option("--no-meta2", action="store_true", dest="NO_META2")
	parser.add_option("--no-sqlx", action="store_true", dest="NO_SQLX")
	parser.add_option("--no-rawx", action="store_true", dest="NO_RAWX")

	parser.add_option("--nb-meta0", action="store", type="int", dest="NB_META0")
	parser.add_option("--nb-meta1", action="store", type="int", dest="NB_META1")
	parser.add_option("--nb-meta2", action="store", type="int", dest="NB_META2")
	parser.add_option("--nb-sqlx",  action="store", type="int", dest="NB_SQLX")
	parser.add_option("--nb-rawx",  action="store", type="int", dest="NB_RAWX")

	options, args = parser.parse_args()
	generate(args[0], args[1], options)

if __name__ == '__main__':
	main()

