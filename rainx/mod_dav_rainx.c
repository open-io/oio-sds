/*
OpenIO SDS rainx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <sys/socket.h>
#include <netdb.h>

#include <httpd.h>
#include <http_config.h>
#include <apr_strings.h>
#include <mod_dav.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "mod_dav_rainx.h"
#include "rainx_internals.h"
#include "rainx_config.h"

#define RAINX_DEFAULT_SOCKET_TIMEOUT (30 * 1000000) /* microseconds */

static void
_stat_cleanup_child(dav_rainx_server_conf *conf)
{
	server_child_stat_fini(conf, conf->pool);
	if (conf->rainx_conf_lock) {
		apr_thread_mutex_destroy(conf->rainx_conf_lock);
		conf->rainx_conf_lock = NULL;
	}
}

static void
_stat_cleanup_master(dav_rainx_server_conf *conf)
{
	server_master_stat_fini(conf, conf->pool);
	if (conf->rainx_conf_lock) {
		apr_thread_mutex_destroy(conf->rainx_conf_lock);
		conf->rainx_conf_lock = NULL;
	}
}

/**
 * Invoked whatever the context
 */
static apr_status_t
_stat_cleanup_to_register(void *udata)
{
	dav_rainx_server_conf *conf = udata;
	if (conf && conf->cleanup) {
		conf->cleanup(conf);
		conf->cleanup = NULL;
	}
	return APR_SUCCESS;
}

static unsigned int i = 0;

static void *
dav_rainx_create_server_config(apr_pool_t *p, server_rec *s)
{
	dav_rainx_server_conf *conf = NULL;

	(void) s;
	DAV_XDEBUG_POOL(p, 0, "%s()", __FUNCTION__);

	conf = apr_pcalloc(p, sizeof(dav_rainx_server_conf));
	conf->pool = p;
	conf->cleanup = NULL;
	conf->socket_timeout = RAINX_DEFAULT_SOCKET_TIMEOUT;

	apr_snprintf(conf->lock.path, sizeof(conf->lock.path), "/var/run/httpd-lock.%d", getpid());
	apr_snprintf(conf->shm.path, sizeof(conf->shm.path), "/var/run/httpd-shm.%d", getpid());

	return conf;
}

static void *
dav_rainx_merge_server_config(apr_pool_t *p, void *base, void *overrides)
{
	(void) base;
	dav_rainx_server_conf *child;
	dav_rainx_server_conf *newconf;

	DAV_XDEBUG_POOL(p, 0, "%s()", __FUNCTION__);
	child = overrides;

	newconf = apr_pcalloc(p, sizeof(*newconf));
	newconf->pool = p;
	newconf->cleanup = NULL;
	memcpy(newconf->docroot, child->docroot, sizeof(newconf->docroot));
	memcpy(newconf->ns_name, child->ns_name, sizeof(newconf->ns_name));
	apr_thread_mutex_create(&(newconf->rainx_conf_lock),
			APR_THREAD_MUTEX_DEFAULT, newconf->pool);
	update_rainx_conf(p, &(newconf->rainx_conf), newconf->ns_name);

	DAV_DEBUG_POOL(p, 0, "Configuration merged!");
	return newconf;
}

static const char *
dav_rainx_cmd_gridconfig_docroot(cmd_parms *cmd, void *config, const char *arg1)
{
	apr_finfo_t finfo;
	dav_rainx_server_conf *conf;

	(void) config;
	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	/* Check the directory exists */
	do {
		apr_status_t status = apr_stat(&(finfo), arg1, APR_FINFO_NORM, cmd->pool);
		if (status != APR_SUCCESS) {
			DAV_DEBUG_POOL(cmd->temp_pool, 0, "Invalid docroot for GridStorage chunks : %s", arg1);
			return apr_pstrcat(cmd->temp_pool, "Invalid docroot for GridStorage chunks : ", arg1, NULL);
		}
		if (finfo.filetype != APR_DIR) {
			DAV_DEBUG_POOL(cmd->temp_pool, 0, "Docroot for GridStorage chunks must be a directory : %s", arg1);
			return apr_pstrcat(cmd->temp_pool, "Docroot for GridStorage chunks must be a directory : ", arg1, NULL);
		}
	} while (0);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rainx_module);
	memset(conf->docroot, 0x00, sizeof(conf->docroot));
	apr_cpystrn(conf->docroot, arg1, sizeof(conf->docroot)-1);

	DAV_DEBUG_POOL(cmd->pool, 0, "DOCROOT=[%s]", conf->docroot);

	return NULL;
}

static const char *
dav_rainx_cmd_gridconfig_namespace(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rainx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rainx_module);
	memset(conf->ns_name, 0x00, sizeof(conf->ns_name));
	apr_cpystrn(conf->ns_name, arg1, sizeof(conf->ns_name));

	DAV_DEBUG_POOL(cmd->pool, 0, "NS=[%s]", conf->ns_name);

	/* Prepare COMPRESSION / ACL CONF when we get ns name */
	namespace_info_t* ns_info;
	GError *local_error = conscience_get_namespace(conf->ns_name, &ns_info);
	if (!ns_info) {
		DAV_DEBUG_POOL(cmd->temp_pool, 0, "Failed to get namespace info from ns [%s]", conf->ns_name);
		return apr_pstrcat(cmd->temp_pool, "Failed to get namespace info from ns: ",
				conf->ns_name, " ", local_error->message, NULL);
	}

	if (!conf->rainx_conf_lock) {
		apr_thread_mutex_create(&(conf->rainx_conf_lock),
				APR_THREAD_MUTEX_DEFAULT, conf->pool);
	}

	apr_thread_mutex_lock(conf->rainx_conf_lock);
	conf->rainx_conf = apr_palloc(cmd->pool, sizeof(rawx_conf_t));

	char * stgpol = NULL;
	stgpol = namespace_storage_policy(ns_info, ns_info->name);
	if(NULL != stgpol) {
		conf->rainx_conf->sp = storage_policy_init(ns_info, stgpol);
	} else {
		conf->rainx_conf->sp = NULL;
	}

	conf->rainx_conf->ni = ns_info;

	conf->rainx_conf->acl = _get_acl(cmd->pool, ns_info);
	conf->rainx_conf->last_update = time(0);
	apr_thread_mutex_unlock(conf->rainx_conf_lock);

	if(local_error)
		g_clear_error(&local_error);
	return NULL;
}

static const char *
dav_rainx_cmd_gridconfig_dirrun(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rainx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rainx_module);

	apr_snprintf(conf->lock.path, sizeof(conf->lock.path),
		"%s/httpd-lock.%d", arg1, getpid());
	apr_snprintf(conf->shm.path, sizeof(conf->shm.path),
		"%s/httpd-shm.%d", arg1, getpid());

	DAV_DEBUG_POOL(cmd->pool, 0, "mutex_key=[%s]", conf->lock.path);
	DAV_DEBUG_POOL(cmd->pool, 0, "shm_key=[%s]", conf->shm.path);

	return NULL;
}

static const char *
dav_rainx_cmd_gridconfig_acl(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rainx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rainx_module);
	conf->enabled_acl = 0;
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"on"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"true"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"yes"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"enabled"));

	return NULL;
}

static const char *
dav_rainx_cmd_gridconfig_sock_timeout(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rainx_server_conf *conf;
	apr_int64_t socket_timeout;
	char *endstr;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rainx_module);

	socket_timeout = apr_strtoi64(arg1, &endstr, 10);
	if (errno == 0 && *endstr == '\0')
	{
		conf->socket_timeout = socket_timeout;
	}
	else
	{
		DAV_ERROR_POOL(cmd->pool, 0, "Invalid socket timeout, default value will be used");
	}

	DAV_DEBUG_POOL(cmd->pool, 0,
			"Socket timeout for rawx request is %" APR_TIME_T_FMT " microseconds",
			conf->socket_timeout);

	return NULL;
}

static void
rainx_hook_child_init(apr_pool_t *pchild, server_rec *s)
{
	apr_status_t status;
	dav_rainx_server_conf *conf;

	DAV_XDEBUG_POOL(pchild, 0, "%s()", __FUNCTION__);
	conf = ap_get_module_config(s->module_config, &dav_rainx_module);
	conf->cleanup = _stat_cleanup_child;

	status = server_init_child_stat(conf, pchild, pchild);
	if (APR_SUCCESS != status)
		DAV_ERROR_POOL(pchild, 0, "Failed to attach the RAWX statistics support");

	conf->cleanup = _stat_cleanup_child;
}

/* Dynamically shared modules are loaded twice by apache!
 * Then we set a dummy information in the server's pool's
 * userdata*/
static int
__rainx_is_first_call(server_rec *server)
{
	const char *userdata_key = "rainx_hook_post_config";
	void *data;

	apr_pool_userdata_get(&data, userdata_key, server->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, server->process->pool);
		return 1;
	}

	return 0;
}

static int
rainx_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
	apr_status_t status;
	server_rec *s;
	server_addr_rec *a;
	dav_rainx_server_conf *conf;
	GError *gerr;

	(void) ptemp;
	DAV_XDEBUG_POOL(plog, 0, "%s(%lx)", __FUNCTION__, (long)server);

	if (__rainx_is_first_call(server)) {
		DAV_DEBUG_POOL(plog, 0, "First call detected");
		return OK;
	}

	DAV_DEBUG_POOL(plog, 0, "Second call detected");

	gerr = NULL;
	conf = ap_get_module_config(server->module_config, &dav_rainx_module);

	DAV_XDEBUG_POOL(plog, 0, "Checking the docroot XATTR lock for [%s]", conf->docroot);

	/* Runs the configured servers and check they do not serve
	 * the grid docroot with an unauthorized IP:PORT couple */
	for (s = server ; s ; s = s->next) {

		for (a = s->addrs ; a ; a = a->next) {
			char *host = NULL, url[512];

			if (gerr)
				g_clear_error(&gerr);
			if (a->host_port == 0)
				continue;

			host = NULL;
			status = apr_getnameinfo(&host, a->host_addr, NI_NUMERICSERV|NI_NUMERICHOST|NI_NOFQDN);
			if (status != APR_SUCCESS || host == NULL) {
				DAV_ERROR_POOL(plog, 0, "getnameinfo() failed : %d", status);
				continue;
			}

			apr_snprintf(url, sizeof(url), "%s:%d", host, a->host_port);
			DAV_DEBUG_POOL(plog, 0, "xattr-lock : testing addr [%s]", url);
		}
	}

	if (gerr)
		g_clear_error(&gerr);

	/* Init the stat support : doing this so late avoids letting orphan
	 * SHM segments in the nature in case of previous errors */
	status = server_init_master_stat(conf, pconf, plog);
	if (APR_SUCCESS != status) {
		DAV_ERROR_POOL(plog, 0, "Failed to init the RAINX statistics support");
		return DONE;
	}
	else {
		/* This will be overwritten by the child_init */
		conf->cleanup = _stat_cleanup_master;
		apr_pool_userdata_set(conf, apr_psprintf(pconf, "RAINX-config-to-be-cleaned-%d", i++),
				_stat_cleanup_to_register, pconf);
	}

	return OK;
}

static const command_rec dav_rainx_cmds[] =
{
    AP_INIT_TAKE1("grid_docroot",     dav_rainx_cmd_gridconfig_docroot,     NULL, RSRC_CONF, "chunks docroot"),
    AP_INIT_TAKE1("grid_namespace",   dav_rainx_cmd_gridconfig_namespace,   NULL, RSRC_CONF, "namespace name"),
    AP_INIT_TAKE1("grid_dir_run",     dav_rainx_cmd_gridconfig_dirrun,      NULL, RSRC_CONF, "run directory"),
    AP_INIT_TAKE1("grid_acl",         dav_rainx_cmd_gridconfig_acl,         NULL, RSRC_CONF, "enabled acl"),
    AP_INIT_TAKE1("grid_rawx_socket_timeout", dav_rainx_cmd_gridconfig_sock_timeout,       NULL, RSRC_CONF, "socket timeout for rawx connections (in microsecond)"),
    AP_INIT_TAKE1(NULL,  NULL,  NULL, RSRC_CONF, NULL)
};

static void
register_hooks(apr_pool_t *p)
{
	dav_rainx_register(p);

	ap_hook_post_config(rainx_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(rainx_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);

	DAV_DEBUG_POOL(p, 0, "Hooks registered");
}

module AP_MODULE_DECLARE_DATA dav_rainx_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	dav_rainx_create_server_config, /* server config */
	dav_rainx_merge_server_config,  /* merge server config */
	dav_rainx_cmds,                 /* command table */
	register_hooks,              /* register hooks */
};
