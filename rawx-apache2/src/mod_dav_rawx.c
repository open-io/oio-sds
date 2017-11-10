/*
OpenIO SDS rawx-apache2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_sds.h>
#include <core/oiovar.h>
#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>
#include <rawx-apache2/src/rawx_variables.h>

#include "mod_dav_rawx.h"
#include "rawx_internals.h"
#include "rawx_config.h"
#include "rawx_event.h"

static void
_cleanup_child(dav_rawx_server_conf *conf)
{
	server_child_stat_fini(conf, conf->pool);
	rawx_event_destroy();
}

static void
_cleanup_master(dav_rawx_server_conf *conf)
{
	server_master_stat_fini(conf, conf->pool);
}

static apr_status_t
_cleanup_to_register(void *udata)
{
	dav_rawx_server_conf *conf = udata;
	if (conf && conf->cleanup) {
		conf->cleanup(conf);
		conf->cleanup = NULL;
	}
	return APR_SUCCESS;
}

static unsigned int i = 0;

static void *
dav_rawx_create_server_config(apr_pool_t *p, server_rec *s UNUSED)
{
	dav_rawx_server_conf *conf = apr_pcalloc(p, sizeof(dav_rawx_server_conf));
	conf->pool = p;
	conf->cleanup = NULL;
	conf->hash_depth = 1;
	conf->hash_width = 3;
	conf->fsync_on_close = FSYNC_ON_CHUNK_DIR;
	conf->fallocate = 1;
	conf->checksum_mode = CHECKSUM_ALWAYS;
	return conf;
}

static void *
dav_rawx_merge_server_config(apr_pool_t *p, void *base UNUSED, void *overrides)
{
	dav_rawx_server_conf *child = overrides;
	dav_rawx_server_conf *newconf = apr_pcalloc(p, sizeof(*newconf));
	newconf->pool = p;
	newconf->enabled_compression = child->enabled_compression;
	newconf->cleanup = NULL;
	newconf->hash_depth = child->hash_depth;
	newconf->hash_width = child->hash_width;
	newconf->fsync_on_close = child->fsync_on_close;
	newconf->fallocate = child->fallocate;
	newconf->checksum_mode = child->checksum_mode;
	memcpy(newconf->docroot, child->docroot, sizeof(newconf->docroot));
	memcpy(newconf->ns_name, child->ns_name, sizeof(newconf->ns_name));
	return newconf;
}

static const char *
dav_rawx_cmd_gridconfig_hash_width(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->hash_width = atoi(arg1);
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_hash_depth(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->hash_depth = atoi(arg1);
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_docroot(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	/* Check the directory exists */
	apr_finfo_t finfo;
	apr_status_t status = apr_stat(&(finfo), arg1, APR_FINFO_NORM, cmd->pool);
	if (status != APR_SUCCESS && status != APR_INCOMPLETE) {
		DAV_DEBUG_POOL(cmd->temp_pool, 0,
				"Invalid docroot for GridStorage chunks: %s", arg1);
		return apr_pstrcat(cmd->temp_pool,
				"Invalid docroot for GridStorage chunks: ", arg1, NULL);
	}
	if (finfo.filetype != APR_DIR) {
		DAV_DEBUG_POOL(cmd->temp_pool, 0,
				"Docroot for GridStorage chunks must be a directory: %s", arg1);
		return apr_pstrcat(cmd->temp_pool,
				"Docroot for GridStorage chunks must be a directory: ", arg1, NULL);
	}

	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	strncpy(conf->docroot, arg1, sizeof(conf->docroot));
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_namespace(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	strncpy(conf->ns_name, arg1, sizeof(conf->ns_name));
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_fsync(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	if (oio_str_parse_bool(arg1, FALSE))
		conf->fsync_on_close |= FSYNC_ON_CHUNK;
	else
		conf->fsync_on_close &= ~FSYNC_ON_CHUNK;

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_fsync_dir(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	if (oio_str_parse_bool(arg1, FALSE))
		conf->fsync_on_close |= FSYNC_ON_CHUNK_DIR;
	else
		conf->fsync_on_close &= ~FSYNC_ON_CHUNK_DIR;
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_fallocate(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->fallocate = oio_str_parse_bool(arg1, FALSE);
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_dirrun(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	apr_snprintf(conf->shm.path, sizeof(conf->shm.path),
		"%s/httpd-shm.%d", arg1, getpid());
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_acl(cmd_parms *cmd, void *config UNUSED, const char *arg1 UNUSED)
{
	DAV_ERROR_POOL(cmd->pool, 0, "IGNORED OPTION: %s", "grid_acl");
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_checksum(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	if (!oio_str_is_set(arg1)) {
		conf->checksum_mode = CHECKSUM_ALWAYS;
	} else if (0 == apr_strnatcasecmp(arg1, "smart")) {
		conf->checksum_mode = CHECKSUM_SMART;
	} else if (oio_str_parse_bool(arg1, TRUE)) {
		conf->checksum_mode = CHECKSUM_ALWAYS;
	} else {
		conf->checksum_mode = CHECKSUM_NEVER;
	}

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_compression(cmd_parms *cmd, void *config UNUSED, const char *arg1)
{
	dav_rawx_server_conf *conf =
		ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->enabled_compression = oio_str_parse_bool(arg1, FALSE);
	return NULL;
}

static void
rawx_hook_child_init(apr_pool_t *pchild, server_rec *s)
{
	apr_status_t status;
	dav_rawx_server_conf *conf;

	DAV_XDEBUG_POOL(pchild, 0, "%s()", __FUNCTION__);
	conf = ap_get_module_config(s->module_config, &dav_rawx_module);
	conf->cleanup = _cleanup_child;

	status = server_init_child_stat(conf, pchild, pchild);
	if (APR_SUCCESS != status)
		DAV_ERROR_POOL(pchild, 0, "Failed to attach the RAWX statistics support");

	conf->cleanup = _cleanup_child;

	/* Load the system configuration in the central config system */
	do {
		struct oio_cfg_handle_s *ns_conf = oio_cfg_cache_create();
		if (ns_conf) {
			oio_var_value_all_with_config(ns_conf, conf->ns_name);
			oio_cfg_handle_clean(ns_conf);
		}
	} while (0);

	if (oio_rawx_events) {
		gchar *event_agent_addr = oio_cfg_get_eventagent(conf->ns_name);
		GError *err = rawx_event_init(event_agent_addr);
		if (NULL != err) {
			DAV_ERROR_POOL(pchild, 0, "Failed to initialize event context: (%d) %s",
					err->code, err->message);
			g_clear_error (&err);
		}
		g_free(event_agent_addr);
	}

	oio_log_to_syslog ();
}

/* Dynamically shared modules are loaded twice by apache!
 * Then we set a dummy information in the server's pool's
 * userdata*/
static int
__rawx_is_first_call(server_rec *server)
{
	const char *userdata_key = "rawx_hook_post_config";
	void *data;

	apr_pool_userdata_get(&data, userdata_key, server->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *)1, userdata_key,
				apr_pool_cleanup_null, server->process->pool);
		return 1;
	}

	return 0;
}

static apr_status_t
_destroy_shm_cb(void *handle)
{
	apr_shm_t *shm = (apr_shm_t*)handle;
	apr_pool_t *pool = apr_shm_pool_get(shm);
	DAV_DEBUG_POOL(pool, 0, "%s: Destroying SHM segment", __FUNCTION__);
	return apr_shm_destroy(shm);
}

static apr_status_t
_create_shm_if_needed(char *shm_path, server_rec *server, apr_pool_t *plog)
{
	apr_pool_t *ppool = server->process->pool;
	apr_shm_t *shm = NULL;
	apr_status_t rc;

	// Test if an SHM segment already exists
	apr_pool_userdata_get((void**)&shm, SHM_HANDLE_KEY, ppool);
	if (shm == NULL) {
		DAV_DEBUG_POOL(plog, 0, "%s: Creating SHM segment at [%s]",
				__FUNCTION__, shm_path);
		// Create a new SHM segment
		rc = apr_shm_create(&shm, sizeof(struct shm_stats_s), shm_path, ppool);
		if (rc != APR_SUCCESS) {
			char buff[256];
			DAV_ERROR_POOL(plog, 0, "Failed to create the SHM segment at [%s]: %s",
					shm_path, apr_strerror(rc, buff, sizeof(buff)));
			return rc;
		}
		/* Init the SHM */
		void *ptr_counter = apr_shm_baseaddr_get(shm);
		if (ptr_counter)
			memset(ptr_counter, 0, sizeof(struct shm_stats_s));
		// Save the SHM handle in the process' pool, without cleanup callback
		apr_pool_userdata_set(shm, SHM_HANDLE_KEY, NULL, ppool);
		// Register the cleanup callback to be executed BEFORE pool cleanup
		apr_pool_pre_cleanup_register(ppool, shm, _destroy_shm_cb);
	} else {
		DAV_DEBUG_POOL(plog, 0, "%s: Found an already created SHM segment",
				__FUNCTION__);
	}
	return APR_SUCCESS;
}

static int
rawx_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp UNUSED,
		server_rec *server)
{
	apr_status_t status;
	server_rec *s;
	server_addr_rec *a;
	dav_rawx_server_conf *conf;
	GError *gerr;
	int volume_validated = 0;

	if (__rawx_is_first_call(server)) {
		DAV_DEBUG_POOL(plog, 0, "First call detected");
		return OK;
	}

	DAV_DEBUG_POOL(plog, 0, "Second call detected");

	gerr = NULL;
	conf = ap_get_module_config(server->module_config, &dav_rawx_module);

	DAV_XDEBUG_POOL(plog, 0, "Checking the docroot XATTR lock for [%s]",
			conf->docroot);

	/* Runs the configured servers and check they do not serve
	 * the grid docroot with an unauthorized IP:PORT couple */
	for (s = server ; s ; s = s->next) {

		for (a = s->addrs ; a ; a = a->next) {
			apr_status_t status2;
			char *host = NULL, url[512];

			if (gerr)
				g_clear_error(&gerr);
			if (a->host_port == 0)
				continue;

			host = NULL;
			status2 = apr_getnameinfo(&host, a->host_addr,
					NI_NUMERICSERV|NI_NUMERICHOST|NI_NOFQDN);
			if (status2 != APR_SUCCESS || host == NULL) {
				DAV_ERROR_POOL(plog, 0, "getnameinfo() failed : %d", status2);
				continue;
			}

			if (strchr(host, ':')) // IPv6
				apr_snprintf(url, sizeof(url), "[%s]:%d", host, a->host_port);
			else // IPv4
				apr_snprintf(url, sizeof(url), "%s:%d", host, a->host_port);
			DAV_DEBUG_POOL(plog, 0, "xattr-lock : testing addr [%s]", url);

			/* FIXME the rawx_id is ok if there is only one ip:port in configuration */
			g_strlcpy(conf->rawx_id, url, sizeof(conf->rawx_id));

			gerr = volume_service_lock (conf->docroot, NAME_SRVTYPE_RAWX,
					url, conf->ns_name);
			if (!gerr)
				volume_validated = 1;
			else {
				DAV_ERROR_POOL(plog, 0, "Failed to grab the docroot ownership: %s",
						gerror_get_message(gerr));
				goto label_error;
			}
		}
	}

	if (gerr)
		g_clear_error(&gerr);

	if (!volume_validated) {
		DAV_ERROR_POOL(plog, 0, "No server found, could not validate the RAWX volume. "
			"Did you declare at least one VirtualHost ?");
		goto label_error;
	}

	if (_create_shm_if_needed(conf->shm.path, server, plog) != APR_SUCCESS) {
		DAV_ERROR_POOL(plog, 0, "Failed to init the RAWX statistics support");
		return DONE;
	}

	/* Init the stat support : doing this so late avoids letting orphan
	 * SHM segments in the nature in case of previous errors */
	status = server_init_master_stat(conf, pconf, plog);
	if (APR_SUCCESS != status) {
		DAV_ERROR_POOL(plog, 0, "Failed to init the RAWX statistics support");
		return DONE;
	}
	else {
		/* This will be overwritten by the child_init */
		conf->cleanup = _cleanup_master;
		apr_pool_userdata_set(conf, apr_psprintf(pconf,
				"RAWX-config-to-be-cleaned-%d", i++),
				_cleanup_to_register, pconf);
	}

	return OK;

label_error:
	if (gerr)
		g_clear_error(&gerr);
	return DONE;
}

static const command_rec dav_rawx_cmds[] =
{
    AP_INIT_TAKE1("grid_hash_width",  dav_rawx_cmd_gridconfig_hash_width,  NULL, RSRC_CONF, "hash width on a chunk's name"),
    AP_INIT_TAKE1("grid_hash_depth",  dav_rawx_cmd_gridconfig_hash_depth,  NULL, RSRC_CONF, "hash depth on a chunk's name"),
    AP_INIT_TAKE1("grid_docroot",     dav_rawx_cmd_gridconfig_docroot,     NULL, RSRC_CONF, "chunks docroot"),
    AP_INIT_TAKE1("grid_namespace",   dav_rawx_cmd_gridconfig_namespace,   NULL, RSRC_CONF, "namespace name"),
    AP_INIT_TAKE1("grid_dir_run",     dav_rawx_cmd_gridconfig_dirrun,      NULL, RSRC_CONF, "run directory"),
    AP_INIT_TAKE1("grid_fsync",       dav_rawx_cmd_gridconfig_fsync,       NULL, RSRC_CONF, "do fsync on file close"),
    AP_INIT_TAKE1("grid_fsync_dir",   dav_rawx_cmd_gridconfig_fsync_dir,   NULL, RSRC_CONF, "do fsync on chunk direcory after renaming .pending"),
    AP_INIT_TAKE1("grid_fallocate",   dav_rawx_cmd_gridconfig_fallocate,   NULL, RSRC_CONF, "call fallocate when receiving a chunk"),
    AP_INIT_TAKE1("grid_acl",         dav_rawx_cmd_gridconfig_acl,         NULL, RSRC_CONF, "enable acl (ignored)"),
    AP_INIT_TAKE1("grid_compression", dav_rawx_cmd_gridconfig_compression, NULL, RSRC_CONF, "enable compression ('yes', 'no')'"),
    AP_INIT_TAKE1("grid_checksum",    dav_rawx_cmd_gridconfig_checksum,    NULL, RSRC_CONF, "enable checksuming the body of PUT ('yes', 'no', 'smart')'"),
    AP_INIT_TAKE1(NULL,  NULL,  NULL, RSRC_CONF, NULL)
};

static void
register_hooks(apr_pool_t *p)
{
	dav_hook_gather_propsets(dav_rawx_gather_propsets, NULL, NULL, APR_HOOK_MIDDLE);
	dav_hook_find_liveprop(dav_rawx_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
	dav_hook_insert_all_liveprops(dav_rawx_insert_all_liveprops, NULL, NULL, APR_HOOK_MIDDLE);

	dav_rawx_register(p);

	ap_hook_post_config(rawx_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(rawx_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);

	DAV_DEBUG_POOL(p, 0, "Hooks registered");
}

module AP_MODULE_DECLARE_DATA dav_rawx_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	dav_rawx_create_server_config, /* server config */
	dav_rawx_merge_server_config,  /* merge server config */
	dav_rawx_cmds,                 /* command table */
	register_hooks,              /* register hooks */
};

