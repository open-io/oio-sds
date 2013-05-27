/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
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

#ifdef HAVE_COMPAT
# include <metautils_compat.h>
#endif

#include <rawx.h>
#include <metautils.h>
#include <storage_policy.h>
#include <gridcluster.h>

#include "./mod_dav_rawx.h"
#include "./rawx_internals.h"
#include "./rawx_config.h"

static void
_stat_cleanup_child(dav_rawx_server_conf *conf)
{
	server_child_stat_fini(conf, conf->pool);
}

static void
_stat_cleanup_master(dav_rawx_server_conf *conf)
{
	server_master_stat_fini(conf, conf->pool);
}

/**
 * Invoked whatever the context
 */
static apr_status_t
_stat_cleanup_to_register(void *udata)
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
dav_rawx_create_server_config(apr_pool_t *p, server_rec *s)
{
	dav_rawx_server_conf *conf = NULL;

	(void) s;
	DAV_XDEBUG_POOL(p, 0, "%s()", __FUNCTION__);

	conf = apr_pcalloc(p, sizeof(dav_rawx_server_conf));
	conf->pool = p;
	conf->cleanup = NULL;
	conf->hash_depth = conf->hash_width = 2;
	conf->headers_scheme = HEADER_SCHEME_V1;
	conf->fsync_on_close = ~0;
	conf->FILE_buffer_size = 0;
	
	apr_snprintf(conf->lock.path, sizeof(conf->lock.path), "/var/run/httpd-lock.%d", getpid());
	apr_snprintf(conf->shm.path, sizeof(conf->shm.path), "/var/run/httpd-shm.%d", getpid());
	
	return conf;
}

static void *
dav_rawx_merge_server_config(apr_pool_t *p, void *base, void *overrides)
{
	dav_rawx_server_conf *parent;
	dav_rawx_server_conf *child;
	dav_rawx_server_conf *newconf;

	DAV_XDEBUG_POOL(p, 0, "%s()", __FUNCTION__);
	parent = base;
	child = overrides;

	newconf = apr_pcalloc(p, sizeof(*newconf));
	newconf->pool = p;
	newconf->cleanup = NULL;
	newconf->hash_depth = child->hash_depth;
	newconf->hash_width = child->hash_width;
	newconf->fsync_on_close = child->fsync_on_close;
	newconf->headers_scheme = child->headers_scheme;
	newconf->FILE_buffer_size = child->FILE_buffer_size;
	memcpy(newconf->docroot, child->docroot, sizeof(newconf->docroot));
	memcpy(newconf->ns_name, child->ns_name, sizeof(newconf->ns_name));
	update_rawx_conf(p, &(newconf->rawx_conf), newconf->ns_name); 

	DAV_DEBUG_POOL(p, 0, "Configuration merged!");
	return newconf;
}

static const char *
dav_rawx_cmd_gridconfig_hash_width(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;

	(void) config;
	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->hash_width = atoi(arg1);

	DAV_DEBUG_POOL(cmd->pool, 0, "hash_width=[%d]", conf->hash_width);
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_hash_depth(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;

	(void) config;
	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->hash_depth = atoi(arg1);

	DAV_DEBUG_POOL(cmd->pool, 0, "hash_depth=[%d]", conf->hash_depth);
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_docroot(cmd_parms *cmd, void *config, const char *arg1)
{
	apr_finfo_t finfo;
	dav_rawx_server_conf *conf;

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
	
	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	memset(conf->docroot, 0x00, sizeof(conf->docroot));
	apr_cpystrn(conf->docroot, arg1, sizeof(conf->docroot)-1);

	DAV_DEBUG_POOL(cmd->pool, 0, "DOCROOT=[%s]", conf->docroot);

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_namespace(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	memset(conf->ns_name, 0x00, sizeof(conf->ns_name));
	apr_cpystrn(conf->ns_name, arg1, sizeof(conf->ns_name)-1);


	DAV_DEBUG_POOL(cmd->pool, 0, "NS=[%s]", conf->ns_name);
	
	/* Prepare COMPRESSION / ACL CONF when we get ns name */
	namespace_info_t* ns_info;
	GError *local_error = NULL;
 	ns_info = get_namespace_info(conf->ns_name, &local_error);
        if(!ns_info) {
		DAV_DEBUG_POOL(cmd->temp_pool, 0, "Failed to get namespace info from ns [%s]", conf->ns_name);
		return apr_pstrcat(cmd->temp_pool, "Failed to get namespace info from ns  : ", conf->ns_name, NULL);
        }
	
	conf->rawx_conf = apr_palloc(cmd->pool, sizeof(rawx_conf_t));

	char * stgpol = NULL;
	stgpol = namespace_storage_policy(ns_info);
	if(NULL != stgpol) {
		conf->rawx_conf->sp = storage_policy_init(ns_info, stgpol);
	} else {
		conf->rawx_conf->sp = NULL;
	}

	conf->rawx_conf->ni = ns_info;

	conf->rawx_conf->acl = _get_acl(cmd->pool, ns_info);
        conf->rawx_conf->last_update = time(0);

	if(local_error)
		g_clear_error(&local_error);
#if 0
	if(ns_info)
		namespace_info_free(ns_info);
#endif
	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_headers(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);

	/* ensure a right default value */
	conf->headers_scheme = HEADER_SCHEME_V1;

	if (0 == apr_strnatcasecmp(arg1,"1"))
		conf->headers_scheme = HEADER_SCHEME_V1;
	else if (0 == apr_strnatcasecmp(arg1, "2"))
		conf->headers_scheme = HEADER_SCHEME_V2;
	else if (0 == apr_strnatcasecmp(arg1, "both"))
		conf->headers_scheme = HEADER_SCHEME_V1 | HEADER_SCHEME_V2;
	else
		return apr_psprintf(cmd->pool, "Grid Headers scheme : invalid value [%s]", arg1);

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_fsync(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->fsync_on_close = 0;
	conf->fsync_on_close |= (0 == apr_strnatcasecmp(arg1,"on"));
	conf->fsync_on_close |= (0 == apr_strnatcasecmp(arg1,"true"));
	conf->fsync_on_close |= (0 == apr_strnatcasecmp(arg1,"yes"));
	conf->fsync_on_close |= (0 == apr_strnatcasecmp(arg1,"enabled"));

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_dirrun(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);

	apr_snprintf(conf->lock.path, sizeof(conf->lock.path),
		"%s/httpd-lock.%d", arg1, getpid());
	apr_snprintf(conf->shm.path, sizeof(conf->shm.path),
		"%s/httpd-shm.%d", arg1, getpid());
	
	DAV_DEBUG_POOL(cmd->pool, 0, "mutex_key=[%s]", conf->lock.path);
	DAV_DEBUG_POOL(cmd->pool, 0, "shm_key=[%s]", conf->shm.path);

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_upblock(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);

	if (arg1 && *arg1) {
		conf->FILE_buffer_size = atoi(arg1);
		if (conf->FILE_buffer_size > 0 && conf->FILE_buffer_size < 8192)
			conf->FILE_buffer_size = 8192;
		else if (conf->FILE_buffer_size > 131072)
			conf->FILE_buffer_size = 131072;
	}

	return NULL;
}

static const char *
dav_rawx_cmd_gridconfig_acl(cmd_parms *cmd, void *config, const char *arg1)
{
	dav_rawx_server_conf *conf;
	(void) config;

	DAV_XDEBUG_POOL(cmd->pool, 0, "%s()", __FUNCTION__);

	conf = ap_get_module_config(cmd->server->module_config, &dav_rawx_module);
	conf->enabled_acl = 0;
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"on"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"true"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"yes"));
	conf->enabled_acl |= (0 == apr_strnatcasecmp(arg1,"enabled"));

	return NULL;
}

static void
rawx_hook_child_init(apr_pool_t *pchild, server_rec *s)
{
	apr_status_t status;
	dav_rawx_server_conf *conf;
	
	DAV_XDEBUG_POOL(pchild, 0, "%s()", __FUNCTION__);
	conf = ap_get_module_config(s->module_config, &dav_rawx_module);
	conf->cleanup = _stat_cleanup_child;

	if (!g_thread_supported ())
		g_thread_init (NULL);
	
	status = server_init_child_stat(conf, pchild, pchild);
	if (APR_SUCCESS != status)
		DAV_ERROR_POOL(pchild, 0, "Failed to attach the RAWX statistics support");
	
	conf->cleanup = _stat_cleanup_child;
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
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, server->process->pool);
		return 1;
	}

	return 0;
}

static int
rawx_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
	apr_status_t status;
	enum lock_state_e state;
	server_rec *s;
	server_addr_rec *a;
	dav_rawx_server_conf *conf;
	GError *gerr;
	int volume_validated = 0;

	(void) ptemp;
	DAV_XDEBUG_POOL(plog, 0, "%s(%lx)", __FUNCTION__, (long)server);

	if (__rawx_is_first_call(server)) {
		DAV_DEBUG_POOL(plog, 0, "First call detected");
		if (!g_thread_supported ())
			g_thread_init (NULL);
		return OK;
	}

	DAV_DEBUG_POOL(plog, 0, "Second call detected");

	gerr = NULL;
	conf = ap_get_module_config(server->module_config, &dav_rawx_module);

	/* perform some options consistency checks */
	if (!(conf->headers_scheme & HEADER_SCHEME_V1) &&
			!(conf->headers_scheme & HEADER_SCHEME_V2)) {
		DAV_ERROR_POOL(plog, 0, "You cannot disable both V1 and V2 header scheme");
		return DONE;
	}

	DAV_XDEBUG_POOL(plog, 0, "Checking the docroot XATTR lock for [%s]", conf->docroot);

	/* Runs the configured servers and check they do not serve
	 * the grid docroot with an unauthorized IP:PORT couple */
	for (s = server ; s ; s = s->next) {

		for (a = s->addrs ; a ; a = a->next) {
			apr_status_t status;
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

			state = rawx_get_volume_lock_state(conf->docroot, conf->ns_name, url, &gerr);
			switch (state) {

				case ERROR_LS:
					DAV_ERROR_POOL(plog, 0, "Failed to check the docroot ownership : %s",
							gerror_get_message(gerr));
					goto label_error;

				case NOLOCK_LS:
					if (!rawx_lock_volume(conf->docroot, conf->ns_name, url, 0, &gerr)) {
						DAV_ERROR_POOL(plog, 0, "Failed to grab the docroot ownership : %s",
								gerror_get_message(gerr));
						goto label_error;
					}
					DAV_DEBUG_POOL(plog, 0, "Docroot now owned");
					volume_validated = ~0;
					break;

				case OWN_LS:
					DAV_DEBUG_POOL(plog, 0, "Docroot already owned by the current server");
					if (!rawx_lock_volume(conf->docroot, conf->ns_name, url,
							RAWXLOCK_FLAG_OVERWRITE, &gerr))
						DAV_ERROR_POOL(plog, 0, "Failed to complete the docroot ownership : %s",
							gerror_get_message(gerr));
					volume_validated = ~0;
					break;

				case OTHER_LS:
					DAV_ERROR_POOL(plog, 0, "Another RAWX already used the docroot (see XATTR)"
							" : %s", gerror_get_message(gerr));
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

	/* Init the stat support : doing this so late avoids letting orphan
	 * SHM segments in the nature in case of previous errors */
	status = server_init_master_stat(conf, pconf, plog);
	if (APR_SUCCESS != status) {
		DAV_ERROR_POOL(plog, 0, "Failed to init the RAWX statistics support");
		return DONE;
	}
	else {
		/* This will be overwritten by the child_init */
		conf->cleanup = _stat_cleanup_master;
		apr_pool_userdata_set(conf, apr_psprintf(pconf, "RAWX-config-to-be-cleaned-%d", i++),
				_stat_cleanup_to_register, pconf);
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
    AP_INIT_TAKE1("grid_headers",     dav_rawx_cmd_gridconfig_headers,     NULL, RSRC_CONF, "which header scheme to adopt (1, 2, both)"),
    AP_INIT_TAKE1("grid_acl",         dav_rawx_cmd_gridconfig_acl,         NULL, RSRC_CONF, "enabled acl"),
    AP_INIT_TAKE1("grid_upload_blocksize",    dav_rawx_cmd_gridconfig_upblock,     NULL, RSRC_CONF, "upload block size"),
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
