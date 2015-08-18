/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/remote/gridcluster_remote.h>

#include "gridcluster.h"
#include "message.h"

#define MAX_REQ_LENGTH 1024
#define CONNECT_TIMEOUT 5000
#define SOCKET_TIMEOUT 5000
#define BUF (wrkParam+writen)
#define LEN (sizeof(wrkParam)-writen-1)
#define MANAGE_ERROR(Req,Resp,Error) do {\
	if (Resp.data_size > 0 && Resp.data)\
		GSETERROR(Error, "Error from agent : %.*s", Resp.data_size, (char*)(Resp.data));\
	else\
		GSETERROR(Error, "Error from agent : (no response)");\
	clear_request_and_reply(&Req,&Resp);\
} while (0)
#define NS_WORM_OPT_NAME "worm"
#define NS_CONTAINER_MAX_SIZE_NAME "container_max_size"
#define NS_STORAGE_POLICY_NAME "storage_policy"
#define NS_CHUNK_SIZE_NAME "chunk_size"
#define NS_WORM_OPT_VALUE_ON "on"
#define NS_COMPRESS_OPT_NAME "compression"
#define NS_COMPRESS_OPT_VALUE_ON "on"

static gint64
_gba_to_int64(GByteArray *gba, gboolean def)
{
	if (!gba)
		return def;
	gchar *str = g_alloca(gba->len + 1);
	memset(str, 0, gba->len + 1);
	memcpy(str, gba->data, gba->len);
	return g_ascii_strtoll(str, NULL, 10);
}

static gboolean
_gba_to_bool(GByteArray *gba, gboolean def)
{
	if (!gba || !gba->data || !gba->len)
		return def;
	if (!gba->data[ gba->len - 1 ])
		return metautils_cfg_get_bool((gchar*)gba->data, def);
	gchar *str = g_alloca(gba->len + 1);
	memset(str, 0, gba->len + 1);
	memcpy(str, gba->data, gba->len);
	return metautils_cfg_get_bool(str, def);
}

static void
clear_request_and_reply( request_t *req, response_t *resp )
{
	if (req) {
		if (req->cmd)
			g_free(req->cmd);
		if (req->arg)
			g_free(req->arg);
		memset(req,0x00,sizeof(request_t));
	}
	if (resp) {
		if (resp->data)
			g_free(resp->data);
		memset(resp,0x00,sizeof(response_t));
	}
}

static namespace_info_t*
_get_namespace_info_from_agent(const char *ns_name, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_GETNS);
	req.arg = g_strdup(ns_name);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request get_namespace_info to agent failed");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status == STATUS_OK) {
		namespace_info_t *ns = namespace_info_unmarshall(resp.data, resp.data_size, error);
		clear_request_and_reply(&req,&resp);
		if (ns == NULL) {
			GSETERROR(error, "Failed to unserialize namespace_info");
			return NULL;
		}
		return ns;
	}

	if (resp.status == STATUS_ERROR) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}

	GSETERROR(error, "Unknown status received from agent");
	clear_request_and_reply(&req,&resp);
	return NULL;
}

static namespace_info_t*
_get_namespace_info_from_conscience(const char *ns_name, GError **error)
{
	addr_info_t *addr = gridcluster_get_conscience_addr(ns_name);
	if (addr == NULL) {
		GSETERROR(error, "Unknown namespace/conscience");
		return NULL;
	}
	namespace_info_t *res = gcluster_get_namespace_info_full(addr,
			CONNECT_TIMEOUT + SOCKET_TIMEOUT, error);
	g_free(addr);
	if (res)
		g_strlcpy(res->name, ns_name, LIMIT_LENGTH_NSNAME);
	return res;
}

namespace_info_t*
get_namespace_info(const char *ns_name, GError **error)
{
	if (!gridagent_available()) {
		return _get_namespace_info_from_conscience(ns_name, error);
	} else {
		return _get_namespace_info_from_agent(ns_name, error);
	}
}

meta0_info_t*
get_meta0_info(const char *ns_name, GError **error)
{
	GSList *services = list_namespace_services(ns_name, NAME_SRVTYPE_META0, error);
	if (!services) {
		GSETERROR(error,"No META0 found");
		return NULL;
	}

	struct service_info_s *si = g_slist_nth_data(services,
			rand() % g_slist_length(services));

	meta0_info_t *meta0 = g_malloc0(sizeof(meta0_info_t));
	memcpy( &(meta0->addr), &(si->addr), sizeof(addr_info_t));
	g_slist_free_full (services, (GDestroyNotify)service_info_clean);
	return meta0;
}

static GSList*
_list_namespace_service_types_from_agent(const char *ns_name, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRVTYPE_LST);
	req.arg = g_strdup(ns_name);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}

	GSList *names = NULL;
	if (!strings_unmarshall(&names, resp.data, resp.data_size, error))
		GSETERROR(error, "Invalid reply from agent : bad names payload (deserialization error)");
	clear_request_and_reply(&req,&resp);
	return names;
}

GSList*
list_namespace_service_types(const char *ns_name, GError **error)
{
	if (gridagent_available()) {
		return _list_namespace_service_types_from_agent(ns_name, error);
	} else {
		addr_info_t *cs_addr = gridcluster_get_conscience_addr(ns_name);
		if (!cs_addr) {
			GSETERROR(error, "Unknown namespace/conscience");
			return(NULL);
		}

		GSList *types = gcluster_get_service_types(cs_addr,
				CONNECT_TIMEOUT + SOCKET_TIMEOUT, error);
		g_free(cs_addr);
		return types;
	}
}

static GSList*
list_gridagent_services(const char *ns_name, const char *type, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRV_LST);
	req.arg = g_strdup_printf("%s:%s",ns_name,type);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status == STATUS_OK) {
		GSList *services = NULL;

		if (!resp.data || resp.data_size<=0) {
			GSETERROR(error,"Empty content received from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}

		if (0>service_info_unmarshall(&services, resp.data, resp.data_size,error)) {
			GSETERROR(error,"Invalid content from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}

		clear_request_and_reply(&req,&resp);
		return services;
	}

	MANAGE_ERROR(req,resp,error);
	return NULL;
}

GSList*
list_namespace_services(const char *ns_name, const char *type, GError **error)
{
	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	if (!gridagent_available()) { // from conscience
		gchar *cs = gridcluster_get_conscience(ns_name);
		if (!cs) {
			GSETERROR(error, "Unknown namespace/conscience");
			return NULL;
		} else {
			GSList *res = gcluster_get_services(cs, CS_CLIENT_TIMEOUT, type, FALSE, error);
			g_free(cs);
			return res;
		}
	} else { // from agent
		return list_gridagent_services(ns_name,type,error);
	}
}

struct service_info_s*
get_one_namespace_service(const gchar *ns_name, const gchar *type, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	if (!gridagent_available()) {
		// Find best scored service. This is basically what's done in agent.
		struct service_info_s *res = NULL;
		GSList *services = list_namespace_services(ns_name, type, error);
		if (services) {
			struct service_info_s *best = NULL;
			for (GSList *l = services; l; l = l->next) {
				struct service_info_s *cur = l->data;
				if (cur->score.value > 0 &&
						(!best || cur->score.value > best->score.value)) {
					best = cur;
				}
			}
			res = service_info_dup(best); // NULL safe
			g_slist_free_full(services, (GDestroyNotify)service_info_clean);
		}
		if (!res && error && !*error) {
			*error = NEWERROR(CODE_POLICY_NOT_SATISFIABLE,
					"No %s service found", type);
		}
		return res;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRV_GET1);
	req.arg = g_strdup_printf("%s:%s", ns_name, type);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status == STATUS_OK) {
		GSList *services = NULL;

		if (!resp.data || resp.data_size<=0) {
			GSETERROR(error,"Empty content received from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}

		if (0>service_info_unmarshall(&services,resp.data, resp.data_size,error)) {
			GSETERROR(error,"Invalid content from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}
		clear_request_and_reply(&req,&resp);
		if (services) {
			struct service_info_s *si;

			si = service_info_dup(services->data);
			g_slist_foreach(services, service_info_gclean, NULL);
			g_slist_free(services);
			return si;
		}
	
		GSETERROR(error, "No service found for type=[%s] in namespace [%s]", type, ns_name);
		return NULL;
	}

	MANAGE_ERROR(req,resp,error);
	return NULL;
}

static GSList*
copy_service_info(const struct service_info_s *si)
{
	GSList *l;
	struct service_info_s *si_copy;

	si_copy = service_info_dup(si);
	if (!si_copy)
		return NULL;

	si_copy->score.value = -2;/*avoid positive values on -1, all others mean "unset"*/
	si_copy->score.timestamp = time(0);
	l = g_slist_append(NULL,si_copy);
	if (!l) {
		service_info_clean(si_copy);
		return NULL;
	}

	return l;
}

int
register_namespace_service(const struct service_info_s *si, GError **error)
{
	GSList *l;
	GByteArray *gba;
	request_t req;
	response_t resp;

	if (!si) {
		GSETERROR(error, "Arg <si> can not be NULL");
		return 0;
	}

	l = copy_service_info(si);
	if (!l) {
		GSETERROR(error,"Request not tried, memory allocation failure");
		return 0;
	}

	gba = service_info_marshall_gba(l,error);
	g_slist_foreach(l,service_info_gclean,NULL);
	g_slist_free(l);

	if (!gba) {
		GSETERROR(error,"No request tried, service_info serialization error");
		return 0;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRV_PSH);
	req.arg = (char*)gba->data;
	req.arg_size = gba->len;
	g_byte_array_free(gba,FALSE);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request register failed");
		clear_request_and_reply(&req,&resp);
		return 0;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return 0;
	}

	clear_request_and_reply(&req,&resp);
	return 1;
}

GSList*
list_local_services(GError **error)
{
	request_t req;
	response_t resp;
	GSList *srv_list = NULL;

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_LSTSVC);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request list services failed");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}

	if (!service_info_unmarshall(&srv_list,resp.data, resp.data_size,error)) {
		GSETERROR(error,"Invalid answer from the agent");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	clear_request_and_reply(&req,&resp);
	return srv_list;
}

int
clear_namespace_services(const char *ns_name, const char *type, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRV_CLR);
	req.arg = g_strdup_printf("%s:%s",ns_name,type);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request clear_services to agent failed");
		clear_request_and_reply(&req,&resp);
		return 0;
	}

	if (resp.status!=STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		clear_request_and_reply(&req,&resp);
		return 0;
	}

	clear_request_and_reply(&req,&resp);
	return 1;
}

GSList*
list_tasks(GError **error)
{
	request_t req;
	response_t resp;

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_LSTTASK);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request list tasks failed");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status == STATUS_OK) {
		size_t size_read = 0;
		struct task_s task;
		GSList *task_list = NULL;
		while (size_read < resp.data_size) {
			memset(&task, 0, sizeof(task));

			memcpy(task.id, resp.data + size_read, sizeof(task.id));
			size_read += sizeof(task.id);

			memcpy(&(task.period), resp.data + size_read, sizeof(task.period));
			size_read += sizeof(task.period);

			memcpy(&(task.busy), resp.data + size_read, sizeof(task.busy));
			size_read += sizeof(task.busy);

			task_list = g_slist_prepend(task_list, g_memdup(&task, sizeof(struct task_s)));
		}

		clear_request_and_reply(&req,&resp);
		return(task_list);

	}

	MANAGE_ERROR(req,resp,error);
	return NULL;
}

/* ------------------------------------------------------------------------- */

static GByteArray *
namespace_param_gba(const namespace_info_t* ns_info, const gchar *ns_name,
		const gchar *param_name)
{
	return namespace_info_get_srv_param_gba(ns_info, ns_name, NULL, param_name);
}

gchar*
gridcluster_get_nsinfo_strvalue(struct namespace_info_s *nsinfo,
		const gchar *key, const gchar *def)
{
	GByteArray *value;

	if (!nsinfo || !nsinfo->options)
		return g_strdup(def);

	value = g_hash_table_lookup(nsinfo->options, key);
	if (!value)
		return g_strdup(def);

	return g_strndup((gchar*)value->data, value->len);
}

gint64
gridcluster_get_nsinfo_int64(struct namespace_info_s *nsinfo,
		const gchar* key, gint64 def)
{
	return namespace_info_get_srv_param_i64(nsinfo, NULL, NULL, key, def);
}

static gsize
namespace_get_size(namespace_info_t *ns_info, const gchar *name, gsize def)
{
	return (gsize) gridcluster_get_nsinfo_int64(ns_info, name, def);
}

gboolean
namespace_in_worm_mode(namespace_info_t* ns_info)
{
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_WORM_OPT_NAME);
	return _gba_to_bool(val, FALSE);
}

gint64
namespace_container_max_size(namespace_info_t* ns_info)
{
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_CONTAINER_MAX_SIZE_NAME);
	return _gba_to_int64(val, -1);
}

gint64
namespace_chunk_size(const namespace_info_t* ns_info, const char *ns_name)
{
	GByteArray *val = namespace_param_gba(ns_info, ns_name,
			NS_CHUNK_SIZE_NAME);
	return _gba_to_int64(val, ns_info->chunk_size);
}

gchar *
namespace_storage_policy(const namespace_info_t* ns_info, const char *ns_name)
{
	GByteArray *gba = namespace_param_gba(ns_info, ns_name,
			NS_STORAGE_POLICY_NAME);
	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

gchar*
namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy)
{
	const gchar *policy_to_lookup = wanted_policy ?
			wanted_policy : namespace_storage_policy(ns_info, ns_info->name);

	if (!ns_info || ns_info->storage_policy)
		return NULL;

	GByteArray *gba = g_hash_table_lookup(ns_info->storage_policy, policy_to_lookup);

	if (!wanted_policy)
		g_free((gpointer)policy_to_lookup);

	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

static gchar*
_get_token(const gchar *colon_separated_tokens, const guint token_rank)
{
	gchar **tokens = g_strsplit(colon_separated_tokens, ":", 0);
	gchar *token_wanted = NULL;

	if (g_strv_length(tokens) < token_rank) {
		ERROR("Cannot split string [%s] into %i ':'-separated tokens.", colon_separated_tokens, token_rank);
		goto end;
	}

	token_wanted = g_strdup(tokens[token_rank]);

end:
	if (tokens)
		g_strfreev(tokens);

	return token_wanted;
}

static gchar*
_get_data_security_id(const gchar *storage_policy_value)
{
	gchar *data_sec_id = _get_token(storage_policy_value, 1);

	if (!data_sec_id) {
		WARN("Storage policy configuration seems to be wrong: [%s]"
				" Correct pattern is STG_CLASS:DATA_SEC:DATA_THREAT",
				storage_policy_value ? storage_policy_value : "NULL");
	}

	return data_sec_id;
}

gchar*
namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy)
{
	gchar *storage_policy_value = namespace_storage_policy_value(ns_info, wanted_policy);
	gchar *data_sec_id = _get_data_security_id(storage_policy_value);
	GByteArray *data_sec_val = NULL;
	gchar str_data_sec_val[LIMIT_LENGTH_STGPOLICY];

	if (storage_policy_value && data_sec_id) {
		data_sec_val = g_hash_table_lookup(ns_info->data_security, data_sec_id);
	}

	if (!data_sec_val) {
		WARN("Cannot find data security with id [%s] (namespace [%s], wanted policy [%s])",
				data_sec_id, ns_info->name, wanted_policy);
	}

	if (data_sec_id)
		g_free(data_sec_id);
	if (storage_policy_value)
		g_free(storage_policy_value);

	metautils_gba_data_to_string(data_sec_val, str_data_sec_val, LIMIT_LENGTH_STGPOLICY);
	return g_strdup(str_data_sec_val);
}

gboolean
namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy)
{
	if (!ns_info || !ns_info->storage_policy || !storage_policy)
		return FALSE;
	if (!g_hash_table_lookup(ns_info->storage_policy, storage_policy))
		return FALSE;
	return TRUE;
}

gboolean
namespace_in_compression_mode(namespace_info_t* ns_info)
{
	if (!ns_info || !ns_info->options)
		return FALSE;
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_COMPRESS_OPT_NAME);
	gboolean res = _gba_to_bool(val, FALSE);
	return res;
}

gsize
namespace_get_autocontainer_src_offset(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_offset", 0);
}

gsize
namespace_get_autocontainer_src_size(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_size", 0);
}

gsize
namespace_get_autocontainer_dst_bits(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_bitlength", 17);
}

gint64
gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo)
{
	/* For backward compatibility, versioning is disabled by default */
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_max_versions", 0);
}

gint64
gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo)
{
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_keep_deleted_delay", -1);
}

gchar *
gridcluster_get_service_update_policy (struct namespace_info_s *nsinfo)
{
	const gchar *def = "meta2=KEEP|1|1|;sqlx=KEEP|3|1|";

	if (!nsinfo || !nsinfo->options)
		return g_strdup(def);

	return gridcluster_get_nsinfo_strvalue (nsinfo, "service_update_policy", def);
}

GError*
gridcluster_reload_lbpool(struct grid_lbpool_s *glp)
{
	gboolean _reload_srvtype(const gchar *ns, const gchar *srvtype) {
		GError *err = NULL;
		GSList *list_srv = list_namespace_services(ns, srvtype, &err);
		if (err) {
			GRID_WARN("Gridagent/conscience error: Failed to list the services"
					" of type [%s]: code=%d %s", srvtype, err->code,
					err->message);
			g_clear_error(&err);
			return FALSE;
		}

		if (list_srv) {
			GSList *l = list_srv;

			gboolean provide(struct service_info_s **p_si) {
				if (!l)
					return FALSE;
				*p_si = l->data;
				l->data = NULL;
				l = l->next;
				return TRUE;
			}
			grid_lbpool_reload(glp, srvtype, provide);
			g_slist_free(list_srv);
		}

		return TRUE;
	}

	GError *err = NULL;
	GSList *list_srvtypes = list_namespace_service_types(grid_lbpool_namespace(glp), &err);
	if (err)
		g_prefix_error(&err, "LB pool reload error: ");
	else {
		guint errors = 0;
		const gchar *ns = grid_lbpool_namespace(glp);

		for (GSList *l=list_srvtypes; l ;l=l->next) {
			if (!l->data)
				continue;
			if (!_reload_srvtype(ns, l->data))
				++ errors;
		}

		if (errors)
			GRID_DEBUG("Reloaded %u service types, with %u errors",
					g_slist_length(list_srvtypes), errors);
	}

	g_slist_foreach(list_srvtypes, g_free1, NULL);
	g_slist_free(list_srvtypes);
	return err;
}

GError*
gridcluster_reconfigure_lbpool(struct grid_lbpool_s *glp)
{
	GError *err = NULL;
	namespace_info_t *nsinfo;

	nsinfo = get_namespace_info(grid_lbpool_namespace(glp), &err);
	if (NULL != nsinfo) {
		grid_lbpool_reconfigure(glp, nsinfo);
		namespace_info_free(nsinfo);
	}

	return err;
}

struct addr_info_s *
gridcluster_get_conscience_addr(const char *ns_name)
{
	addr_info_t addr;
	gchar *cs = gridcluster_get_conscience(ns_name);
	if (!cs)
		return NULL;
	gboolean rc = grid_string_to_addrinfo(cs, NULL, &addr);
	g_free(cs);
	return rc ? g_memdup(&addr, sizeof(addr_info_t)) : NULL;
}

gchar *
gridcluster_get_agent(void)
{
	gchar *cfg = oio_cfg_get_value(NULL, OIO_CFG_AGENT);
	return cfg ? cfg : g_strdup(GCLUSTER_AGENT_SOCK_PATH);
}

