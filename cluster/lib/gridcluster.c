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
#include <cluster/remote/gridcluster_remote.h>

#include "gridcluster.h"
#include "message.h"

#define MANAGE_ERROR(Req,Resp,Error) do {\
	if (Resp.data_size > 0 && Resp.data)\
		GSETERROR(Error, "Error from agent : %.*s", Resp.data_size, (char*)(Resp.data));\
	else\
		GSETERROR(Error, "Error from agent : (no response)");\
	clear_request_and_reply(&Req,&Resp);\
} while (0)

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
	namespace_info_t *res = NULL;
	gchar *cs = gridcluster_get_conscience(ns_name);
	GError *err = gcluster_get_namespace_info_full(cs, &res);
	g_free0(cs);
	if (res)
		g_strlcpy(res->name, ns_name, LIMIT_LENGTH_NSNAME);
	g_error_transmit (error, err);
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
		GSList *types = NULL;
		gchar *cs = gridcluster_get_conscience(ns_name);
		GError *err = gcluster_get_service_types(cs, &types);
		g_free0 (cs);
		g_error_transmit (error, err);
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
		GSList *res = NULL;
		gchar *cs = gridcluster_get_conscience(ns_name);
		GError *err = gcluster_get_services(cs, type, FALSE, &res);
		g_free0 (cs);
		g_error_transmit (error, err);
		return res;
	} else { // from agent
		return list_gridagent_services(ns_name,type,error);
	}
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

GError*
gridcluster_reload_lbpool(struct grid_lbpool_s *glp)
{
	gboolean _reload_srvtype(const char *ns, const char *srvtype) {
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
		const char *ns = grid_lbpool_namespace(glp);

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

gchar *
oio_cfg_get_agent(void)
{
	gchar *cfg = oio_cfg_get_value(NULL, OIO_CFG_AGENT);
	return cfg ? cfg : g_strdup(GCLUSTER_AGENT_SOCK_PATH);
}

