#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.lib"
#endif

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
#include "connect.h"
#include "message.h"

#define MAX_REQ_LENGTH 1024
#define CONNECT_TIMEOUT 5000
#define SOCKET_TIMEOUT 5000
#define BUF (wrkParam+writen)
#define LEN (sizeof(wrkParam)-writen-1)
#define MANAGE_ERROR(Req,Resp,Error) do {\
	if (Resp.data_size > 0 && Resp.data)\
		GSETERROR(Error, "Error from agent : %.*s", Resp.data_size, Resp.data);\
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

static gboolean
gridagent_available(void)
{
	struct stat sock_stat;
	return (stat(AGENT_SOCK_PATH, &sock_stat) == 0);
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

/**
 * Get conscience address from configuration files.
 *
 * Do not forget to free the result (g_free).
 */
static addr_info_t*
_get_cs_addr(const char *ns_name, GError **error) {
	addr_info_t *cs_addr;
	GHashTable *ns_hash;

	cs_addr = NULL;
	ns_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	if (!parse_cluster_config(ns_hash, error)) {
		g_hash_table_destroy(ns_hash);
		GSETERROR(error, "Failed to parse cluster config");
		return(NULL);
	}

	/* Need to truncate NS name => only physical NS NAME file exists */
	gchar **tmp = NULL;
	tmp =g_strsplit(ns_name , ".", 2);
	cs_addr = g_hash_table_lookup(ns_hash, tmp[0]);
	g_strfreev(tmp);

	if (!cs_addr) {
		GSETERROR(error, "No conscience addr found for namespace [%s]", ns_name);
	} else {
		cs_addr = g_memdup(cs_addr, sizeof(addr_info_t));
	}

	g_hash_table_destroy(ns_hash);
	return cs_addr;
}

static namespace_info_t*
_get_namespace_info_from_agent(const char *ns_name, GError **error)
{
	request_t req;
	response_t resp;

	gchar master_ns[512];
	gchar *virt_ns = NULL;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	virt_ns = strchr(ns_name, '.');
	memset(master_ns, '\0', 512);
	g_snprintf(master_ns, 512, "%.*s:%s",
		virt_ns!=NULL? (gint) (virt_ns - ns_name) : (gint)strlen(ns_name), ns_name,
		SHORT_API_VERSION);
	
	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_GETNS);
	req.arg = g_strdup(master_ns);
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
		if (virt_ns) {
			memset(ns->name, '\0', LIMIT_LENGTH_NSNAME);
			g_strlcpy(ns->name, ns_name, LIMIT_LENGTH_NSNAME);
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
	GError *local_error = NULL;
	namespace_info_t *res = NULL;
	addr_info_t *addr = _get_cs_addr(ns_name, &local_error);
	if (addr == NULL) {
		g_prefix_error(&local_error, "Failed to get conscience address: ");
		*error = local_error;
		res = NULL;
	} else {
		res = gcluster_get_namespace_info_full(addr,
				CONNECT_TIMEOUT + SOCKET_TIMEOUT, error);
		g_free(addr);
		// In case we asked for a VNS
		if (res)
			g_strlcpy(res->name, ns_name, LIMIT_LENGTH_NSNAME);
	}
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


static meta0_info_t*
get_meta0_info_from_conscience(const char *ns_name, long timeout_cnx, long timeout_req, GError **error)
{
	meta0_info_t *meta0;
	addr_info_t *cs_addr;

	cs_addr = _get_cs_addr(ns_name,error);
	if(!cs_addr)
		return(NULL);

	meta0 = gcluster_get_meta0_2timeouts(cs_addr, timeout_cnx, timeout_req, error);
	if (!meta0)
		GSETERROR(error, "Failed to retrieve meta0 infos from conscience of namespace [%s] timeout(%ld,%ld)",
				ns_name, timeout_cnx, timeout_req);
	g_free(cs_addr);
	return(meta0);
}

static meta0_info_t*
get_meta0_info_from_agent(const char *ns_name, GError **error)
{
	struct service_info_s *si;
	GSList *services;
	meta0_info_t *meta0 = NULL;

	/* Build request */
	services = list_namespace_services(ns_name,"meta0",error);
	if (!services) {
		GSETERROR(error,"No META0 found");
		return NULL;
	}

	srand(time(NULL));
	si = g_slist_nth_data(services,rand()%g_slist_length(services));
	meta0 = g_try_malloc0(sizeof(meta0_info_t));
	if (meta0)
		memcpy( &(meta0->addr), &(si->addr), sizeof(addr_info_t));
	g_slist_foreach( services, service_info_gclean, NULL);
	g_slist_free( services );
	return meta0;
}

meta0_info_t *
get_meta0_info2(const char *ns_name, long timeout_cnx, long timeout_req, GError **error)
{
	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	if (!gridagent_available())
		return get_meta0_info_from_conscience(ns_name, timeout_cnx, timeout_req, error);
	else
		return get_meta0_info_from_agent(ns_name, error);
}

meta0_info_t*
get_meta0_info(const char *ns_name, GError **error)
{
	return get_meta0_info2(ns_name, 1000, 4000, error);
}

gint
count_namespace_services(const char *ns_name, const char *type, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return -1;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRV_CNT);
	req.arg = g_strdup_printf("%s:%s",ns_name,type);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request '%s' to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return -1;
	}
	if (resp.status == STATUS_OK) {
		gchar wrkBuf[1024];
		gint64 nbVol64;
		gint32 nbVol32;
	
		memset( wrkBuf, 0x00, sizeof(wrkBuf) );
		g_strlcpy( wrkBuf, resp.data, MAX(sizeof(wrkBuf)-1,resp.data_size));
		nbVol64 = g_ascii_strtoll( wrkBuf, NULL, 10 );
	
		nbVol32 = nbVol64;
		clear_request_and_reply(&req,&resp);
		return nbVol32;
	}

	MANAGE_ERROR(req,resp,error);
	return -1;
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
	names = meta2_maintenance_names_unmarshall_buffer(resp.data,resp.data_size,error);
	if (!names)
		GSETERROR(error,"Invalid reply from agent : bad names payload (deserialization error)");
	clear_request_and_reply(&req,&resp);
	return names;
}

static GSList*
_list_namespace_service_types_from_conscience(const char *ns_name, GError **error)
{
	addr_info_t *cs_addr;

	cs_addr = _get_cs_addr(ns_name,error);
	if(!cs_addr)
		return(NULL);

	GSList *types = gcluster_get_service_types(cs_addr,
			CONNECT_TIMEOUT + SOCKET_TIMEOUT, error);

	g_free(cs_addr);
	return types;
}

GSList*
list_namespace_service_types(const char *ns_name, GError **error)
{
	if (gridagent_available()) {
		return _list_namespace_service_types_from_agent(ns_name, error);
	} else {
		return _list_namespace_service_types_from_conscience(ns_name, error);
	}
}

GSList*
list_namespace_services(const char *ns_name, const char *type, GError **error)
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
		gsize body_size;

		if (!resp.data || resp.data_size<=0) {
			GSETERROR(error,"Empty content received from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}

		body_size = resp.data_size;
		if (0>service_info_unmarshall(&services,resp.data,&body_size,error)) {
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
list_namespace_services2(const char *ns_name, const char *type, GError **error)
{
	if (!ns_name || !type) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	if (!gridagent_available()) {
		// from conscience
		addr_info_t *cs_addr;

		cs_addr = _get_cs_addr(ns_name,error);
		if(!cs_addr)
			return(NULL);

		GSList *res = gcluster_get_services2(cs_addr, 1000, 4000, type, error);
		g_free(cs_addr);
		return res;
	} else {
		// from agent
		return list_namespace_services(ns_name,type,error);
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
		GSList *services = list_namespace_services2(ns_name, type, error);
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
		gsize body_size;

		if (!resp.data || resp.data_size<=0) {
			GSETERROR(error,"Empty content received from the gridagent");
			clear_request_and_reply(&req,&resp);
			return NULL;
		}

		body_size = resp.data_size;
		if (0>service_info_unmarshall(&services,resp.data,&body_size,error)) {
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
	gsize resp_size;

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

	resp_size = resp.data_size;
	if (!service_info_unmarshall(&srv_list,resp.data,&resp_size,error)) {
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

/* ------------------------------------------------------------------------- */

int
store_erroneous_content( const char *ns_name, const container_id_t cID,
	addr_info_t *src_addr, GError **error, const gchar *path, const gchar *cause )
{
	gsize writen;
	request_t req;
	response_t resp;
	char wrkParam[4096];

	if (!cID || !ns_name || !src_addr) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Pack the parameters : hexadecimal cID, colon, ascii namespace */
	memset(wrkParam, 0, sizeof(wrkParam));
	writen = 0;
	writen += g_snprintf( BUF, LEN, "%s:", ns_name);
	writen += addr_info_to_string( src_addr, BUF, LEN);
	writen += g_snprintf( BUF, LEN, ":");
	writen += container_id_to_string( cID, BUF, LEN);

	if (path && cause)
		writen += g_snprintf( BUF, LEN, ":%s:%s", path, cause);
	else if (path)
		writen += g_snprintf( BUF, LEN, ":%s:", path);
	else
		writen += g_snprintf( BUF, LEN, "::");

	DEBUG("Message sent to agent: (length=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT") [%s]", writen, strlen(wrkParam), wrkParam);

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_STORE);
	req.arg = g_strndup(wrkParam, writen);
	req.arg_size = writen;

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
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

int
fixed_erroneous_content( const char *ns_name, const container_id_t cID, GError **error, const gchar *path)
{
	request_t req;
	response_t resp;
	gsize writen;
	char wrkParam[LIMIT_LENGTH_NSNAME+1+STRLEN_CONTAINERID+1+LIMIT_LENGTH_CONTENTPATH+1];

	if (!cID || !ns_name) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Pack the parameters : hexadecimal cID, colon, ascii namespace */
	memset(wrkParam, 0, sizeof(wrkParam));
	writen = 0;
	writen += g_snprintf( BUF, LEN, "%s:0.0.0.0:0:", ns_name);
	writen += container_id_to_string( cID, BUF, LEN);
	writen += g_snprintf( BUF, LEN, ":%s", path?path:"");
	DEBUG("Message sent to agent: (length=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT") [%s]", writen, strlen(wrkParam), wrkParam);

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_FIXED);
	req.arg = g_strndup(wrkParam, writen);
	req.arg_size = writen;

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
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

int
store_erroneous_meta1( const char *ns_name, const addr_info_t *m1_addr, GError **error )
{
	gsize writen;
	request_t req;
	response_t resp;
	char wrkParam[ LIMIT_LENGTH_NSNAME + 1 + sizeof("META1:") + STRLEN_ADDRINFO ];

	if (!ns_name || !m1_addr) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Pack the parameters : hexadecimal cID, colon, ascii namespace */
	memset(wrkParam, 0, sizeof(wrkParam));
	writen = 0;
	writen += g_snprintf( BUF, LEN, "%s:META1:", ns_name);
	writen += addr_info_to_string( m1_addr, BUF, LEN);
	DEBUG("Message sent to agent: (length=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT") [%s]", writen, strlen(wrkParam), wrkParam);

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_STORE);
	req.arg = g_strndup(wrkParam, writen+1);
	req.arg_size = writen;

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
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

int
store_erroneous_container( const char *ns_name, const container_id_t cID, addr_info_t *src_addr, GError **error )
{
	gsize writen;
	request_t req;
	response_t resp;
	char wrkParam[2048];

	if (!cID || !ns_name || !src_addr) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Pack the parameters : hexadecimal cID, colon, ascii namespace */
	memset(wrkParam, 0, sizeof(wrkParam));
	writen = 0;
	writen += g_snprintf( BUF, LEN, "%s:", ns_name);
	writen += addr_info_to_string( src_addr, BUF, LEN);
	writen += g_snprintf( BUF, LEN, ":");
	writen += container_id_to_string( cID, BUF, LEN);
	writen += g_snprintf( BUF, LEN, "::");
	DEBUG("Message sent to agent: (length=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT") [%s]", writen, strlen(wrkParam), wrkParam);

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_STORE);
	req.arg = g_strndup(wrkParam, writen+1);
	req.arg_size = writen;

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return 0;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return 0;
	}

	clear_request_and_reply(&req,&resp);
	return(1);
}

int
fixed_erroneous_meta1( const char *ns_name, GError **error, addr_info_t *m1_addr)
{
	gsize writen;
	request_t req;
	response_t resp;
	char wrkParam[ LIMIT_LENGTH_NSNAME + 1 + sizeof("META1:") + STRLEN_ADDRINFO ];

	if (!ns_name || !m1_addr) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	/* Pack the parameters : hexadecimal cID, colon, ascii namespace */
	memset(wrkParam, 0, sizeof(wrkParam));
	writen = 0;
	writen += g_snprintf( BUF, LEN, "%s:META1:", ns_name);
	writen += addr_info_to_string( m1_addr, BUF, LEN);
	DEBUG("Message sent to agent: (length=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT") [%s]", writen, strlen(wrkParam), wrkParam);

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_FIXED);
	req.arg = g_strndup(wrkParam, writen+1);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request to agent failed");
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
fetch_erroneous_containers( const char *ns_name, GError **error )
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return NULL;
	}

	/* Build request */
	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_FETCH);
	req.arg = g_strdup(ns_name);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request to agent failed");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status == STATUS_OK) {
		ssize_t signed_size;
		GSList *result;
		gchar *ptr;
	
		ptr = resp.data;
		result = NULL;
		while (ptr && ptr-((gchar*)resp.data)<(signed_size=resp.data_size)) {
			if (*ptr) {
				int len = strlen( ptr );
				TRACE("new erroneous entity received, length=%d", len);
				result = g_slist_prepend( result, g_strdup( ptr ));
				ptr += len + 1;
			} else {
				TRACE("new erroneous entity received, empty!");
				ptr ++;
			}
		}
		clear_request_and_reply(&req,&resp);
		return result;
	}

	MANAGE_ERROR(req,resp,error);
	return NULL;
}

int
flush_erroneous_elements( const char *ns_name, GError **error )
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter");
		return 0;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_ERRCID_FLUSH);
	req.arg = g_strdup(ns_name);
	req.arg_size = strlen(req.arg);

	if (!send_request(&req, &resp, error)) {
		GSETERROR(error, "Request %s to agent failed", __FUNCTION__);
		clear_request_and_reply(&req,&resp);
		return 0;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return 0;
	}

	clear_request_and_reply(&req,&resp);
	return(1);
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

			memcpy(&(task.next_schedule), resp.data + size_read, sizeof(task.next_schedule));
			size_read += sizeof(task.next_schedule);

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

GSList*
event_get_managed_patterns(const gchar *ns_name, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter (%p)", ns_name);
		return NULL;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_EVENTS_PATTERNS);
	req.arg = (void*)ns_name;
	req.arg_size = strlen(ns_name)+1;

	if (!send_request(&req,&resp,error)) {
		GSETERROR(error,"Failed to forward the event to the agent");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}
	else {
		gsize resp_size;
		GSList *result = NULL;
		resp_size = resp.data_size;
		if (!strings_unmarshall(&result, resp.data, &resp_size, error)) {
			MANAGE_ERROR(req,resp,error);
			return NULL;
		}
		clear_request_and_reply(&req,&resp);
		return result;
	}
}

GByteArray*
event_get_configuration(const gchar *ns_name, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name) {
		GSETERROR(error,"Invalid parameter (%p)", ns_name);
		return NULL;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_EVENTS_CONFIGURATION);
	req.arg = g_strdup(ns_name);
	req.arg_size = strlen(req.arg)+1;

	if (!send_request(&req,&resp,error)) {
		GSETERROR(error,"Failed to forward the event to the agent");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}
	else {
		GByteArray *result;

		result = g_byte_array_append(g_byte_array_new(), resp.data, resp.data_size);
		clear_request_and_reply(&req,&resp);
		g_byte_array_append(result, (const guint8*)"", 1);
		return result;
	}
}

GByteArray*
get_srvtype_configuration(const gchar *ns_name, const gchar *type_name, GError **error)
{
	request_t req;
	response_t resp;

	if (!ns_name || !type_name) {
		GSETERROR(error,"Invalid parameter (%p,%p)", ns_name, type_name);
		return NULL;
	}

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_SRVTYPE_CONFIG);
	req.arg = g_strdup_printf("%s:%s",ns_name, type_name);
	req.arg_size = strlen(req.arg)+1;

	if (!send_request(&req,&resp,error)) {
		GSETERROR(error,"Failed to forward the event to the agent");
		clear_request_and_reply(&req,&resp);
		return NULL;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return NULL;
	}
	else {
		GByteArray *result;

		result = g_byte_array_append(g_byte_array_new(), resp.data, resp.data_size);
		clear_request_and_reply(&req,&resp);
		g_byte_array_append(result, (const guint8*)"", 1);
		return result;
	}
}

gboolean
event_send_to_agent( const gchar *ns_name, gridcluster_event_t *event, GError **error )
{
	request_t req;
	response_t resp;
	GByteArray *gba;

	if (!ns_name || !event) {
		GSETERROR(error,"Invalid parameter (%p,%p)", ns_name, event);
		return FALSE;
	}

	gba = gridcluster_encode_event(event, error);
	if (!gba) {
		GSETERROR(error,"Failed to serialize the event");
		return FALSE;
	}
	g_byte_array_prepend(gba, (const guint8*)ns_name, strlen(ns_name)+1);

	memset(&req, 0, sizeof(request_t));
	memset(&resp, 0, sizeof(response_t));
	req.cmd = g_strdup(MSG_EVT_PUSH);
	req.arg = (char*)gba->data;
	req.arg_size = gba->len;
	g_byte_array_free(gba,FALSE); gba = NULL;

	if (!send_request(&req,&resp,error)) {
		GSETERROR(error,"Failed to forward the event to the agent");
		clear_request_and_reply(&req,&resp);
		return FALSE;
	}

	if (resp.status != STATUS_OK) {
		MANAGE_ERROR(req,resp,error);
		return FALSE;
	}

	clear_request_and_reply(&req,&resp);
	return TRUE;
}

static GByteArray *
namespace_param_gba(const namespace_info_t* ns_info, const gchar *ns_name,
		const gchar *param_name)
{
	return namespace_info_get_srv_param_gba(ns_info, ns_name, NULL, param_name);
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

static gsize
namespace_get_size(namespace_info_t *ns_info, const gchar *name, gsize def)
{
	if (!ns_info || !ns_info->options || !name)
		return def;

	GByteArray *val = namespace_param_gba(ns_info, NULL, name);
	return (gsize) _gba_to_int64(val, def);
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

gboolean
namespace_get_rules_path(const gchar *ns, const gchar *typename, gchar **path,
		GError **err)
{
	if (!ns || !typename || !path) {
		GSETERROR(err, "Invalid parameter (%p %p %p)", ns, typename, path);
		return FALSE;
	}

	*path = g_strdup_printf("/GRID/%s/common/conf/%s.rules.py", ns, typename);
	return TRUE;
}

/**
 * FIXME TODO XXX File loading managed by glib2  : g_file_get_contents()
 * FIXME TODO XXX duplicated in metautils/lib/utils_acl.c : parse_acl_conf_file()
 */
static gboolean
gba_read(GByteArray *gba, int fd, GError **err)
{
	ssize_t r, offset = 0, max;
	struct stat s;

	fstat(fd, &s);

	max = s.st_size + 2;
	g_byte_array_set_size(gba, max);

	if (max > 0) {
		for (;;) {
			r = read(fd, gba->data + offset, max - offset);
			if (r == 0)
				break;
			if (r < 0) {
				GSETERROR(err, "read(%d) = %d (%s)", fd, errno, strerror(errno));
				return FALSE;
			}
			offset += r;
		}
	}

	/* pad with zeros */
	memset(gba->data + offset, 0, max - offset);

	return TRUE;
}

static gboolean
gba_read_path(GByteArray *gba, gchar *path, GError **err)
{
	if (!path || !*path) {
		GSETERROR(err, "invalid parameter (NULL/empty path)");
		return FALSE;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		GSETERROR(err, "open(%s) error : errno=%d (%s)", path, errno, strerror(errno));
		return FALSE;
	}

	gboolean rc = gba_read(gba, fd, err);
	metautils_pclose(&fd);
	return rc;
}

GByteArray*
namespace_get_rules(const gchar *ns, const gchar *typename, GError **err)
{
	GByteArray *gba = NULL;
	gchar *path = NULL;

	if (!ns || !typename) {
		GSETERROR(err, "Invalid parameter (%p %p)", ns, typename);
		return NULL;
	}

	if (!namespace_get_rules_path(ns, typename, &path, err)) {
		GSETERROR(err, "script's path not found");
		return NULL;
	}

	gba = g_byte_array_new();
	gboolean err_check = gba_read_path(gba, path, err);
	if (path)
		g_free(path);

	if (!err_check) {
		GSETERROR(err, "read error");
		g_byte_array_free(gba, TRUE);
		return NULL;
	}
	return gba;
}

static void
_svcupd_preload_with_default(GHashTable *ht, gchar *ns, const gchar *srvtype)
{
	if (!g_ascii_strcasecmp(srvtype, "meta1"))
		g_hash_table_insert(ht, g_strdup(ns), g_strdup(
					"meta2=NONE;solr=APPEND;redis=REPLACE"));
	else if (!g_ascii_strcasecmp(srvtype, "meta2"))
		g_hash_table_insert(ht, g_strdup(ns), g_strdup(
					"solr=APPEND;rawx=NONE;tsmx=APPEND"));
	else
		g_hash_table_insert(ht, g_strdup(ns), g_strdup(""));
}

static void
_complete_with_nsinfo(GHashTable *ht, struct namespace_info_s *ni,
		const gchar *key_suffix, const gchar *srvtype)
{
	GHashTableIter iter;
	gchar *k;
	GByteArray *vba;

	gchar *suffix = g_strdup_printf("%s.%s", key_suffix, srvtype);
	gsize suffix_len = strlen(suffix);

	g_hash_table_iter_init(&iter, ni->options);
	while (g_hash_table_iter_next(&iter, (gpointer*)&k, (gpointer*)&vba)) {
		if (g_str_has_suffix(k, suffix)) { // New key with NS
			gchar *key = (strlen(k) == suffix_len) ? g_strdup(ni->name)
				: g_strndup(k, strlen(k) - suffix_len);
			gchar *value = g_strndup((const char *)vba->data, vba->len);
			g_hash_table_insert(ht, key, value);
		}
		else if (0 == g_ascii_strcasecmp(k, suffix+1)) { // Old key without NS
			gchar *value = g_strndup((const char *)vba->data, vba->len);
			g_hash_table_insert(ht, g_strdup(ni->name), value);
		}
	}
	g_free(suffix);
}

GHashTable*
gridcluster_get_service_update_policy(struct namespace_info_s *nsinfo,
	const gchar *srvtype)
{
	if (!nsinfo || !nsinfo->options || !srvtype) {
		errno = EINVAL;
		return NULL;
	}

	GHashTable *result = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	_svcupd_preload_with_default(result, nsinfo->name, srvtype);
	_complete_with_nsinfo(result, nsinfo, "_service_update_policy", srvtype);
	return result;
}

static void
_evtcfg_preload_with_default(GHashTable *ht, gchar *ns, const gchar *srvtype)
{
	if (!g_ascii_strcasecmp(srvtype, "meta2"))
		g_hash_table_insert(ht, g_strdup(ns), g_strdup(
					"enabled=false;dir=/GRID/common/spool;aggregate=false"
					";kafka_enabled=false;kafka_topic=redc.meta2"));
	else
		g_hash_table_insert(ht, g_strdup(ns), g_strdup(""));
}


GHashTable*
gridcluster_get_event_config(struct namespace_info_s *nsinfo,
	const gchar *srvtype)
{
	if (!nsinfo || !nsinfo->options || !srvtype) {
		errno = EINVAL;
		return NULL;
	}

	GHashTable *result = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	_evtcfg_preload_with_default(result, nsinfo->name, srvtype);
	_complete_with_nsinfo(result, nsinfo, "_event_config", srvtype);
	return result;
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

GError*
gridcluster_reload_lbpool(struct grid_lbpool_s *glp)
{
	gboolean _reload_srvtype(const gchar *ns, const gchar *srvtype) {
		GError *err = NULL;
		GSList *list_srv = list_namespace_services2(ns, srvtype, &err);
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
	GSList *l, *list_srvtypes;

	list_srvtypes = list_namespace_service_types(grid_lbpool_namespace(glp), &err);
	if (err)
		g_prefix_error(&err, "LB pool reload error: ");
	else {
		guint errors = 0;
		const gchar *ns = grid_lbpool_namespace(glp);

		for (l=list_srvtypes; l ;l=l->next) {
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

gint64
gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo)
{
	/* For backward compatibility, versioning is disabled by default
	 */
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_max_versions", 0);
}

gint64
gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo)
{
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_keep_deleted_delay", -1);
}

