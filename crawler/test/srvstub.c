#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.test.service.stub"
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>




#include "../../metautils/lib/metautils.h"

#include "../../meta2v2/generic.h"
#include "../../meta2v2/meta2_bean.h"

#include "../../server/grid_daemon.h"
#include "../../server/gridd_dispatcher_filters.h"
#include "../../server/transport_gridd.h"
#include "../../server/network_server.h"

#include "srvstub.h"


static GError* g_err          = NULL;

static void*   g_responsedata = NULL;
static char*   g_module_name  = NULL;

#define SRVSTUB_PRINTF(...) /*fprintf(stdout, __VA_ARGS__);*/



//------------------------------------------------------------------------------

int meta2_filter_action_purge_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	SRVSTUB_PRINTF("packet received...PURGE");

	// M2V2_MODE_DRYRUN, ...
	guint32 flags = 0;
	const char *fstr = NULL;
	if (NULL != fstr)
		flags = (guint32) g_ascii_strtoull(fstr, NULL, 10);

	GSList* del_chunks_list = NULL;

	if (NULL != g_err) {
		GRID_DEBUG("Container purge failed (%d) : %s", g_err->code, g_err->message);
		//meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}


	reply->add_body(bean_sequence_marshall(g_responsedata));
	reply->send_reply(200, "OK");
	_bean_cleanl2(del_chunks_list);
	return FILTER_OK;
}

	int
meta2_filter_action_deduplicate_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList* result = NULL;   // list of list
	GSList* common_prefixes = NULL;

	SRVSTUB_PRINTF("packet received...DEDUP");

	void send_result()
	{
		GSList *list_of_lists = NULL;
		list_of_lists = gslist_split(result, 32);
		for (GSList *cursor = list_of_lists; cursor; cursor = cursor->next) {
			reply->add_body(bean_sequence_marshall(cursor->data));
			reply->send_reply(206, "Partial content");
		}
		if (NULL != common_prefixes) {
			char **array = (char **)metautils_list_to_array(common_prefixes);
			reply->add_header("COMMON_PREFIXES", metautils_encode_lines(array));
			g_strfreev(array);
		}

		/* TODO : max-keys, truncated */

		reply->send_reply(200, "OK");

		gslist_chunks_destroy(list_of_lists, NULL);
	}


	send_result();

	return FILTER_OK;
}


//------------------------------------------------------------------------------
//
static gboolean meta2_dispatch_all(struct gridd_reply_ctx_s *reply, gpointer gdata, gpointer hdata)
{
	gridd_filter *fl;
	struct gridd_filter_ctx_s *ctx;
	guint loop;

	fl = (gridd_filter*)hdata;

	SRVSTUB_PRINTF("packet received...");

	if (!fl) {
		GRID_INFO("No filter defined for this request, consider not yet implemented");
		reply->send_reply(501, "NOT IMPLEMENTED");
	}
	else {
		for (loop=1; loop && *fl; fl++) {
			switch ((*fl)(ctx, reply)) {
				case FILTER_OK:
					break;
				case FILTER_KO:
					reply->send_error(0, g_err);
					loop = 0;
					break;
				case FILTER_DONE:
					loop = 0;
					break;
				default:
					reply->send_error(0, g_err);
					loop = 0;
					break;
			}
		}
	}

	return TRUE;
}

static gboolean meta2_dispatch_ok(struct gridd_reply_ctx_s *reply, gpointer gdata, gpointer hdata)
{
	SRVSTUB_PRINTF("packet received...Send OK without data");
	reply->send_reply(200, "OK");
	return TRUE;
}


static gboolean meta2_dispatch_error(struct gridd_reply_ctx_s *reply, gpointer gdata, gpointer hdata)
{
	GError* error = NULL;
	error = NEWERROR(-1, "error from stub srv");
	SRVSTUB_PRINTF("packet received...Send ERROR");
	reply->send_error(0, error);
	return TRUE;
}

static gboolean meta2_dispatch_none(struct gridd_reply_ctx_s *reply, gpointer gdata, gpointer hdata)
{
    return TRUE;
}



//------------------------------------------------------------------------------
//
static gridd_filter M2V2_PURGE_FILTERS[] = { meta2_filter_action_purge_container,       NULL };
static gridd_filter M2V2_DEDUP_FILTERS[] = { meta2_filter_action_deduplicate_container, NULL };




typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);
const struct gridd_request_descr_s *_get_requests(ESrvStubCmd sscmd, char* name)
{
	int i=0;
	/* one-shot features */
	static struct gridd_request_descr_s descriptions[] = {
		/* containers */
		{"M2V2_PURGE",     (hook) meta2_dispatch_all, M2V2_PURGE_FILTERS},
		{"M2V2_DEDUP",     (hook) meta2_dispatch_all, M2V2_DEDUP_FILTERS},

		{"M1V2_SRVALLONM1",   (hook) meta2_dispatch_all, NULL},
		{"M1V2_LISTBYPREFIX", (hook) meta2_dispatch_all, NULL},
		{"M1V2_LISTBYSERV",   (hook) meta2_dispatch_all, NULL},

		{NULL, NULL, NULL}  
	};

	if (!name) {
		if (sscmd == SSCMD_ONE_ERR_WITHOUTDATA) {			
			GRID_WARN("srvstub, %s: name == NULL: SSCMD_ONE_ERR_WITHOUTDATA --> SSCMD_ALL_ERR_WITHOUTDATA", __FUNCTION__);
			sscmd = SSCMD_ALL_ERR_WITHOUTDATA;
		}
	}

	if (sscmd == SSCMD_ALL_OK)
		 return descriptions;

	while (descriptions[i].name ) {	
		descriptions[i].handler_data = NULL;
		switch(sscmd) {
		case SSCMD_ALL_OK: 	break;
		case SSCMD_ALL_NONE:
				descriptions[i].handler      = meta2_dispatch_none;
				descriptions[i].handler_data = NULL;
				break;

		case SSCMD_ALL_OK_WITHOUTDATA:  
				descriptions[i].handler      = meta2_dispatch_ok;
				descriptions[i].handler_data = NULL;
				break;

		case SSCMD_ALL_ERR_WITHOUTDATA:
				descriptions[i].handler      = meta2_dispatch_error;
				descriptions[i].handler_data = NULL;
				break;

		case SSCMD_ONE_ERR_WITHOUTDATA:
				if (g_strcmp0(descriptions[i].name, name)) {
					descriptions[i].handler      = meta2_dispatch_error;
					descriptions[i].handler_data = NULL;
					break;
				}
		}i;
		i++;
	}

	return descriptions;
}




//------------------------------------------------------------------------------
//

struct SSrvStubHandle {
	struct network_server_s *          server;	
	guint                              max_connections;
	struct gridd_request_dispatcher_s *dispatcher;
};


/**
 * responsedata: M2V2_PURGE: --> GSList*
 *
 */
TSrvStubHandle* srvstub_init(char* url, ESrvStubCmd sscmd, char* name, void* responsedata)
{
	GError* err = NULL;
	struct SSrvStubHandle* s = g_malloc0(sizeof(struct SSrvStubHandle));

	memset(s, 0, sizeof(struct SSrvStubHandle));
	s->max_connections = 5;

	g_module_name  = NULL;
	g_responsedata = NULL;

	/* Configures the NETWORK management */
	if (!(s->server = network_server_init())) {
		GRID_WARN("SERVER init failure : (%d) %s", errno, strerror(errno));
		return NULL;
	}
	if (s->max_connections)
		network_server_set_maxcnx(s->server, s->max_connections);

	s->dispatcher = transport_gridd_build_empty_dispatcher();
	transport_gridd_dispatcher_add_requests(s->dispatcher, _get_requests(sscmd, name) , NULL);
	grid_daemon_bind_host(s->server, url, s->dispatcher);

	if (NULL != (err = network_server_open_servers(s->server))) {
		GRID_WARN("Failed to start some server sockets : (%d) %s",
				err->code, err->message);
		srvstub_close(&s);
		g_clear_error(&err);
		return NULL;
	}

    g_module_name  = name;
    g_responsedata = responsedata;

	return s;
}


GError* srvstub_run(TSrvStubHandle* s)
{
	GError* err= NULL;
	if (NULL != (err = network_server_run(s->server))) {
		GRID_WARN("GRIDD run failure : code=%d message=%s", err->code, err->message);
		return err;
	}

	return NULL;
}


int srvstub_close(TSrvStubHandle** s)
{
	TSrvStubHandle* ss = *s;

	if (!ss)
		return 0;

	if (ss->server) {
		network_server_stop(ss->server);
		network_server_close_servers(ss->server);
	}

	if (ss->dispatcher)
		gridd_request_dispatcher_clean(ss->dispatcher);

	ss = NULL;

	return 0;
}

