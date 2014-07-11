#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <metautils/lib/metacomm.h>

#include <cluster/module/module.h>
#include <cluster/conscience/conscience.h>

#include "./agent.h"
#include "./broken_workers.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

struct runner_data_s {
	GByteArray *packed;
	gint64 counter;
};

static gboolean
broken_meta1_runner( gpointer u, struct broken_meta1_s *bm1 )
{
	struct runner_data_s *data;

	TRACE_POSITION();

	data = u;
	if (bm1) {
		gchar *str = broken_holder_write_meta1( bm1 );
		if (str) {
			g_byte_array_append( data->packed, (guint8*)str, strlen(str));
			g_byte_array_append( data->packed, (guint8*)"", 1);
			g_free(str);
			data->counter ++;
		}
	}
	return TRUE;
}

static gboolean
broken_content_runner(gpointer u, struct broken_meta2_s *bm2, struct broken_content_s *bc)
{
	gchar *str;
	struct runner_data_s *data;

	TRACE_POSITION();
	if (bm2) {
		str = bc ? broken_holder_write_content(bm2,bc) : broken_holder_write_meta2(bm2);
		data = u;
		if (str) {
			g_byte_array_append( data->packed, (guint8*)str, strlen(str)+1);
			g_free(str);
			data->counter ++;
		}
	}
	return TRUE;
}

int
agent_fetch_broken_all_elements(worker_t *worker, GError **error)
{
	GError *error_local = NULL;
	struct runner_data_s data;
	request_t *req = NULL;
	namespace_data_t *ns_data = NULL;
	gchar ns_name[LIMIT_LENGTH_NSNAME];

	TRACE_POSITION();
	memset(&data, 0x00, sizeof(data));

	/*extract the namespace nae in request and find respective ns_data*/
	req = (request_t*)worker->data.session;
	if (!req->arg) {
		GSETERROR(&error_local,"Invalid request");
		return 0;
	}

	memset(ns_name, 0x00, sizeof(ns_name));
	memcpy(ns_name, req->arg, MIN(sizeof(ns_name),req->arg_size));
	ns_name[sizeof(ns_name)-1] = '\0';
	if (strchr(ns_name,' '))
		*strchr(ns_name,' ') = '\0';

	ns_data = get_namespace(ns_name, error);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	/*reply the broken elements from the conscience*/
	data.counter = 0;
	data.packed = g_byte_array_new();
	broken_holder_run_elements( ns_data->conscience->broken_elements, 0, &data, broken_meta1_runner, broken_content_runner);
	DEBUG("BROKEN containers/contents of %s listed! nb=%"G_GINT64_FORMAT" buffer=%d", ns_name, data.counter, data.packed->len);

	return __respond(worker, 1, data.packed, error);
}

