#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.get_ns_worker"
#endif

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>

#include "./agent.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./get_ns_worker.h"
#include "./namespace_get_task_worker.h"

int get_ns_worker(worker_t *worker, GError **error) {
	worker_data_t *data = &(worker->data);
	request_t *req = (request_t*)data->session;
	char *ns_and_vers = req->arg;
	char ns[LIMIT_LENGTH_NSNAME];
	memset(ns, 0, LIMIT_LENGTH_NSNAME);

	namespace_data_t *ns_data = NULL;
	GByteArray* gba = NULL;

	TRACE_POSITION();

	TRACE("Got request args : %s", ns_and_vers);

	if (!ns_and_vers || !*ns_and_vers)
		return __respond_message(worker, 0, "Invalid NAMESPACE name", error);

	char *version = strchr(ns_and_vers, ':');
	if (NULL != version) {
		strncpy(ns, ns_and_vers, version - ns_and_vers);
		version++; // skip ':'
	} else {
		g_strlcpy(ns, ns_and_vers, LIMIT_LENGTH_NSNAME);
	}

	GError *e = NULL;
	if (!(ns_data = get_namespace(ns, &e))) {
		return __respond_error(worker, e, error);
	}

	DEBUG("Namespace : name[%s] size[%"G_GINT64_FORMAT"]", ns_data->ns_info.name, ns_data->ns_info.chunk_size);

	/* marshall to ASN1 */
	if (!(gba = namespace_info_marshall(&(ns_data->ns_info), version, error))) {
		GSETERROR(error, "Marshalling error");
		return 0;
	}

	return __respond(worker, 1, gba, error);
}

