#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.event.receive"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/events/gridcluster_events.h>
#include <cluster/events/gridcluster_eventsremote.h>
#include <cluster/events/gridcluster_eventhandler.h>
#include <cluster/conscience/conscience.h>

#include "./config.h"
#include "./agent.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

#define TASK_ID "incoming_events"

/* ------------------------------------------------------------------------- */

/**
 * Generates a new UEID and fills the ueid fields of the structure pointed by
 * param
 */
static gchar *
ueid_generate(void)
{
	struct timeval tv;
	static gchar hostname[256] = {0,0};
	static guint64 event_counter = 0LLU;

	if (!*hostname) {
		bzero(hostname, sizeof(hostname));
		gethostname(hostname,sizeof(hostname)-1);
	}

	gettimeofday(&tv, NULL);
	return g_strdup_printf("%s_%lu_%lu_%d_%"G_GUINT64_FORMAT,
		hostname, tv.tv_sec, tv.tv_usec, getpid(), event_counter++);
}

/**
 * Get the UEID from the encoded event (or generate a new UEID if not present),
 * and return the decoded event
 */
static gchar *
ueid_get_from_event(gridcluster_event_t *decoded_event)
{
	GByteArray *gba;

	/* Decode and check there is an UEID in the event */
	if (!(gba = g_hash_table_lookup(decoded_event, "UEID"))) {
		gchar *result = ueid_generate();
		gridcluster_event_add_string(decoded_event, "UEID", result);
		return result;
	}

	return g_strndup((gchar*)gba->data, gba->len);
}

static gchar*
path_get_from_event_aggrname(gridcluster_event_t *decoded_event, const gchar *basedir)
{
	gchar c, *s, aggr_name[1024];
	GByteArray *gba;

	bzero(aggr_name, sizeof(aggr_name));

	/* Decode and check there is an UEID in the event */
	if (!(gba = g_hash_table_lookup(decoded_event, GRIDCLUSTER_EVTFIELD_AGGRNAME))) {
		gchar *ueid = ueid_get_from_event(decoded_event);
		g_strlcpy(aggr_name, ueid, sizeof(aggr_name)-1);
		g_free(ueid);
	}
	else 
		g_memmove(aggr_name, gba->data, MIN(gba->len, sizeof(aggr_name)-1));

	/* Cannonify the aggr_name*/
	for (s=aggr_name; '\0'!=(c=*s) ;s++) {
		if (!g_ascii_isprint(c) || g_ascii_isspace(c) || c==G_DIR_SEPARATOR || c=='.')
			*s = '_';
	}

	/* Replace the aggregation name with its canonized form */
	gridcluster_event_add_string(decoded_event, GRIDCLUSTER_EVTFIELD_AGGRNAME, aggr_name);
	return g_strdup_printf("%s%c%s", basedir, G_DIR_SEPARATOR, aggr_name);
}

static int
event_set_timestamp(const gchar *path, time_t when)
{
	gchar str[128];
	gsize str_len;

	str_len = g_snprintf(str, sizeof(str), "%ld", when);
	return 0 == setxattr(path, xattr_event_timestamp, str, str_len, 0);
}

static time_t
event_get_timestamp(const gchar *path, struct stat *s0)
{
	time_t t;
	gint64 i64;
	gchar str[128];
	struct stat s;

	if (0 != getxattr(path, xattr_event_timestamp, str, sizeof(str))) {
		if (errno == ENOENT)
			return 0;
		if (s0)
			return s0->st_mtime;
		return (0 == stat(path, &s)) ? s.st_mtime : 0;
	}

	i64 = g_ascii_strtoll(str, NULL, 10);
	return (t = i64);
}

/* ------------------------------------------------------------------------- */

static gboolean
save_event(struct namespace_data_s *ns_data, gridcluster_event_t *e, GError **error)
{
	time_t old_timestamp = 0L;
	gchar *path, *ueid;
	gboolean rc;
	GByteArray *encoded = NULL;

	encoded = gridcluster_encode_event(e, error);
	if (!encoded) {
		GSETERROR(error, "Serialisation error");
		return FALSE;
	}
	
	if (0 != g_mkdir_with_parents(ns_data->queues.dir_incoming, event_directory_mode)) {
		GSETERROR(error, "mkdir(%s) error", ns_data->queues.dir_incoming);
		g_byte_array_free(encoded, TRUE);
		return FALSE;
	}

	path = path_get_from_event_aggrname(e, ns_data->queues.dir_incoming);
	ueid = ueid_get_from_event(e);

	/* get the previous timestamp and unlink the previous file */
	old_timestamp = event_get_timestamp(path, NULL);
	if (0 == unlink(path))
		DEBUG("Unlinked a previous event at [%s]", path);

	if (!(rc = g_file_set_contents(path, (gchar*)encoded->data, encoded->len, error)))
		GSETERROR(error,"Failed to write the serialized event UEID[%s] at [%s]", ueid, path);
	else {
		gboolean xattr_rc;

		xattr_rc = event_set_timestamp(path, old_timestamp ? old_timestamp : time(0));
		g_chmod(path, event_file_mode);

		INFO("Incoming event UEID[%s] saved at [%s] (%s : %s)", ueid, path,
			(xattr_rc ? "xattr timestamp set" : "xattr timestamp not set"),
			strerror(errno));
	}

	g_byte_array_free(encoded, TRUE);
	g_free(path);
	g_free(ueid);
	return rc;
	
}

static gboolean
save_event_bytes(struct namespace_data_s *ns_data, const guint8 *buf, gsize buf_size, GError **error)
{
	gridcluster_event_t *decoded_event;

	decoded_event = gridcluster_decode_event2(buf, buf_size, error);
	if (!decoded_event) {
		GSETERROR(error, "Failed to decode the event");
		return FALSE;
	}

	if (!save_event(ns_data, decoded_event, error)) {
		g_hash_table_destroy(decoded_event);
		GSETERROR(error, "Event cannot be saved");
		return FALSE;
	}

	g_hash_table_destroy(decoded_event);
	return TRUE;
}

int
agent_receive_event_worker(worker_t *worker, GError **error)
{
	GError *error_local;
	worker_data_t *data;
	request_t *req;
	gchar ns_name[LIMIT_LENGTH_NSNAME+1];

	struct namespace_data_s *ns_data;
	const char *encoded_event;
	gsize ns_name_len, encoded_event_size;

	TRACE_POSITION();
	memset(ns_name, 0x00, sizeof(ns_name));
	ns_name_len = encoded_event_size = 0;
	error_local = NULL;
	data = &(worker->data);
	req = (request_t*)data->session;

	/* Unpack the NAMESPACE name and the EVENT serialized form:
	 * format: NAMESPACE\e00<BUFFER>*/
	g_memmove(ns_name, req->arg, MIN(sizeof(ns_name)-1,req->arg_size));
	ns_name_len = strlen(ns_name);
	encoded_event = req->arg + (ns_name_len+1);
	encoded_event_size = req->arg_size - (ns_name_len+1);

	/* Check namespace */
	if (!*ns_name)
		return __respond_message(worker, 0, "Invalid format", error);

	DEBUG("[ns=%s] Received an event of %"G_GSIZE_FORMAT" bytes (from %d)", ns_name, encoded_event_size, req->arg_size);

	if (!(ns_data = g_hash_table_lookup(namespaces, ns_name)))
		return __respond_message(worker, 0, "Unknown namespace '%s'", error);
	if (!event_enable_receive)
		return __respond_message(worker, 0, "Events not managed on this host", error);

	if (!save_event_bytes(ns_data, (guint8*)encoded_event, encoded_event_size, &error_local))
		return __respond_error(worker, error_local, error);
	
	return __respond_message(worker, 1, "OK, event saved", error);
}

