#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.notif"
#endif

#include <errno.h>
#include <glib.h>
#include <librdkafka/rdkafka.h>

#include <metautils/lib/metautils.h>

#include <metautils/lib/notifications.h>

#define METAUTILS_NOTIFIER_JSON_TEMPLATE "{ \"timestamp\": %ld,\
 \"origin\": \"%s\",\
 \"type\": \"%s\",\
 \"seq\": %d,\
 \"data\": { %s } }"

struct metautils_notifier_s
{
	const gchar *ns;
	struct grid_lbpool_s *lb_pool;
	rd_kafka_t *kafka;
	GHashTable *kafka_topics; // GHashTable<char*,rd_kafka_topic_t*>
};

// Per service sequence number
static volatile gint _seq = 0;

// --- Kafka specific --------------------------------------------------------
static GError *
_kafka_topic_ref(metautils_notifier_t *handle, const gchar *name,
		rd_kafka_topic_t **topic)
{
	rd_kafka_topic_t *new_topic = NULL;
	if (!handle->kafka) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"No kafka handle, events disabled?");
	}
	// Returns a reference if topic already exists
	new_topic = rd_kafka_topic_new(handle->kafka, name, NULL);
	if (!new_topic) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"Failed to initialize Kafka topic: %s", strerror(errno));
	}
	*topic = new_topic;
	return NULL;
}

static void
_kafka_topic_unref(metautils_notifier_t *handle, rd_kafka_topic_t *utopic)
{
	(void) handle;
	// Decreases reference counter
	rd_kafka_topic_destroy(utopic);
}

static void
metautils_notifier_clear_kafka_topic_cache(metautils_notifier_t *handle)
{
	if (handle && handle->kafka_topics) {
		// Hash table was created with topic destroy callback
		g_hash_table_destroy(handle->kafka_topics);
		handle->kafka_topics = NULL;
	}
}

GError *
metautils_notifier_prepare_kafka_topic(metautils_notifier_t *notifier,
		 const gchar *topic_name)
{
	GError *err = NULL;
	rd_kafka_topic_t *topic = NULL;

	if (!notifier || !notifier->kafka || !notifier->kafka_topics) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"Kafka notifications not configured!");
	}

	err = _kafka_topic_ref(notifier, topic_name, &topic);
	if (!err) {
		g_hash_table_insert(notifier->kafka_topics, g_strdup(topic_name), topic);
	}
	return err;
}

GError *
metautils_notifier_init_kafka(metautils_notifier_t *handle)
{
	GError *err = NULL;
	gchar errmsg[256];
	service_info_t *svc = NULL;
	gchar broker[128] = {0};
	struct grid_lb_iterator_s *svc_it = NULL;

	// Already initialized
	if (handle->kafka != NULL)
		return NULL;

	svc_it = grid_lbpool_get_iterator(handle->lb_pool, "kafka");
	if (!grid_lb_iterator_next(svc_it, &svc)) {
		return NEWERROR(CODE_INTERNAL_ERROR, "Failed to find a kafka broker");
	}
	grid_addrinfo_to_string(&(svc->addr), broker, sizeof(broker));

	// TODO: customize configuration
	rd_kafka_t *k_handle = rd_kafka_new(RD_KAFKA_PRODUCER, NULL,
			errmsg, sizeof(errmsg));

	if (!k_handle) {
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"Failed to initialize Kafka: %s", errmsg);
		goto end;
	}
	rd_kafka_set_logger(k_handle, rd_kafka_log_syslog);

	if (!rd_kafka_brokers_add(k_handle, broker)) {
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"Failed to configure kafka broker to %s", broker);
		rd_kafka_destroy(k_handle);
		goto end;
	}
	handle->kafka_topics = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify)rd_kafka_topic_destroy);
	handle->kafka = k_handle;

end:
	service_info_clean(svc);
	return err;
}

void
metautils_notifier_free_kafka(metautils_notifier_t *handle)
{
	if (handle && handle->kafka) {
		// Set pointer to NULL so Kafka events are disabled immediately
		rd_kafka_t *k_handle = handle->kafka;
		handle->kafka = NULL;
		// Now clear handle
		metautils_notifier_clear_kafka_topic_cache(handle);
		rd_kafka_destroy(k_handle);
	}
}

static GError *
_send_notif_to_kafka(metautils_notifier_t *handle, const gchar *topic_name,
		GByteArray *data)
{
	int rc = 0;
	GError *err = NULL;
	rd_kafka_topic_t *topic = NULL;

	err = _kafka_topic_ref(handle, topic_name, &topic);
	if (!err) {
		rc = rd_kafka_produce(topic, 0, RD_KAFKA_MSG_F_COPY,
				data->data, data->len, NULL, 0, NULL);
		if (rc < 0) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Failed to send event to Kafka: (%d) %s",
					errno, rd_kafka_err2str(rd_kafka_errno2err(errno)));
		}
		_kafka_topic_unref(handle, topic);
	}
	return err;
}

// --- General ---------------------------------------------------------------
void
metautils_notifier_init(metautils_notifier_t **handle, const gchar *ns_name,
		struct grid_lbpool_s *lbpool)
{
	metautils_notifier_t *handle2 = NULL;

	g_assert(handle != NULL);

	handle2 = g_malloc0(sizeof(struct metautils_notifier_s));
	handle2->ns = g_strdup(ns_name);
	handle2->lb_pool = lbpool;

	if (*handle != NULL)
		metautils_notifier_clear(handle);

	*handle = handle2;
}

void
metautils_notifier_clear(metautils_notifier_t **handle)
{
	if (!handle || !*handle)
		return;
	metautils_notifier_t *handle2 = *handle;
	*handle = NULL;
	if (handle2->kafka)
		metautils_notifier_free_kafka(handle2);
	g_free((gpointer)handle2->ns);
	g_free(handle2);
}

GError *
metautils_notifier_send_raw(metautils_notifier_t *handle, const gchar *topic,
		GByteArray *data)
{
	GError *err = NULL;

	if (handle && handle->kafka) {
		err = _send_notif_to_kafka(handle, topic, data);
	} else {
		GRID_DEBUG("Notification not sent: no broker configured");
	}

	return err;
}

GError *
metautils_notifier_send_json(metautils_notifier_t *handle, const gchar *topic,
		const gchar *src_addr, const char *notif_type, const gchar *notif_data)
{
	GError *err = NULL;
	GString *event = g_string_sized_new(1024);
	GByteArray *event_gba = NULL;
#ifdef OLD_GLIB2
	gint seq = g_atomic_int_exchange_and_add(&_seq, 1);
#else
	gint seq = g_atomic_int_add(&_seq, 1);
#endif

	g_string_append_printf(event, METAUTILS_NOTIFIER_JSON_TEMPLATE,
			g_get_real_time() / 1000, // milliseconds since 1970
			src_addr,
			notif_type,
			seq,
			notif_data);

	event_gba = metautils_gba_from_string(event->str);
	err = metautils_notifier_send_raw(handle, topic, event_gba);

	metautils_gba_unref(event_gba);
	g_string_free(event, TRUE);

	return err;
}

