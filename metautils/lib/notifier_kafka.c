#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "notif.kafka"
#endif

#include <errno.h>
#include <glib.h>
#include <librdkafka/rdkafka.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/notifications.h>
#include <metautils/lib/notifier_kafka.h>

struct kafka_handle_s
{
	const gchar *ns;
	struct grid_lbpool_s *lb_pool;
	rd_kafka_t *kafka;
	GHashTable *kafka_topics; // GHashTable<char*,rd_kafka_topic_t*>
};

// --- Kafka specific --------------------------------------------------------
static GError *
_kafka_topic_ref(struct kafka_handle_s *handle, const gchar *name,
		rd_kafka_topic_conf_t *topic_conf, rd_kafka_topic_t **topic)
{
	rd_kafka_topic_t *new_topic = NULL;
	if (!handle->kafka) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"No kafka handle, events disabled?");
	}
	// Returns a reference if topic already exists
	new_topic = rd_kafka_topic_new(handle->kafka, name, topic_conf);
	if (!new_topic) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"Failed to initialize Kafka topic: %s", strerror(errno));
	}
	*topic = new_topic;
	return NULL;
}

static void
_kafka_topic_unref(struct kafka_handle_s *handle, rd_kafka_topic_t *utopic)
{
	(void) handle;
	// Decreases reference counter
	rd_kafka_topic_destroy(utopic);
}

static void
_kafka_clear_topic_cache(struct kafka_handle_s *handle)
{
	if (handle && handle->kafka_topics) {
		// Hash table was created with topic destroy callback
		g_hash_table_destroy(handle->kafka_topics);
		handle->kafka_topics = NULL;
	}
}

GError *
kafka_send(struct kafka_handle_s *handle, const gchar *topic_name,
		const guint32 *lb_key, GByteArray *data)
{
	int rc = 0;
	GError *err = NULL;
	rd_kafka_topic_t *topic = NULL;

	err = _kafka_topic_ref(handle, topic_name, NULL, &topic);
	if (!err) {
		const void *key;
		size_t key_len;
		if (lb_key != NULL) {
			key = (const void *)lb_key;
			key_len = sizeof(guint32);
		} else {
			key = NULL;
			key_len = 0;
		}
		rc = rd_kafka_produce(topic, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
				data->data, data->len, key, key_len, NULL);
		if (rc < 0) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Failed to send event to Kafka: (%d) %s",
					errno, rd_kafka_err2str(rd_kafka_errno2err(errno)));
		}
		_kafka_topic_unref(handle, topic);
	}
	return err;
}

GError *
_kafka_prepare_topic(struct kafka_handle_s *handle,
		 const gchar *topic_name)
{
	GError *err = NULL;
	rd_kafka_topic_t *topic = NULL;

	if (!handle || !handle->kafka || !handle->kafka_topics) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"Kafka notifications not configured!");
	}

	if (g_hash_table_lookup(handle->kafka_topics, topic_name)) {
		// Topic already initialized
		return NULL;
	}

	gint32 _partitioner(const rd_kafka_topic_t *rkt,
			const void *keydata, size_t keylen, gint32 partition_cnt,
			void *rkt_opaque, void *msg_opaque) {
		(void) rkt_opaque;
		(void) msg_opaque;

		guint32 part = 0;
		guint32 max_part = 1;

		// Zero partition? Write to partition 0
		// and hope it will be automatically created.
		if (partition_cnt == 0) {
			GRID_DEBUG("No already created partition for topic [%s], "
					"writing to [0]", rd_kafka_topic_name(rkt));
			return 0;
		}

		// Make sure the number of partitions is a power of two
		while (max_part <= (guint32)partition_cnt &&
				max_part <= MAX_TOPIC_PARTITIONS)
			max_part *= 2;
		max_part /= 2;

		switch (keylen) {
		default:
		// Unless MAX_TOPIC_PARTITIONS is greater than 65536,
		// the highest bytes are irrelevant
/*
		case 4:
			part |= ((gint8*)keydata)[3] << 24;
		case 3:
			part |= ((gint8*)keydata)[2] << 16;
*/
		case 2:
			part |= ((guint8*)keydata)[1] << 8;
		case 1:
			part |= ((guint8*)keydata)[0];
			break;
		case 0:
			part = 0;
			break;
		}
		if (GRID_TRACE_ENABLED()) {
			gchar tmp[16] = {0};
			buffer2str(keydata, keylen, tmp, sizeof(tmp));
			GRID_TRACE("Partition [%d] chosen for key [%s]",
					part % max_part, tmp);
		}
		return part % max_part;
	}

	// Prepare a topic configuration with a partitioner.
	// Because we are the first to ask for this topic, it will be
	// created with this configuration, and next callers can pass NULL.
	rd_kafka_topic_conf_t *topic_conf = rd_kafka_topic_conf_new();
	rd_kafka_topic_conf_set_partitioner_cb(topic_conf, _partitioner);
	err = _kafka_topic_ref(handle, topic_name, topic_conf, &topic);
	if (!err) {
		g_hash_table_insert(handle->kafka_topics, g_strdup(topic_name), topic);
	} else {
		rd_kafka_topic_conf_destroy(topic_conf);
	}
	return err;
}

static void
_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
	(void) fac;
	int redc_level = 1 << MAX(0, level-3);
	GRID_LOG(redc_level, "%s: %s", rk ? rd_kafka_name(rk) : "", buf);
}

void
kafka_free(struct kafka_handle_s *handle)
{
	if (handle) {
		if (handle->kafka) {
			// Set pointer to NULL so Kafka events are disabled immediately
			rd_kafka_t *k_handle = handle->kafka;
			handle->kafka = NULL;
			// Now clear handle
			_kafka_clear_topic_cache(handle);
			rd_kafka_destroy(k_handle);
		}
		g_free(handle);
	}
}

GError *
kafka_configure(const namespace_info_t *nsinfo, struct grid_lbpool_s *lb_pool,
		GSList *topics, struct kafka_handle_s **handle)
{
	(void) nsinfo;
	GError *err = NULL;
	gchar errmsg[256];
	service_info_t *svc = NULL;
	gchar broker[128] = {0};
	struct grid_lb_iterator_s *svc_it = NULL;
	struct kafka_handle_s * l_handle = *handle;

	g_assert(handle != NULL);

	if (l_handle == NULL)
		l_handle = g_malloc0(sizeof(struct kafka_handle_s));

	if (l_handle->kafka == NULL) {
		svc_it = grid_lbpool_get_iterator(lb_pool, "kafka");
		if (!grid_lb_iterator_next(svc_it, &svc)) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Failed to find a kafka broker");
			goto end;
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
		rd_kafka_set_logger(k_handle, _kafka_logger);

		if (!rd_kafka_brokers_add(k_handle, broker)) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Failed to configure kafka broker to %s", broker);
			rd_kafka_destroy(k_handle);
			goto end;
		}
		l_handle->kafka_topics = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, (GDestroyNotify)rd_kafka_topic_destroy);
		l_handle->kafka = k_handle;
	}

	for (GSList *cursor = topics; cursor != NULL; cursor = cursor->next) {
		err = _kafka_prepare_topic(l_handle, cursor->data);
		if (err) {
			GRID_WARN("Failed to prepare topic %s: %s",
					(gchar*)cursor->data, err->message);
			g_clear_error(&err);
		}
	}

end:
	service_info_clean(svc);
	if (err) {
		kafka_free(l_handle);
	} else {
		*handle = l_handle;
	}
	return err;
}


