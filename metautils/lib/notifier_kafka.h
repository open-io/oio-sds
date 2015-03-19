#ifndef __REDCURRANT__metautils_notifier_kafka__h
# define __REDCURRANT__metautils_notifier_kafka__h 1

#include <glib.h>
#include <metautils/lib/metautils.h>

// Kafka docs says that 10000 partitions is huge but should work
#define MAX_TOPIC_PARTITIONS 16384


struct kafka_handle_s;

/** Configuration function for Kafka notifier.
 * Compatible with typedef notifier_configure. */
GError *kafka_configure(const namespace_info_t *nsinfo,
		struct grid_lbpool_s *lb_pool, GSList *topics,
		struct kafka_handle_s **handle);

/** Sending function for Kafka notifier.
 * Compatible with typedef notifier_send. */
GError *kafka_send(struct kafka_handle_s *handle, const gchar *topic_name,
		const guint32 *lb_key, GByteArray *data);

/** Free function for Kafka notifier.
 * Compatible with typedef notifier_free. */
void kafka_free(struct kafka_handle_s *handle);

#endif
