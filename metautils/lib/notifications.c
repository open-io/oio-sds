/*
OpenIO SDS metautils
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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.notif"
#endif

#include <errno.h>
#include <glib.h>

#include <metautils/lib/metautils.h>

#include <metautils/lib/notifications.h>

#ifdef RD_KAFKA_ENABLED
 #include <metautils/lib/notifier_kafka.h>
#endif

#define METAUTILS_NOTIFIER_JSON_TEMPLATE "{\"timestamp\":%ld,\
\"origin\":\"%s\",\
\"type\":\"%s\",\
\"seq\":%d,\
\"data\":{%s}}"

struct metautils_notif_pool_s
{
	const gchar *ns;
	struct grid_lbpool_s *lb_pool;
	GSList *notifiers; // GSList<struct notifier_s*>
};

// Per service sequence number
static volatile gint _seq = 0;

// --- General ---------------------------------------------------------------
void
metautils_notif_pool_init(metautils_notif_pool_t **pool, const gchar *ns_name,
		struct grid_lbpool_s *lbpool)
{
	metautils_notif_pool_t *pool2 = NULL;

	g_assert(pool != NULL);

	pool2 = g_malloc0(sizeof(struct metautils_notif_pool_s));
	pool2->ns = g_strdup(ns_name);
	pool2->lb_pool = lbpool;

	if (*pool != NULL)
		metautils_notif_pool_clear(pool);

	*pool = pool2;
}

static void
_notifier_clear(struct notifier_s *notifier)
{
	notifier->free(notifier->handle);
	g_free((gpointer)notifier->type);
	memset(notifier, 0, sizeof(struct notifier_s));
	g_free(notifier);
	// TODO: unload notifier module
}


static GError *
_notifier_load(metautils_notif_pool_t *pool, const gchar *type,
		struct notifier_s **out)
{
	(void) pool, (void) out;
	GError *err = NULL;

#ifdef RD_KAFKA_ENABLED
	if (!g_strcmp0(type, "kafka")) {
		// TODO: load notifier from module
		struct notifier_s *notifier = g_malloc0(sizeof(struct notifier_s));
		notifier->type = g_strdup(type);
		notifier->configure = (notifier_configure) kafka_configure;
		notifier->send = (notifier_send) kafka_send;
		notifier->free = (notifier_free) kafka_free;
		*out = notifier;
		GRID_INFO("Notifier %s created", notifier->type);
	} else
#endif
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"Unknown notifier type: %s", type);

	return err;
}

void
metautils_notif_pool_clear(metautils_notif_pool_t **pool)
{
	if (!pool || !*pool)
		return;
	metautils_notif_pool_t *pool2 = *pool;
	*pool = NULL;
	for (GSList *cur = pool2->notifiers; cur; cur = cur->next) {
		_notifier_clear(cur->data);
	}
	g_free((gpointer)pool2->ns);
	g_free(pool2);
}

GError *
metautils_notif_pool_configure_type(metautils_notif_pool_t *pool,
		namespace_info_t *nsinfo, const gchar *type, GSList *topics)
{
	GError *err = NULL;
	struct notifier_s *notifier = NULL;

	for (GSList *cur = pool->notifiers; cur; cur = cur->next) {
		struct notifier_s *not = cur->data;
		if (!g_strcmp0(type, not->type)) {
			notifier = not;
			break;
		}
	}

	if (!notifier) {
		err = _notifier_load(pool, type, &notifier);
		if (!err)
			pool->notifiers = g_slist_prepend(pool->notifiers, notifier);
	}

	if (!err) {
		err = notifier->configure(nsinfo, pool->lb_pool, topics,
				&(notifier->handle));
	}

	return err;
}

void
metautils_notif_pool_clear_type(metautils_notif_pool_t *notif_pool,
		const gchar *type)
{
	struct notifier_s *notifier = NULL;
	for (GSList *cur = notif_pool->notifiers; cur; cur = cur->next) {
		struct notifier_s *not = cur->data;
		if (!g_strcmp0(type, not->type)) {
			notifier = not;
			break;
		}
	}
	if (notifier) {
		GRID_INFO("Cleaning notifier %s", notifier->type);
		notif_pool->notifiers = g_slist_remove(notif_pool->notifiers, notifier);
		_notifier_clear(notifier);
	}
}

GError *
metautils_notif_pool_send_raw(metautils_notif_pool_t *pool, const gchar *topic,
		GByteArray *data, const guint32 *lb_key)
{
	GError *err = NULL;

	for (GSList *cursor = pool->notifiers; cursor; cursor = cursor->next) {
		GError *err2 = NULL;
		struct notifier_s *notif = cursor->data;
		if (GRID_TRACE_ENABLED())
			GRID_TRACE("Sending notification to %s, topic %s",
					notif->type, topic);
		err2 = notif->send(notif->handle, topic, lb_key, data);
		if (err2) {
			GRID_WARN("Notifier %s failed to send notification to topic %s: %s",
					notif->type, topic, err2->message);
			if (!err) {
				err = err2;
			} else {
				g_clear_error(&err2);
			}
		}
	}

	return err;
}

GError *
metautils_notif_pool_send_json(metautils_notif_pool_t *pool, const gchar *topic,
		const gchar *src_addr, const char *notif_type, const gchar *notif_data,
		const guint32 *lb_key)
{
	GError *err = NULL;
	GString *event = g_string_sized_new(1024);
	GByteArray *event_gba = NULL;

	// No notifier, return directly
	if (!pool->notifiers)
		return NULL;

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
	err = metautils_notif_pool_send_raw(pool, topic, event_gba, lb_key);

	metautils_gba_unref(event_gba);
	g_string_free(event, TRUE);

	return err;
}

