#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.evt"
#endif

#include <errno.h>

#include "metautils.h"

struct event_config_s {
	gboolean enabled;
	gboolean kafka_enabled;
	GMutex *lock;
	gint64 seq;
	gchar *dir;
	gboolean aggregate;
	time_t last_error;
	time_t delay_on_error;
	gchar *kafka_topic;
};

struct event_config_repo_s {
	GStaticRWLock rwlock;
	GHashTable *evt_config; /* <gchar*, struct event_config_s*> */
	metautils_notifier_t *notifier;
};

static GQuark gquark_log = 0;

/* ------------------------------------------------------------------------- */

struct event_config_s *
event_config_create(void)
{
	struct event_config_s *result;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	result = g_malloc0(sizeof(*result));
	result->enabled = FALSE;
	result->lock = g_mutex_new();
	result->seq = 0;
	result->dir = g_strdup("/GRID/common/spool");
	result->aggregate = FALSE;
	result->last_error = 0;
	result->delay_on_error = 0;

	return result;
}

void
event_config_destroy(struct event_config_s *evt_config)
{
	GMutex *lock = NULL;

	if (!evt_config)
		return;

	if (evt_config->lock) {
		lock = evt_config->lock;
		evt_config->lock = NULL;
	}

	if (lock)
		g_mutex_lock(lock);

	if (evt_config->dir)
		g_free(evt_config->dir);

	if (lock) {
		g_mutex_unlock(lock);
		g_mutex_free(lock);
	}

	g_free(evt_config);
}

gchar *
event_config_dump(struct event_config_s *evt_config)
{
	GString *out = g_string_new("event_config={");

	g_mutex_lock(evt_config->lock);
	g_string_append_printf(out,"enabled=%s; kafka_enabled=%s; dir=%s; aggr=%s,"
			" seq=%"G_GINT64_FORMAT,
			evt_config->enabled ? "yes":"no",
			evt_config->kafka_enabled ? "yes":"no",
			evt_config->dir,
			evt_config->aggregate ? "yes":"no",
			evt_config->seq);
	g_mutex_unlock(evt_config->lock);

	out = g_string_append(out, "}");

	return g_string_free(out, FALSE);
}

/* ------------------------------------------------------------------------- */

GError*
event_config_reconfigure(struct event_config_s *evt_config,
		const gchar *cfg)
{
	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	gchar **tok = g_strsplit(cfg, ";", 0);
	g_mutex_lock(evt_config->lock);

	for(guint i = 0; i < g_strv_length(tok); i++) {
		char *val = NULL;
		if (!tok[i] || 0 == strlen(tok[i]) || !(val = strchr(tok[i],'='))) {
			continue;
		}
		val++;
		GRID_DEBUG("Reconfiguration, key=%.*s, val=%s",
				(int)(val - tok[i]), tok[i], val);
		if(0 == g_ascii_strncasecmp(tok[i], "enabled", 7)) {
			evt_config->enabled = metautils_cfg_get_bool(val, FALSE);
		} else if (0 == g_ascii_strncasecmp(tok[i], "kafka_enabled", 13)) {
			evt_config->kafka_enabled = metautils_cfg_get_bool(val, FALSE);
		} else if (0 == g_ascii_strncasecmp(tok[i], "kafka_topic", 11)) {
			if (evt_config->kafka_topic)
				g_free(evt_config->kafka_topic);
			evt_config->kafka_topic = g_strdup(val);
		} else if(0 == g_ascii_strncasecmp(tok[i], "dir", 3)) {
			if (evt_config->dir)
				g_free(evt_config->dir);
			evt_config->dir = g_strdup(val);
		} else if(0 == g_ascii_strncasecmp(tok[i], "aggregate", 9)) {
			evt_config->aggregate = metautils_cfg_get_bool(val, FALSE);
		}
	}

	g_strfreev(tok);

	g_mutex_unlock(evt_config->lock);

	return NULL;
}

gboolean
event_is_enabled(struct event_config_s *evt_config)
{
	return (!evt_config) ? FALSE : evt_config->enabled;
}

gboolean
event_is_notifier_enabled(struct event_config_s *evt_config)
{
	return (!evt_config) ? FALSE : evt_config->kafka_enabled;
}

const gchar *
event_get_notifier_topic_name(struct event_config_s *evt_config, const gchar *def)
{
	if (!evt_config || !evt_config->kafka_topic) {
		return def;
	} else {
		return evt_config->kafka_topic;
	}
}

gboolean
event_is_aggregate(struct event_config_s *evt_config)
{
	return(!evt_config) ? FALSE : evt_config->aggregate;
}

const gchar*
event_get_dir(struct event_config_s *evt_config)
{
	return (!evt_config) ? NULL : evt_config->dir;
}

gint64
event_get_and_inc_seq(struct event_config_s *evt_config)
{
	return (!evt_config) ? 0 : evt_config->seq ++;
}

GMutex *
event_get_lock(struct event_config_s *evt_config)
{
	return (!evt_config) ? NULL : evt_config->lock;
}

struct event_config_repo_s *
event_config_repo_create(const gchar *ns_name, struct grid_lbpool_s *lbpool)
{
	struct event_config_repo_s *conf = NULL;
	conf = g_malloc0(sizeof(struct event_config_repo_s));
	conf->evt_config = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) event_config_destroy);
	g_static_rw_lock_init(&(conf->rwlock));
	metautils_notifier_init(&(conf->notifier), ns_name, lbpool);

	return conf;
}

void
event_config_repo_clear(struct event_config_repo_s **repo)
{
	if (!repo || !*repo)
		return;
	struct event_config_repo_s *repo2 = *repo;
	*repo = NULL;
	metautils_notifier_clear(&(repo2->notifier));
	if (repo2->evt_config) {
		g_hash_table_destroy(repo2->evt_config);
	}
	g_static_rw_lock_free(&(repo2->rwlock));
	memset(repo2, 0, sizeof(struct event_config_repo_s));
	g_free(repo2);
}

metautils_notifier_t *
event_config_repo_get_notifier(struct event_config_repo_s *repo)
{
	return repo->notifier;
}

struct event_config_s*
event_config_repo_get(struct event_config_repo_s *conf,
	const char *ns_name, gboolean vns_fallback)
{
	struct event_config_s *event = NULL;
	if (conf != NULL) {
		g_static_rw_lock_writer_lock(&conf->rwlock);
		if (vns_fallback)
			event = namespace_hash_table_lookup(conf->evt_config, ns_name, NULL);
		else
			event = g_hash_table_lookup(conf->evt_config, ns_name);
		if (!event) {
			GRID_DEBUG("Event config not found for %s, creating one", ns_name);
			event = event_config_create();
			g_hash_table_insert(conf->evt_config, g_strdup(ns_name), event);
		}
		g_static_rw_lock_writer_unlock(&conf->rwlock);
	}
	return event;
}

