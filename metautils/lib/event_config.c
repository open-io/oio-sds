#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.evt"
#endif

#include <errno.h>

#include "metautils.h"

struct event_config_s {
	gboolean enabled;
	GMutex *lock;
	gint64 seq;
	gchar *dir;
	gboolean aggregate;
	time_t last_error;
	time_t delay_on_error;
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
	g_string_append_printf(out,"enabled=%s; dir=%s; aggr=%s,"
			" seq=%"G_GINT64_FORMAT,
			evt_config->enabled ? "yes":"no", evt_config->dir,
			evt_config->aggregate ? "yes":"no", evt_config->seq);
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
		} else if(0 == g_ascii_strncasecmp(tok[i], "dir", 3)) {
			if(evt_config->dir)
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
