#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "sqlite_service_extras"
#endif

#include <errno.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <sqlx/sqlx_service.h>
#include <sqlx/sqlx_service_extras.h>

GError *
sqlx_service_extras_init(struct sqlx_service_s *ss)
{
	GError *err = NULL;

	if (ss->extras != NULL)
		return NEWERROR(CODE_INTERNAL_ERROR,
				"sqlx_service_extras already initialized");

	ss->extras = g_malloc0(sizeof(struct sqlx_service_s));

	ss->extras->lb = grid_lbpool_create(ss->ns_name);
	if (!ss->extras->lb) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "LB pool init failure");
		goto end;
	}

	ss->extras->evt_repo = event_config_repo_create(ss->ns_name,
			ss->extras->lb);
	if (!ss->extras->evt_repo) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "Event config repo init failure");
	}

end:
	if (err) {
		grid_lbpool_destroy(ss->extras->lb);
		g_free(ss->extras);
		ss->extras = NULL;
	}
	return err;
}

void
sqlx_service_extras_clear(struct sqlx_service_s *ss)
{
	if (!ss || !ss->extras)
		return;

	event_config_repo_clear(&(ss->extras->evt_repo));
	grid_lbpool_destroy(ss->extras->lb);
	ss->extras->lb = NULL;
	g_free(ss->extras);
	ss->extras = NULL;
}

void
sqlx_task_reload_lb(struct sqlx_service_s *ss)
{
	GError *err;

	EXTRA_ASSERT(ss != NULL);

	if (!ss->extras || !ss->extras->lb)
		return;

	if (NULL != (err = gridcluster_reload_lbpool(ss->extras->lb))) {
		GRID_WARN("Failed to reload the LB pool services: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}

	if (NULL != (err = gridcluster_reconfigure_lbpool(ss->extras->lb))) {
		GRID_WARN("Failed to reload the LB pool configuration: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

static GError*
_init_events(metautils_notifier_t *notifier, const gchar *topic)
{
	GError *err = NULL;
	err = metautils_notifier_init_kafka(notifier);
	if (!err) {
		err = metautils_notifier_prepare_kafka_topic(notifier, topic);
	}
	return err;
}

void
sqlx_task_reload_event_config(struct sqlx_service_s *ss)
{
	GError *err = NULL;
	gboolean must_clear_events = TRUE;
	GHashTable *ht = NULL;
	metautils_notifier_t *notifier = NULL;

	EXTRA_ASSERT(ss != NULL);

	if (!ss->extras || !ss->extras->evt_repo)
		return;

	void _update_each(gpointer k, gpointer v, gpointer ignored) {
		(void) ignored;
		if (!err) {
			struct event_config_s *conf = event_config_repo_get(
					ss->extras->evt_repo, (char *)k, FALSE);
			err = event_config_reconfigure(conf, (char *)v);
			if (!err && event_is_notifier_enabled(conf)) {
				must_clear_events = FALSE;
				err = _init_events(notifier,
						event_get_notifier_topic_name(conf, "redc"));
				if (err) {
					GRID_WARN("Failed to initialize notifications (will retry soon): %s",
							err->message);
					g_clear_error(&err);
				}
			}
		}
	}

	notifier = event_config_repo_get_notifier(ss->extras->evt_repo);
	ht = gridcluster_get_event_config(&(ss->nsinfo),
			ss->service_config->srvtype);
	if (!ht)
		err = NEWERROR(EINVAL, "Invalid parameter");
	else {
		g_hash_table_foreach(ht, _update_each, NULL);
		g_hash_table_destroy(ht);
	}

	if (!err)
		GRID_TRACE("Event config reloaded");
	else {
		GRID_WARN("Event config reload error [%s]: (%d) %s",
				ss->ns_name, err->code, err->message);
		g_clear_error(&err);
	}

	if (must_clear_events)
		metautils_notifier_free_kafka(notifier);
}

