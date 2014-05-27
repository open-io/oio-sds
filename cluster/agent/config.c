#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.config"
#endif

#include <string.h>

#include <metautils/lib/metautils.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/module/module.h>

#include "./config.h"
#include "./agent.h"
#include "./server.h"
#include "./cluster_conf_parser.h"

#define GRIDD_TIMEOUT 5000

#define GENERAL_GROUP "General"

int
parse_config(const char *config_file, GHashTable * params, GError ** error)
{
	GKeyFile *key_file = NULL;

	void copy_cfg_value(const gchar *g, const gchar *n) {
		if (g_key_file_has_key(key_file, g, n, error))
			g_hash_table_insert(params, g_strdup(n), g_key_file_get_value(key_file, g, n, error));
	}

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, config_file, 0, error)) {
		GSETERROR(error, "Failed to load key file %s", config_file);
		goto error;
	}
	if (!g_key_file_has_key(key_file, GENERAL_GROUP, USER_KEY, error)) {
		GSETERROR(error, "No user specified in config");
		goto error;
	}
	if (!g_key_file_has_key(key_file, GENERAL_GROUP, GROUP_KEY, error)) {
		GSETERROR(error, "No group specified in config");
		goto error;
	}
	if (g_key_file_has_key(key_file, GENERAL_GROUP, BACKLOG_KEY, error)) {
		gchar *str;
		gint64 i64;

		str = g_key_file_get_value(key_file, GENERAL_GROUP, BACKLOG_KEY, error);
		i64 = g_ascii_strtoll(str, NULL, 10);
		g_free(str);
		backlog_unix = backlog_tcp = CLAMP(i64, 128LL, 1024LL);
		NOTICE("UNIX and TCP backlogs set to [%d]", backlog_tcp);
	}


	copy_cfg_value(GENERAL_GROUP, USER_KEY);
	copy_cfg_value(GENERAL_GROUP, GROUP_KEY);

	copy_cfg_value(GENERAL_GROUP, SVC_CHECK_KEY);
	copy_cfg_value(GENERAL_GROUP, SVC_CHECK_FREQ_KEY);

	copy_cfg_value(GENERAL_GROUP, KEY_BROKEN_MANAGE);
	copy_cfg_value(GENERAL_GROUP, KEY_BROKEN_FREQ_PUSH);
	copy_cfg_value(GENERAL_GROUP, KEY_BROKEN_FREQ_GET);

	copy_cfg_value(GENERAL_GROUP, CS_DEFAULT_FREQ_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_GET_EVTCFG_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_GET_NS_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_GET_SRVTYPE_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_GET_SRVLIST_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_PUSH_SRVLIST_PERIOD_KEY);

	copy_cfg_value(GENERAL_GROUP, EVENTS_SPOOL_DIR_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_SPOOL_SIZE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MODE_DIR_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MODE_FILE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MANAGE_ENABLE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_RECEIVE_ENABLE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MAXPENDING_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_DELAY_INCOMING_KEY);

	copy_cfg_value(GENERAL_GROUP, UNIX_SOCK_KEY_MODE);
	copy_cfg_value(GENERAL_GROUP, UNIX_SOCK_KEY_UID);
	copy_cfg_value(GENERAL_GROUP, UNIX_SOCK_KEY_GID);

	if (g_key_file_has_group(key_file, NAME_SECTION_SERVER_INET)) {
		if (g_key_file_has_key(key_file, NAME_SECTION_SERVER_INET, BACKLOG_KEY, error)) {
			gchar *str;
			gint64 i64;

			str = g_key_file_get_value(key_file, NAME_SECTION_SERVER_INET, BACKLOG_KEY, error);
			i64= g_ascii_strtoll(str, NULL, 10);
			g_free(str);
			backlog_tcp = CLAMP(i64,128LL,1024LL);
			NOTICE("TCP backlog set to [%d]", backlog_tcp);
		}
		if (g_key_file_has_key(key_file, NAME_SECTION_SERVER_INET, PORT_KEY, error)) {
			gchar *str;
			gint64 i64;
			int i_port;

			str = g_key_file_get_value(key_file, NAME_SECTION_SERVER_INET, PORT_KEY, error);
			i64= g_ascii_strtoll(str, NULL, 10);
			g_free(str);
			i_port = i64;
			set_inet_server_port(i_port);
		}
	}

	g_key_file_free(key_file);
	return (1);

      error:
	g_key_file_free(key_file);

	return (0);
}

/* ------------------------------------------------------------------------- */

static time_t
get_config_time(namespace_data_t *ns_data, const gchar *key, time_t def)
{
	if (!ns_data)
		return def;
	return gridcluster_get_nsinfo_int64(&(ns_data->ns_info), key, def);
}

time_t
get_event_delay(namespace_data_t *ns_data)
{
	return get_config_time(ns_data, GS_CONFIG_EVENT_DELAY, event_delay);
}

