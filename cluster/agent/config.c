/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "gridcluster.agent.config"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <string.h>

#include <metautils.h>

#include "./config.h"
#include "./agent.h"
#include "./server.h"
#include "./cluster_conf_parser.h"
#include "../module/module.h"

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
	copy_cfg_value(GENERAL_GROUP, SVC_CHECK_FREQ_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_FREQ_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_NS_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_SRV_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_SRVTYPE_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_EVTCFG_PERIOD_KEY);
	copy_cfg_value(GENERAL_GROUP, CS_UPDATE_SRVLST_PERIOD_KEY);

	copy_cfg_value(GENERAL_GROUP, EVENTS_SPOOL_DIR_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_SPOOL_SIZE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MODE_DIR_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MODE_FILE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MANAGE_ENABLE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_RECEIVE_ENABLE_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_MAXPENDING_KEY);
	copy_cfg_value(GENERAL_GROUP, EVENTS_DELAY_INCOMING_KEY);

	copy_cfg_value(GENERAL_GROUP, EVENTS_DELAY_REFRESH_KEY);
	copy_cfg_value(GENERAL_GROUP, NSINFO_DELAY_REFRESH_KEY);

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
	gint64 i64;
	time_t result;
	GByteArray *gba_value;

	if (!ns_data || !ns_data->ns_info.options)
		return def;

	gba_value = g_hash_table_lookup(ns_data->ns_info.options, key);
	if (!gba_value)
		return def;

	if (gba_value->data[gba_value->len-1]) {
		g_byte_array_append(gba_value, (guint8*)"", 1);
		g_byte_array_set_size(gba_value, gba_value->len-1);
	}

	i64 = g_ascii_strtoll((gchar*) gba_value->data, NULL, 10);
	if (i64 < 0)
		return 0;

	return (result = i64); /* implicit conversion */
}

time_t
get_event_delay(namespace_data_t *ns_data)
{
	return get_config_time(ns_data, GS_CONFIG_EVENT_DELAY, event_delay);
}

time_t
get_nsinfo_refresh_delay(namespace_data_t *ns_data)
{
	return get_config_time(ns_data, GS_CONFIG_NSINFO_REFRESH, nsinfo_refresh_delay);
}

time_t
get_event_refresh_delay(namespace_data_t *ns_data)
{
	return get_config_time(ns_data, GS_CONFIG_EVENT_REFRESH, events_refresh_delay);
}

