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

#ifdef HAVE_CONFIG
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.griddef.module"
#endif
#include <glib.h>
#include <metautils.h>
#include "./griddef_wrapper.h"

static GStaticRecMutex initMutex;
static struct conscience_db_s *db = NULL;

gboolean
gdwrap_get_nsinfo(GSList *list_nsname, GSList **list_nsinfo, GError **error)
{
	return griddef_get_nsinfo(db, list_nsname, list_nsinfo, error);
}

gboolean
gdwrap_get_extended_nsinfo(GSList *list_nsname, GSList **list_nsinfo, GError **error)
{
	return griddef_get_extended_nsinfo(db, list_nsname, list_nsinfo, error);
}

gboolean
gdwrap_load_services_by_host(const gchar *hostname, GSList **result, GError **error)
{
	return griddef_load_services_by_host(db, hostname, result, error);
}

gboolean
gdwrap_load_services_by_address(const gchar *str_ip, GSList **result, GError **error)
{
	return griddef_load_services_by_address(db, str_ip, result, error);
}

int
griddef_custom_init(GHashTable * params, GError ** err)
{
	struct griddef_cnx_s cnx;

	g_static_rec_mutex_init(&initMutex);

	if (db) {
		GSETERROR(err, "DB connection init already done");
		goto error;
	}

	if (!(cnx.url = g_hash_table_lookup(params,"url"))) {
		GSETERROR(err, "No database URL set in the configuration key=[url]");
		goto error;
	}
	if (!(cnx.user = g_hash_table_lookup(params,"user"))) {
		GSETERROR(err, "No database user set in the configuration key=[user]");
		goto error;
	}
	if (!(cnx.passwd = g_hash_table_lookup(params,"passwd"))) {
		GSETERROR(err, "No database password set in the configuration key=[passwd]");
		goto error;
	}
	if (!(cnx.db_name = g_hash_table_lookup(params,"db_name"))) {
		GSETERROR(err, "No database name set in the configuration key=[db_name]");
		goto error;
	}

	if (!(db = griddef_init_db_handle(&cnx, err))) {
		GSETERROR(err, "Cannot connect to the conscience");
		goto error;
	}

	DEBUG("Conscience's DB-connection establiched");
	return 1;

error:
	ERROR("conscience DB connection failed : %s", err ? gerror_get_message(*err) : NULL);
	return 0;
}

void
griddef_custom_close(void)
{
	g_static_rec_mutex_lock(&initMutex);
	if (db)
		griddef_close_db_handle(db);
	g_static_rec_mutex_unlock(&initMutex);
}

