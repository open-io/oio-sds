/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__gridd__main__plugin_h
# define OIO_SDS__gridd__main__plugin_h 1

#include <glib.h>
#include <gmodule.h>

/**
 * The signature of the callback called for each plugin previously loaded.
 *
 * Never called in  a multi-thread environment.
 */
typedef gint (*plugin_init_f)  (GHashTable *h, GError **err);

/**
 * The signature of the callback used for reload plugin configuration.
 */
typedef gint (*plugin_configure_f) (GHashTable *h, GError **err);

/**
 * The signature of the callback used before the main program exit.
 *
 * Never called in  a multi-thread environment.
 */
typedef gint (*plugin_close_f) (GError **err);

/**
 * This function can be called in a multithread environment.
 * It returns a copy of structure API of the plugin.
 */
typedef gpointer (*plugin_get_provided_api_f) (GError **err);

/**
 * The structure that must be exported by each plugin.
 */
struct exported_api_s
{
#define LIMIT_PLUGIN_NAME_LENGTH 64
	gchar                      name [LIMIT_PLUGIN_NAME_LENGTH];
	plugin_init_f              init;
	plugin_close_f             close;
	plugin_get_provided_api_f  get_api;
	plugin_configure_f	   configure;
};

/**
 *
 */
# define EXPORTED_SYMBOL_NAME "exported_symbol"
# define EXPORTED_SYMBOL_NAME_V2 "exported_symbol_v2"
# define EXPORTED_SYMBOL exported_symbol

/**
 * Get a copy of the previously registered plugin API.
 * The result has been alocated with g_try_malloc() and must be
 * freed with g_free();
 */
gpointer plugin_get_api (const gchar *plugin_name, GError **err);

/**
 * Register a new plugin in the core.
 */
gint plugin_add_api (struct exported_api_s *api, GError **err);

#endif /*OIO_SDS__gridd__main__plugin_h*/
