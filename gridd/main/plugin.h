/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#endif /*OIO_SDS__gridd__main__plugin_h*/
