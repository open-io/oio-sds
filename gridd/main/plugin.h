#ifndef __PLUGIN_H__
# define __PLUGIN_H__

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

#define NS_INFO_FUNC "ns_info_func"

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

#endif /*__PLUGIN_H__*/
