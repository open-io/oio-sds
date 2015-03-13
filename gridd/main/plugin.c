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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "server"
#endif

#include <metautils/lib/metautils.h>
#include <gmodule.h>

#include "./plugin.h"
#include "./plugin_holder.h"
#include "./message_handler.h"

GHashTable *plugins = NULL;

GSList *plugins_list = NULL;

struct plugin_s
{
	gboolean init_done;
	GModule *module;
	GHashTable *params;
	struct exported_api_s *syms;
};

static void plugin_holder_init (void)
{
	if (!plugins)
		plugins = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
	g_assert(plugins != NULL);
}

/* ------------------------------------------------------------------------- */

gpointer plugin_get_api (const gchar *plugin_name, GError **err)
{
	gpointer ptr;
	struct plugin_s *plg;

	if (!plugin_name)
	{
		GSETERROR(err,"Invalid parameter");
		return NULL;
	}

	plugin_holder_init();
	
	if (!(ptr = g_hash_table_lookup (plugins, plugin_name)))
	{
		GSETERROR(err, "plugin %s not found", plugin_name);
		return NULL;
	}

	plg = (struct plugin_s*) ptr;

	return plg->syms->get_api(err);
}

gint plugin_holder_keep (GModule *mod, GHashTable *params, GError **err)
{
	struct plugin_s *plg=NULL;

	if (!mod || !params)
	{
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	plugin_holder_init();
	
	plg = g_malloc0(sizeof(struct plugin_s));
	
	/* try to load EXPORTED_SYMBOL_V2 if exists */
	if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME_V2, (void**)&(plg->syms))) {
		/* loading old style EXPORTED_SYMBOL */
		if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME, (void**)&(plg->syms))) {
			GSETERROR(err, "Cannot get the exported structure (%s) from the plug-in %p (%s)", EXPORTED_SYMBOL_NAME, (void*)mod, g_module_error());
			goto errorLabel;
		}
	}

	if (NULL != g_hash_table_lookup(plugins, plg->syms->name))
	{
		g_free (plg);
		DEBUG("Module %s already referenced", plg->syms->name);
		return 1;
	}

	plg->module = mod;
	plg->params = params;
	/* ADD gridd_get_namespace_info callback */
	g_hash_table_insert(plg->params, NS_INFO_FUNC, gridd_get_namespace_info);
	/* */
	plg->init_done = FALSE;

	g_hash_table_insert (plugins, plg->syms->name, plg);
	plugins_list = g_slist_append (plugins_list, plg);

	DEBUG("Module %s referenced", plg->syms->name);

	return 1;

errorLabel:

	if (plg)
	{
		if (plg->params)
			g_hash_table_destroy (plg->params);
		g_free(plg);
	}
	
	return 0;	
}

void plugin_holder_close_all (void)
{
	void runner (gpointer d, gpointer u) {
		struct plugin_s *plg = (struct plugin_s*) d;
		(void) u;
		GError *err = NULL;
		if (!plg->syms->close(&err))
			ERROR("cannot close the plugin %s : (%d) %s", plg->syms->name, err->code, err->message);
		if (err)
			g_clear_error(&err);
	}
	
	plugin_holder_init();
	
	g_slist_foreach (plugins_list, runner, NULL);
	DEBUG ("Plugins closed!");
}

gint plugin_holder_init_all (GError **err)
{
	gboolean mayContinue=TRUE;

	void runner (gpointer d, gpointer e0) {
		struct plugin_s *plg = (struct plugin_s*) d;
		if (!mayContinue)
			return;
		if (plg->init_done)
			return;
		plg->init_done = TRUE;
		DEBUG ("initializing %s", plg->syms->name);
		if (!plg->syms->init (plg->params, e0)) {
			GSETERROR(e0, "Failed to init plugin %s", plg->syms->name);
			mayContinue = FALSE;
		}
	}
	
	plugin_holder_init();
	DEBUG ("Plugins being initiated ...");
	g_slist_foreach (plugins_list, runner, err);
	DEBUG ("Plugins initiated!");
	return mayContinue ? 1 : 0;
}

gint plugin_holder_update_config (GModule *mod, GHashTable *params, GError **err)
{
	struct plugin_s *plg=NULL;

	struct exported_api_s *symbol = NULL;

	if (!mod || !params)
	{
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	plugin_holder_init();
	
	/* try to load EXPORTED_SYMBOL_V2 if exists */
	if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME_V2, (gpointer*)&symbol)) {
		/* loading old style EXPORTED_SYMBOL */
		if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME, (gpointer*)&symbol)) {
			GSETERROR(err, "Cannot get the exported structure (%s) from the plug-in %p (%s)",
				EXPORTED_SYMBOL_NAME, (void*)mod, g_module_error());
			return 0;
		}
	}

	if ((plg = g_hash_table_lookup(plugins, symbol->name)) == NULL)
	{
		GSETERROR(err, "Module %s not found in plugin list.", symbol->name);
		return 0;
	}

	plg->params = params;

	NOTICE("Module %s params table updated", plg->syms->name);

	return 1;
}

gint plugin_holder_reload_all (GError **err)
{
	gboolean mayContinue=TRUE;

	DEBUG ("About to reload plugins configuration...");
	
	void runner (gpointer d, gpointer e0)
	{
		struct plugin_s *plg = (struct plugin_s*) d;
		if (!mayContinue)
			return;
		DEBUG ("reloading %s", plg->syms->name);
		if (plg->syms->configure && !plg->syms->configure (plg->params, e0))
		{
			GSETERROR(e0, "Failed to reload plugin %s config", plg->syms->name);
			mayContinue = FALSE;
		}
	}
	
	g_slist_foreach (plugins_list, runner, err);

	DEBUG ("configuration reload done!");
	
	return mayContinue ? 1 : 0;
}

