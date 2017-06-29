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

gint plugin_holder_keep (GModule *mod, GHashTable *params, GError **err)
{
	EXTRA_ASSERT(mod != NULL);
	EXTRA_ASSERT(params != NULL);

	plugin_holder_init();

	struct plugin_s *plg= g_malloc0(sizeof(struct plugin_s));

	/* try to load EXPORTED_SYMBOL_V2 if exists */
	if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME_V2, (void**)&(plg->syms))) {
		/* loading old style EXPORTED_SYMBOL */
		if (!g_module_symbol(mod, EXPORTED_SYMBOL_NAME, (void**)&(plg->syms))) {
			GSETERROR(err, "Cannot get the exported structure (%s) from the plug-in %p (%s)", EXPORTED_SYMBOL_NAME, (void*)mod, g_module_error());
			goto errorLabel;
		}
	}

	if (NULL != g_hash_table_lookup(plugins, plg->syms->name)) {
		g_free (plg);
		return 1;
	}

	plg->module = mod;
	plg->params = params;
	plg->init_done = FALSE;

	g_hash_table_insert (plugins, plg->syms->name, plg);
	plugins_list = g_slist_append (plugins_list, plg);

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
			GRID_ERROR("cannot close the plugin %s : (%d) %s", plg->syms->name, err->code, err->message);
		if (err)
			g_clear_error(&err);
	}

	plugin_holder_init();

	g_slist_foreach (plugins_list, runner, NULL);
	GRID_DEBUG ("Plugins closed!");
}

gint plugin_holder_init_all (GError **err)
{
	gboolean mayContinue=TRUE;

	void runner (gpointer d, gpointer e0) {
		struct plugin_s *plg = (struct plugin_s*) d;
		if (!mayContinue || plg->init_done)
			return;
		plg->init_done = TRUE;
		GRID_DEBUG ("initializing %s", plg->syms->name);
		if (!plg->syms->init (plg->params, e0)) {
			GSETERROR(e0, "Failed to init plugin %s", plg->syms->name);
			mayContinue = FALSE;
		}
	}

	plugin_holder_init();
	GRID_DEBUG ("Plugins being initiated ...");
	g_slist_foreach (plugins_list, runner, err);
	GRID_DEBUG ("Plugins initiated!");
	return mayContinue ? 1 : 0;
}
