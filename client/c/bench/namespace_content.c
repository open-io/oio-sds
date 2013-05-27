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

#include <glib.h>

#include "gs_bench.h"
#include "grid_client.h"
#include "metautils.h"

typedef struct s_add_container_data
{
	gs_grid_storage_t *gs;
	GHashTable *ns_content;
} add_container_data;

typedef struct s_apply_content_data {
	GFunc cb;
	gs_grid_storage_t *gs;
	gpointer user_data;
} t_apply_content_data;

static int my_content_filter(gs_content_t * content, void *user_data)
{
	gs_error_t *err = NULL;
	gs_content_info_t info;
	GSList **result = user_data;

	if (!content)
		return -1;

	if (!gs_content_get_info(content, &info, &err)) {
		ERROR("cannot read the information about a content (%s)\n", gs_error_get_message(err));
		gs_error_free(err);
		return -1;
	}
	*result = g_slist_prepend(*result, g_strdup(info.path));

	return 0;
}

static void _add_container_entries(gpointer cName, gpointer p_acdata)
{
	add_container_data *acdata = p_acdata;
	int rc = -1;
	gs_error_t *err = NULL;
	gs_container_t *container = NULL;
	GSList *clist = NULL;
	GSList **p_clist = NULL;
	const gchar *container_name = cName;

	if (!acdata || !acdata->gs || !acdata->ns_content)
		return;

	DEBUG("#listing container=[%s]", container_name);

	clist = g_hash_table_lookup(acdata->ns_content, container_name);
	if (clist == NULL) {
		container = gs_get_storage_container(acdata->gs, container_name, NULL, 0, &err);
		if (!container) {
			ERROR("cannot find %s\n", container_name);
			goto exit_label;
		} else {
			DEBUG("%s found\n", container_name);
		}

		p_clist = &clist;

		if (!gs_list_container(container, NULL, my_content_filter, p_clist, &err)) {
			ERROR("cannot list %s\n", container_name);
			goto exit_label;
		} else {
			g_hash_table_insert(acdata->ns_content, cName, *p_clist);
			DEBUG("%s listed\n", container_name);
		}
	}

exit_label:
	if (rc < 0) {
		if (err) {
			ERROR("Failed to list [%s] cause:\n", container_name);
			DEBUG("\t%s\n", gs_error_get_message(err));
			gs_error_free(err);
		} else {
			ERROR("Failed to list [%s]\n", container_name);
		}
	}
	gs_container_free(container);
}

GSList* get_txtfile_lines(const gchar *filepath)
{
	GSList *ret = NULL;
	gchar **names = NULL;
	gchar *filecontent = NULL;
	gchar *tmpname = NULL;
	gint name_pos = 0;
	GError *err = NULL;

	if (g_file_get_contents(filepath, &filecontent, NULL, &err)) {
		names = g_strsplit(filecontent, "\n", 5000);
	} else {
		ERROR("Cannot open file [%s]: %s", filepath, err->message);
		g_error_free(err);
	}

	if (names) {
		while (NULL != (tmpname = names[name_pos++])) {
			if (*tmpname != '\0' && *tmpname != '#')
				ret = g_slist_prepend(ret, g_strdup(tmpname));
		}
		g_strfreev(names);
	}

	if (filecontent)
		g_free(filecontent);

	return ret;
}

GSList* get_container_list(const gchar *filepath)
{
	GSList *container_list = get_txtfile_lines(filepath);

	if (NULL == container_list) {
		container_list = g_slist_prepend(container_list, g_strdup("BENCHCONTAINER"));
	}

	return container_list;
}

void fill_namespace_content(GHashTable *ns_content, gs_grid_storage_t *gs, gpointer user_data)
{
	add_container_data acdata = {gs, ns_content};
	gchar *filepath = user_data;
	GSList *container_list = get_container_list(filepath);

	g_slist_foreach(container_list, _add_container_entries, &acdata);
	g_slist_free(container_list);
}

gboolean _apply_callback_to_list(gpointer _container_name, gpointer _content_list, gpointer _acd)
{
	gchar *container_name = _container_name;
	GSList *content_list = _content_list;
	t_apply_content_data *acd = _acd;

	gs_grid_storage_t *gs = acd->gs;
	GFunc content_callback = acd->cb;

	t_content_data cdata;
	gs_container_t *container = NULL;
	gs_error_t *err = NULL;

	DEBUG("processing container [%s]", container_name);

	if (g_slist_length(content_list) == 0) {
		DEBUG("No file to process for container [%s]", container_name);
		return TRUE;
	}

	container = gs_get_storage_container(gs, container_name, NULL, 0, &err);
	if (!container) {
		ERROR("Cannot find container %s\n", container_name);
		if (err) {
			ERROR("%s\n", gs_error_get_message(err));
			gs_error_free(err);
		}
		return TRUE;
	}
	cdata.container_name = container_name;
	cdata.container = container;
	cdata.user_data = acd->user_data;
	gs_g_slist_foreach_until_stop(content_list, content_callback, &cdata);
	gs_container_free(container);

	if (err)
		gs_error_free(err);
	return TRUE;
}

gboolean _apply_callback_to_ht(GHashTable *_content_ht, GFunc _callback, gs_grid_storage_t *gs, gpointer _user_data)
{
	t_apply_content_data acd = {_callback, gs, _user_data};
	g_hash_table_foreach_remove(_content_ht, _apply_callback_to_list, &acd);

	return TRUE;
}

static void _slist_free(gpointer _list)
{
	GSList *list = _list;
	g_slist_free_full(list, g_free);
}

GHashTable* _init_content_ht(gs_grid_storage_t *gs, gpointer user_data)
{
	GHashTable *content_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, _slist_free);
	fill_namespace_content(content_ht, gs, user_data);
	if (g_hash_table_size(content_ht) == 0) {
		ERROR("no container to process");
		g_hash_table_destroy(content_ht);
		return NULL;
	}
	return content_ht;
}

