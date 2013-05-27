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

#ifndef GS_BENCH__H
# define GS_BENCH__H 1

#include <glib.h>

#include "../lib/grid_client.h"

typedef gint (*generator_callback) (gchar *name, gint name_len, gpointer user_data);

struct scenario_data {
	generator_callback container_generator;
	generator_callback content_generator;
	gpointer callback_userdata;
	gs_grid_storage_t * gs;
	GSList *options;
};

typedef struct s_content_data {
	gchar *container_name;
	gs_container_t *container;
	gpointer user_data;
} t_content_data;

void gs_g_slist_foreach_until_stop(GSList *list, GFunc func, gpointer user_data);

/* Initializers */
void init_container_generators(GHashTable * container_generators);
void init_content_generators(GHashTable * content_generators);
void init_scenarii(GHashTable * scenarii);

gboolean is_input_file_needed(const gchar *generator_name);
gboolean is_namespace_needed(const gchar *scenario);
gboolean is_container_generator_needed(const gchar *scenario);
gboolean is_content_generator_needed(const gchar *scenario);
gboolean is_multithreading_supported(const gchar *scenario);

void clean_scenarii(void);
void clean_generators(void);

/* Tools */
void fill_namespace_content(GHashTable *ns_content, gs_grid_storage_t * gs, gpointer user_data);
GHashTable* _init_content_ht(gs_grid_storage_t *gs, gpointer user_data);
gboolean _apply_callback_to_ht(GHashTable *_content_ht, GFunc _callback, gs_grid_storage_t *gs, gpointer _user_data);
gboolean _apply_callback_to_list(gpointer _container_name, gpointer _content_list, gpointer _acd);
GSList* get_container_list(const gchar *filepath);
GSList* get_txtfile_lines(const gchar *filepath);

/* Scenarii */
typedef gboolean (*scenario_callback) (struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean create_container_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean put_content_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean set_service_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean get_service_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean delete_all_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean get_all_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len);
gboolean m2v2_db_convert(struct scenario_data * sdata, gchar * result_str, gint result_str_len);

#endif /* GS_BENCH__H */
