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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "metautils.h"

#include "gs_bench.h"

static gint generic_generator_random(const gchar *head, gchar *name, gint name_len, gpointer user_data);
static gint generic_generator_random_range(const gchar *head, gchar *name, gint name_len, gpointer user_data);
static gint generic_generator_list(const gchar *head, gchar *name, gint name_len, gpointer user_data);

#define DEFINE_GENERATOR(obj, algo) \
	static gint obj##_generator_##algo(gchar *name, gint name_len, gpointer user_data) { \
		return generic_generator_##algo("gs_bench_"#obj, name, name_len, user_data); \
	}

// Content generators definition
DEFINE_GENERATOR(content, random)
DEFINE_GENERATOR(content, random_range)
DEFINE_GENERATOR(content, list)

// Container generators definition
DEFINE_GENERATOR(container, random)
DEFINE_GENERATOR(container, random_range)
DEFINE_GENERATOR(container, list)

void init_container_generators(GHashTable * container_generators)
{
	g_assert(container_generators);

	g_hash_table_insert(container_generators, "random", container_generator_random);
	g_hash_table_insert(container_generators, "random_range", container_generator_random_range);
	g_hash_table_insert(container_generators, "list", container_generator_list);
}

void init_content_generators(GHashTable * content_generators)
{
	g_assert(content_generators);

	g_hash_table_insert(content_generators, "random", content_generator_random);
	g_hash_table_insert(content_generators, "random_range", content_generator_random_range);
	g_hash_table_insert(content_generators, "list", content_generator_list);
}

gboolean is_input_file_needed(const gchar *generator_name)
{
	return g_strcmp0(generator_name, "list") == 0;
}

static gint generic_generator_random(const gchar *head, gchar *name, gint name_len, gpointer user_data)
{
	(void) user_data;
	g_assert(name);
	memset(name, '\0', name_len);

	g_snprintf(name, name_len, "%s_%u_%u", head, getpid(), g_random_int());

	return 1;
}

static gint generic_generator_random_range(const gchar *head, gchar *name, gint name_len, gpointer user_data)
{
	(void) user_data;
	g_assert(name);
	memset(name, '\0', name_len);

	g_snprintf(name, name_len, "%s_%u", head, g_random_int_range(0, 50));

	return 1;
}

static gchar **names = NULL;

static gint generic_generator_list(const gchar *head, gchar *name, gint name_len, gpointer user_data)
{
	static GStaticMutex global_mutex = G_STATIC_MUTEX_INIT;
	static gint name_pos = 0;

	(void) head;
	gchar *tmpname = NULL;

	g_assert(name);
	g_assert(user_data);
	memset(name, '\0', name_len);

	g_static_mutex_lock(&global_mutex);
	if (names == NULL) {
		GError *err = NULL;
		gchar *filecontent = NULL;
		gchar *filepath = user_data;
		if (g_file_get_contents(filepath, &filecontent, NULL, &err)) {
			names = g_strsplit(filecontent, "\n", 5000);
			g_free(filecontent);
		} else {
			ERROR("Cannot open file [%s]: %s", filepath, err->message);
			return 0;
		}
	}

	if (names) {
		while (NULL != (tmpname = names[name_pos++])) {
			if (*tmpname != '\0' && *tmpname != '#')
				break;
		}
		if (tmpname) {
			g_snprintf(name, name_len, "%s", tmpname);
		} else {
			name_pos = 1;
			g_snprintf(name, name_len, "%s", names[0]);
		}
	}
	g_static_mutex_unlock(&global_mutex);

	return 1;
}

void
clean_generators(void)
{
	if (names)
		g_strfreev(names);
}

