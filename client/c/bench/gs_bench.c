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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.client.bench"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <glib/gprintf.h>

#include "../../../metautils/lib/metautils.h"
#include "../../../metautils/lib/common_main.h"
#include "../lib/grid_client.h"

#include "gs_bench.h"

struct thread_scenario_data {
	gint thread_group;
	scenario_callback sc;
	struct scenario_data sdata;
};

/* Globals */
static GHashTable * container_generators;
static GHashTable * content_generators;
static GHashTable * scenarii;
static GPtrArray * threads;
static gboolean stop_threads = FALSE;

/* Options */
static GString * container_generator;
static GString * content_generator;
static GString * asked_scenarii;
static gint nb_thread;
static gboolean use_cache;
static gint content_size;
static GString * input_file_name;
static GString * generator_file_name;
static gchar * namespace;

/* usage string */
static gchar *usage_string = NULL;

void gs_g_slist_foreach_until_stop(GSList *list, GFunc func, gpointer user_data)
{
	do {
		func(g_slist_nth_data(list, 0), user_data);
	} while (NULL != (list = g_slist_next(list)) && !stop_threads);
}

static void
scenario_thread(gpointer data)
{
	g_assert(data);
	struct thread_scenario_data * tsdata = data;
	GTimer * timer = g_timer_new();
	GTimeVal timeval;

	while (!stop_threads) {
		guint elapsed = 0;
		gboolean result = FALSE;
		gchar result_str[256];

		memset(result_str, '\0', sizeof(result_str));

		g_timer_start(timer);
		result = tsdata->sc(&(tsdata->sdata), result_str, sizeof(result_str));
		elapsed = 1000*g_timer_elapsed(timer, NULL);
		g_get_current_time(&timeval);
		g_printf("%lli,%u,%s,,ThreadGroup %d,,%s,0\n", (timeval.tv_sec*1000LL)+(timeval.tv_usec/1000), elapsed, result_str,
				tsdata->thread_group, result ? "true" : "false");
		g_usleep(10000);
	}

	/* free data before exiting */
	g_free(data);
	g_timer_destroy(timer);
}

static void
scenario_thread_join(gpointer data, gpointer user_data)
{
	GThread * thread = data;
	(void) user_data;

	g_assert(thread);

	g_thread_join(thread);
}

static void
gs_bench_action(void)
{
	struct thread_scenario_data tsdata;
	gs_error_t * error = NULL;
	gchar *content_generator_name = NULL;
	gchar *container_generator_name = NULL;
	gs_container_t* container = NULL;
	struct stat stat_buf;

	g_assert(asked_scenarii);

#if 0
	GRegex * scenario_regex = NULL;
	GMatchInfo * scenario_regex_info = NULL;

	/* Extract scenario options */
	scenario_regex = g_regex_new("(\\w*)\\{(?:(\\w*=\\w*);?)*\\}", G_REGEX_CASELESS|G_REGEX_EXTENDED, 0, NULL);
	if (! g_regex_match(scenario_regex, asked_scenarii->str, 0, &scenario_regex_info)) {
		GRID_ERROR("Failed to parse scenario options");
		return;
	}
	g_printf("Scenario parsing matched %d patterns\n", g_match_info_get_match_count(scenario_regex_info));
	for (gint i = 0; i < g_match_info_get_match_count(scenario_regex_info); i++) {
		g_printf("Matched pattern %d : %s\n", i, g_match_info_fetch (scenario_regex_info, i));
	}
#endif

	/* Init data */
	tsdata.sc = g_hash_table_lookup(scenarii, asked_scenarii->str);
	if (tsdata.sc == NULL) {
		g_printerr("Unknown scenario [%s]\n", asked_scenarii->str);
		return;
	}

	if (is_namespace_needed(asked_scenarii->str)) {
		tsdata.sdata.gs = gs_grid_storage_init(namespace, &error);
		if (tsdata.sdata.gs == NULL) {
			g_printerr("Failed to connect to namespace [%s] : %s\n", namespace, gs_error_get_message(error));
			goto error_label;
		}
	}

	tsdata.sdata.options = NULL;
	tsdata.sdata.callback_userdata = NULL;

	tsdata.sdata.options = g_slist_append(tsdata.sdata.options, &use_cache);

	/* Initialize generators for scenarii needing names (eg containers or contents creation) */
	if (is_content_generator_needed(asked_scenarii->str)) {
		if (content_generator) {
			tsdata.sdata.content_generator = g_hash_table_lookup(content_generators, content_generator->str);
			content_generator_name = content_generator->str;
			if (tsdata.sdata.content_generator == NULL) {
				g_printerr("Unknown content generator [%s]\n", content_generator_name);
				goto error_label;
			}
		} else {
			g_printerr("The scenario [%s] needs a content generator.  Please specify it with option 'ContentGenerator'.\n", asked_scenarii->str);
			goto error_label;
		}

		if (container_generator) {
			tsdata.sdata.container_generator = g_hash_table_lookup(container_generators, container_generator->str);
			container_generator_name = container_generator->str;
		}

		tsdata.sdata.options = g_slist_append(tsdata.sdata.options, &content_size);
		if (input_file_name) {
			if (stat(input_file_name->str, &stat_buf) == -1) {
				g_printerr("Error stating [%s]: %s\n", input_file_name->str, strerror(errno));
				goto error_label;
			}

			if (!S_ISREG(stat_buf.st_mode)) {
				g_printerr("Error: [%s] is not a regular file.\n", input_file_name->str);
				goto error_label;
			}
			tsdata.sdata.options = g_slist_append(tsdata.sdata.options, input_file_name->str);
		}
	}

	if (is_container_generator_needed(asked_scenarii->str)) {
		if (container_generator) {
			tsdata.sdata.container_generator = g_hash_table_lookup(container_generators, container_generator->str);
			container_generator_name = container_generator->str;
			if (tsdata.sdata.container_generator == NULL) {
				g_printerr("Unknown container generator [%s]\n", container_generator_name);
				goto error_label;
			}
		} else {
			g_printerr("The scenario [%s] needs a container generator.  Please specify it with option 'ContainerGenerator'.\n", asked_scenarii->str);
			goto error_label;
		}
	}

	if (nb_thread > 1 && !is_multithreading_supported(asked_scenarii->str)) {
		g_print("The scenario [%s] does not support multithreading.  Switching number of threads to 1.\n", asked_scenarii->str);
		nb_thread = 1;
	}

	if (is_input_file_needed(container_generator->str) || is_input_file_needed(content_generator->str)) {
		if (generator_file_name) {
			if (stat(generator_file_name->str, &stat_buf) == -1) {
				g_printerr("Error stating [%s]: %s\n", generator_file_name->str, strerror(errno));
				goto error_label;
			}

			if (!S_ISREG(stat_buf.st_mode)) {
				g_printerr("Error: [%s] is not a regular file.\n", generator_file_name->str);
				goto error_label;
			}
			tsdata.sdata.callback_userdata = generator_file_name->str;
		} else {
			g_printerr("The generator [%s] needs an input file containing names.  Please specify it with option 'GeneratorFile'.\n",
					container_generator->str ? container_generator->str : content_generator->str);
			goto error_label;
		}
	}

	/* Lauch threads */
	threads = g_ptr_array_new();
	for (gint i = 1; i <= nb_thread; i++) {
		g_printf("Starting thread %d of scenario [%s]\n", i, asked_scenarii->str);
		tsdata.thread_group = i;
		g_ptr_array_add(threads, g_thread_create((GThreadFunc)scenario_thread,
					g_memdup(&tsdata, sizeof(struct thread_scenario_data)), TRUE, NULL));
	}

	/* Wait for all threads to stop */
	g_ptr_array_foreach(threads, (GFunc)scenario_thread_join, NULL);

error_label:
	/* Clean data */
	gs_grid_storage_free(tsdata.sdata.gs);
	if (error)
		gs_error_free(error);
	if (container)
		gs_container_free(container);
	if (tsdata.sdata.options)
		g_slist_free(tsdata.sdata.options);
}

static inline gboolean
_is_help(gchar *str)
{
	return 0 == g_strcmp0("help", str);
}

static const char *
gs_bench_usage(void)
{
	auto void _append_to_string (gpointer, gpointer);
	GString *strbuff = NULL;

	if (usage_string)
		return usage_string;
	
	strbuff = g_string_new("<NS_NAME>\n");

#define APPEND_HT_KEYS_TO_USAGE(desc, ht) \
do { \
	g_string_append_printf(strbuff, "\n%s", desc); \
	GList *key_list = g_hash_table_get_keys(ht); \
	g_list_foreach(key_list, _append_to_string, strbuff); \
	g_list_free(key_list); \
	g_string_overwrite(strbuff, strbuff->len-1, "\n"); \
} while (0)

	void _append_to_string (gpointer str, gpointer user_data) {
		g_string_append_printf(user_data, "%s,", (gchar*)str);
	}

	if (container_generator && _is_help(container_generator->str)) {
		APPEND_HT_KEYS_TO_USAGE("Available container generators: ", container_generators);
	}

	if (content_generator && _is_help(content_generator->str)) {
		APPEND_HT_KEYS_TO_USAGE("Available content generators: ", content_generators);
	}

	if (asked_scenarii && _is_help(asked_scenarii->str)) {
		APPEND_HT_KEYS_TO_USAGE("Available scenarii: ", scenarii);
	}

	return (usage_string = g_string_free(strbuff, FALSE));
}

static struct grid_main_option_s *
gs_bench_get_options(void)
{
        static struct grid_main_option_s gs_bench_options[] = {
		{"ContainerGenerator", OT_STRING, {.str = &container_generator},
                        "Specificy a container generator algorythm ('help' to get a list of available generators)"},
		{"ContentGenerator", OT_STRING, {.str = &content_generator},
                        "Specificy a content generator algorythm ('help' to get a list of available generators)"},
		{"GeneratorFile", OT_STRING, {.str = &generator_file_name},
                        "Specificy an input file for generators to read names from"},
		{"ContentSize", OT_INT, {.i = &content_size},
                        "Specificy a content size (in bytes)"},
		{"ContentInputFile", OT_STRING, {.str = &input_file_name},
                        "Specificy an input file to read content from"},
		{"Scenarii", OT_STRING, {.str = &asked_scenarii},
                        "Specificy a list of scenarii to launch for this bench ('help' to get a list of available scenarii)"},
		{"UseCache", OT_BOOL, {.b = &use_cache},
                        "Specificy whether the scenario should use cached entries"},
		{"NbThread", OT_INT, {.i = &nb_thread},
                        "Specificy the number of threads to launch for this bench"},
                {NULL, 0, {.i=0}, NULL}
        };
        return gs_bench_options;
}

static void
gs_bench_specific_fini(void)
{
	if (usage_string)
		free(usage_string);
	g_hash_table_destroy(scenarii);
	clean_scenarii();
	clean_generators();
}

static void
gs_bench_set_defaults(void)
{
	container_generators = g_hash_table_new(g_str_hash, g_str_equal);
	content_generators = g_hash_table_new(g_str_hash, g_str_equal);
	scenarii = g_hash_table_new(g_str_hash, g_str_equal);

	init_container_generators(container_generators);
	init_content_generators(content_generators);
	init_scenarii(scenarii);

	nb_thread = 1;
	content_size = 1<<20;
	input_file_name = NULL;
	generator_file_name = NULL;
	use_cache = FALSE;
}

static gboolean
gs_bench_configure(int argc, char **argv)
{
	if (asked_scenarii == NULL || _is_help(asked_scenarii->str)) {
		GRID_WARN("No scenario specified in options, see usage.");
		return FALSE;
	}

	if (is_namespace_needed(asked_scenarii->str)) {
		if (argc < 1) {
			GRID_WARN("Not enough options, see usage.");
			return FALSE;
		}
		namespace = g_strdup(argv[0]);
	}

	// If help was asked for one of the options, return FALSE to display usage
	if ((container_generator && _is_help(container_generator->str)) ||
		(content_generator && _is_help(content_generator->str)) ) {
		return FALSE;
	}

	return TRUE;
}

static void
gs_bench_specific_stop(void)
{
	stop_threads = TRUE;
        GRID_TRACE("STOP!");
}

static struct grid_main_callbacks gs_bench_callbacks =
{
        .options = gs_bench_get_options,
        .action = gs_bench_action,
        .set_defaults = gs_bench_set_defaults,
        .specific_fini = gs_bench_specific_fini,
        .configure = gs_bench_configure,
        .usage = gs_bench_usage,
        .specific_stop = gs_bench_specific_stop,
};

int
main(int argc, char ** argv)
{
        return grid_main(argc, argv, &gs_bench_callbacks);
}
