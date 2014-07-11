#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_container"
#endif //G_LOG_DOMAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <glib.h>

#include "../metautils/lib/loggers.h"
#include "../metautils/lib/metautils.h"

#include "lib/lib_trip.h"
#include "lib/crawler_tools.h"
#include "lib/dir_explorer.h"

#define LIMIT_LENGTH_URL 23


static gchar* trip_name = "trip_test_action";
static gchar* source_cmd_opt_name = "s";
static gchar* infinite_cmd_opt_name = "infinite";
static gchar* triptest_cmd_opt_name = "triptest";
static gchar* triptestdata_cmd_opt_name = "triptestdata";
static gchar* trip_occur_format_string = "(ss)";

static gchar meta1_url[LIMIT_LENGTH_URL] = "";
static gchar meta2_url[LIMIT_LENGTH_URL] = "";
static gchar* source_directory_path_ref = NULL;
static gchar* triptest  = NULL;
static gchar* triptestdata = NULL;

static dir_explorer_t dir_explorer_handle;

static gboolean infinite = FALSE;


struct SItemTest {
	gboolean bTitle;
	int argc;
	char** argv;
};

static GSList* g_item_test = NULL;   //struct SItemTest*



int
trip_progress(void)
{
	return dir_progress(&dir_explorer_handle);
}

int
trip_start(int argc, char** argv)
{
	GError *err = NULL;
	memset(meta2_url, 0, sizeof(meta2_url));
	memset(&dir_explorer_handle, 0, sizeof(dir_explorer_t));

	if (NULL != (triptest = get_argv_value(argc, argv, trip_name, triptest_cmd_opt_name))) {
	}

    if (NULL != (triptestdata = get_argv_value(argc, argv, trip_name, triptestdata_cmd_opt_name))) {
	 }
	

	/* Infinite parameter extraction */
	gchar* temp_infinite = NULL;
	if (NULL != (temp_infinite = get_argv_value(argc, argv, trip_name, infinite_cmd_opt_name))) {
		infinite = metautils_cfg_get_bool(temp_infinite, FALSE);
		g_free(temp_infinite);
	}
	/* ------- */

	/* Source directory path extraction */
	if (NULL == (source_directory_path_ref = get_argv_value(argc, argv, trip_name, source_cmd_opt_name))) {
		GRID_ERROR("Bad or missing -%s.%s argument", trip_name, source_cmd_opt_name);
		return EXIT_FAILURE;
	}
	/* ------- */

	if (NULL != (triptest = get_argv_value(argc, argv, trip_name, triptest_cmd_opt_name))) {
	}


	/* Meta2 URL extraction */
	if (getxattr(source_directory_path_ref, "user.meta2_server.address", meta2_url, sizeof(meta2_url)) <= 0) {
        GRID_ERROR("Failed during get xattr(meta2) parameter about repository [%s]: (errno:%d)", source_directory_path_ref, errno);
	}
	
    /* Meta1 URL extraction */
    if (getxattr(source_directory_path_ref, "user.meta1_server.address", meta1_url, sizeof(meta1_url)) <= 0) {
        GRID_ERROR("Failed during get xattr(meta2) parameter about repository [%s]: (errno:%d)", source_directory_path_ref, errno);
    }


	/* ------- */
	err = dir_explore(source_directory_path_ref, &dir_explorer_handle);
	if (err) {
		GRID_ERROR("Failed during exploring repository [%s]: %s", source_directory_path_ref, err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }


	FILE* f = fopen(triptestdata, "r");
	if (f) {
		char tmp[100];
		gboolean b = TRUE;
		while (fgets(tmp, 99, f) != NULL) {
			struct SItemTest* itm =  g_new(struct SItemTest, 1);
			if (strlen(tmp) <= 0) break;
			if ((tmp[strlen(tmp)-1] == '\n')||(tmp[strlen(tmp)-1] == '\r'))
				tmp[strlen(tmp)-1] = '\0';

			itm->argv = g_strsplit(tmp, ",", 0);
		    itm->argc = g_strv_length(itm->argv);
			itm->bTitle = b;   b = FALSE;
			g_item_test = g_slist_append(g_item_test, itm);

		}
		fclose(f);
	}



	return EXIT_SUCCESS;
}

static gboolean
_reset_infinite(void)
{
	GError *err = NULL;
	sleep(1);

	dir_explorer_clean(&dir_explorer_handle);

	return TRUE;
}


// selection du type de test: trip_chunk / trip_container / trip_content / trip_prefix
//selon type de test, selection meta1_url/meta2_url
static GVariant* _sub_trip_next()
{
    static int test_id = 0;
    static int item_nb = 0;
	GVariant* ret = NULL;

	int nb = g_slist_length(g_item_test);

	do {
		struct SItemTest* item = NULL;
		do {
			fprintf(stdout, "%s> test_id=%d / total:%d\n", trip_name, test_id, nb);
			item = (struct SItemTest*) g_slist_nth_data(g_item_test, test_id);
			if (item == NULL) {
				test_id = 0;
				fprintf(stdout, "%s>: End of test case\n", trip_name);
				return NULL;
			}
			test_id++;

			if (item->bTitle == TRUE) {
				GString* str = g_string_new("");
				for(item_nb=0;item_nb<item->argc;item_nb++)
					g_string_append_printf(str, "%s, ", item->argv[item_nb]);
				gchar* tmp = g_string_free(str, FALSE);
				fprintf(stdout, "%s> %s\n", trip_name, tmp);
				g_free(tmp);
			} else {	
				switch(item->argc) {
				case 1: ret = g_variant_new("(s)", item->argv[0]);
						break;

				case 2:	ret = g_variant_new("(ss)", item->argv[0], item->argv[1]);
						break;

				case 3:	ret = g_variant_new("(sss)", item->argv[0], item->argv[1], item->argv[2]);
						break;

				default:
						fprintf(stdout, "%d item: Failed to generate GVariant, NOT IMPLEMENTED\n", item->argc);
						test_id = 0;
						return NULL;
				};
				gchar* tmp = g_variant_print(ret, FALSE);
				fprintf(stdout, "%s> Send To Action [%s]\n", trip_name, tmp);
				g_free(tmp);
				return ret;
			}
			fprintf(stdout, "%s> End Item\n", trip_name);
		} while (item != NULL);
		test_id = 0;
	}while (infinite);
	fprintf(stdout, "%s> End test\n", trip_name);

	return NULL;
}

GVariant*
trip_next(void)
{
	return _sub_trip_next();
}

void
trip_end(void)
{
	dir_explorer_clean(&dir_explorer_handle);
	if (NULL!= source_directory_path_ref)
        g_free(source_directory_path_ref);
}

