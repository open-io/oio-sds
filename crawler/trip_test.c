/* THIS FILE IS NO MORE MAINTAINED */

#include <stdlib.h>
#include <string.h>

#include "lib/lib_trip.h"
#include "lib/crawler_constants.h"
#include "lib/crawler_tools.h"

static gchar* trip_name = "trip_test";
static gchar* source_cmd_opt_name = "s";
static gchar* extension_cmd_opt_name = "e";
static gchar* trip_occur_format_string = "(s)";

static gchar* source_directory_path = NULL;
static GDir* source_directory_pointer = NULL;
static gchar** extensions = NULL;

/*
 * This function tests if the extension of a particular file name is contained into an array of extension values (TRUE on NULL parameters)
 **/
static gboolean
extension_test(gchar** array, gchar* file_name)
{
        const gchar* entry = NULL;
        gchar* src_extension = NULL;
        int i = 0;

        if (NULL == array || NULL == file_name || 0 == g_strv_length(array))
                return TRUE;

        while ((entry = array[i])) {
                src_extension = g_substr(file_name, strlen(file_name) - strlen(entry), strlen(file_name));

                if (!g_strcmp0(src_extension, entry)) {
                        g_free(src_extension);

                        return TRUE;
                }

                g_free(src_extension);

                i++;
        }

        return FALSE;
}

int
trip_start(int argc, char** argv)
{
	gchar* temp = NULL;

	if (NULL == (source_directory_path = get_argv_value(argc, argv, trip_name, source_cmd_opt_name))){
		g_printerr("bad source_directory_path");
		return EXIT_FAILURE;
	}

	if (NULL == (source_directory_pointer = g_dir_open(source_directory_path, 0, NULL))) {
		g_free(source_directory_path);
		g_printerr("Failed g_dir_open");
		return EXIT_FAILURE;
	}
	/* ------- */

	/* Allowed extensions extraction */
	if (NULL == (temp = get_argv_value(argc, argv, trip_name, extension_cmd_opt_name)))
		return EXIT_SUCCESS;

	extensions = g_strsplit(temp, opt_value_list_separator, -1);
	/* ------- */

	return EXIT_SUCCESS;
}

GVariant*
trip_next(void)
{
        gchar* file_name = NULL;

        if (NULL == source_directory_path || NULL == source_directory_pointer)
                return NULL;

        while ((file_name = (gchar*)g_dir_read_name(source_directory_pointer))) {
                if (TRUE == extension_test(extensions, file_name)) {
						g_printerr("filename=[%s]\n", file_name);
						return g_variant_new(trip_occur_format_string, file_name);
				}
        }

        return NULL;
}

void
trip_end(void)
{
	if (NULL != source_directory_path)
		g_free(source_directory_path);

	if (NULL != source_directory_pointer)
		g_dir_close(source_directory_pointer);

	if (NULL != extensions)
		g_strfreev(extensions);
}


int
trip_progress(void)
{
	return 0;
}

