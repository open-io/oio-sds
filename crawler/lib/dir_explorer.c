#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "crawler.dir_explorer"
#endif

#include <string.h> // For memset
#include <glib.h>

#include "dir_explorer.h"


static GError* _dir_explore_rec(gchar* current_path, dir_explorer_t *exp)
{
    GError *error = NULL;
    const gchar* fn = NULL;

	GDir* sdp = g_dir_open(current_path, 0, &error);
    if (error) {
        g_prefix_error(&error, "about source directory path[%s]: ", current_path);
        return error;
    }

	if (sdp != NULL) {
		exp->src_dir_list = g_slist_prepend(exp->src_dir_list,
				g_strdup(current_path));
		exp->dir_count++;

		while ((fn = g_dir_read_name(sdp)) && (error == NULL)) {
			gchar* fn2 = g_strconcat(current_path, G_DIR_SEPARATOR_S, fn, NULL);
			if (g_file_test(fn2, G_FILE_TEST_IS_DIR))
				error = _dir_explore_rec(fn2, exp);
			g_free(fn2);
		}

		g_dir_close(sdp);
		sdp = NULL;
	}

	return error;
}

GError* dir_explore(gchar* current_path, dir_explorer_t *exp)
{
	GError *err = NULL;
	err =_dir_explore_rec(current_path, exp);
	if (err == NULL) {
		exp->dir_index = 0;
		exp->src_dir_cursor = exp->src_dir_list;
		exp->src_dir_ptr = g_dir_open(exp->src_dir_cursor->data, 0, &err);
	}
	return err;
}

gint dir_progress(dir_explorer_t *exp)
{
	if (exp->dir_count == 0)
		return 0;
	return (exp->dir_index * 100) / exp->dir_count;
}

gchar *dir_next_match(dir_explorer_t *exp, GPatternSpec *exclude_pattern,
		dir_explorer_match match, gpointer udata)
{
	const gchar* file_name = NULL;

	if (NULL == exp->src_dir_ptr)
		return NULL;

	while (exp->src_dir_cursor != NULL) {
		gchar* temp_buf_src_dir = exp->src_dir_cursor->data;
		gchar *dname = g_path_get_basename(temp_buf_src_dir);
		if (!exclude_pattern ||
				!g_pattern_match_string(exclude_pattern, dname)) {
			// Iterate over files in current directory
			while ((file_name = g_dir_read_name(exp->src_dir_ptr))) {
				gchar* file_path = g_strconcat(temp_buf_src_dir,
						G_DIR_SEPARATOR_S, (gchar*)file_name, NULL);
				if (match(file_path, udata)) {
					g_free(dname);
					return file_path;
				}
				g_free(file_path);
			}
		}
		g_free(dname);

		if (exp->src_dir_ptr != NULL) {
			g_dir_close(exp->src_dir_ptr);
			exp->src_dir_ptr = NULL;
		}

		// Find a readable directory
		do {
			exp->dir_index++;
			exp->src_dir_cursor = exp->src_dir_cursor->next;
			if (!exp->src_dir_cursor || !(exp->src_dir_cursor->data))
				break;
			else
				exp->src_dir_ptr = g_dir_open(exp->src_dir_cursor->data,
						0, NULL);

		} while (exp->src_dir_ptr == NULL);
	}

	return NULL;
}

gchar* dir_next_file(dir_explorer_t *exp, gchar *exclude_dir_pattern)
{
	gboolean _match_files(gchar *path, gpointer udata)
	{
		(void) udata;
		return !g_file_test(path, G_FILE_TEST_IS_DIR);
	}
	GPatternSpec *exclude_pattern = NULL;
	if (exclude_dir_pattern)
		exclude_pattern = g_pattern_spec_new(exclude_dir_pattern);
	gchar *ret = dir_next_match(exp, exclude_pattern, _match_files, NULL);
	if (exclude_pattern)
		g_pattern_spec_free(exclude_pattern);
	return ret;
}

void dir_explorer_clean(dir_explorer_t *exp)
{
	if (exp == NULL)
		return;

	if (exp->src_dir_list != NULL) {
		g_slist_free_full(exp->src_dir_list, g_free);
	}
	if (exp->src_dir_ptr != NULL) {
		g_dir_close(exp->src_dir_ptr);
	}
	memset(exp, 0, sizeof(dir_explorer_t));
}

