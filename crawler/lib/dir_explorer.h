#ifndef DIR_EXPLORER_H
#define DIR_EXPLORER_H
#include <glib.h>

typedef struct dir_explorer_s
{
	gint64 dir_count;
	gint64 dir_index;
	GSList *src_dir_list;
	GSList *src_dir_cursor;
	GDir* src_dir_ptr;
} dir_explorer_t;

/**
 * Callback function for dir_next_match
 *
 * @param path A complete file or directory path
 * @return True if path matches criteria, False otherwise
 */
typedef gboolean (*dir_explorer_match)(gchar *path, gpointer user_data);

GError* dir_explore(gchar* current_path, dir_explorer_t *iter);
gint dir_progress(dir_explorer_t *exp);
gchar *dir_next_match(dir_explorer_t *exp, GPatternSpec *exclude_pattern,
		dir_explorer_match, gpointer user_data);
gchar *dir_next_file(dir_explorer_t *exp, gchar *exclude_dir_pattern);
void dir_explorer_clean(dir_explorer_t *exp);

#endif
