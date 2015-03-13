/*
OpenIO SDS crawler
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

#ifndef OIO_SDS__crawler__lib__dir_explorer_h
# define OIO_SDS__crawler__lib__dir_explorer_h 1

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

#endif /*OIO_SDS__crawler__lib__dir_explorer_h*/