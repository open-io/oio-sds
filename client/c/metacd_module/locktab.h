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

#ifndef __LOCKTAB_H__
# define __LOCKTAB_H__
# include <glib.h>

typedef struct lockelement_s lockelement;

typedef struct locktab_s locktab;

typedef gboolean (*locktab_callback_f)(lockelement *le, gpointer ctx_data,
	GError **err);

typedef gpointer (*key_copy_f) (gconstpointer p);

struct locktab_ctx_s {
	gpointer ctx_data;
	locktab_callback_f on_destroy;

	key_copy_f copy_key;
	GHashFunc hash_key;
	GEqualFunc equal_key;
	GDestroyNotify free_key;
};

gsize locktab_get_struct_size(void);

void locktab_init(locktab *lt, gsize nb_cond, struct locktab_ctx_s *ctx);

void locktab_fini(locktab *lt);

void locktab_unlock(locktab *lt, gpointer key);

lockelement* locktab_lock(locktab *lt, gpointer key);

gpointer lockelement_get_user_data(lockelement *le);

/**
 * Returns the previous user_data, or 'u' if 'le' is invalid
 */
gpointer lockelement_set_user_data(lockelement *le, gpointer u);

gpointer lockelement_get_key(lockelement *le);

#endif /*__LOCKTAB_H__*/
