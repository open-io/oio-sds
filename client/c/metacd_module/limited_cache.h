/*
OpenIO SDS client
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

#ifndef OIO_SDS__client__c__metacd_module__limited_cache_h
# define OIO_SDS__client__c__metacd_module__limited_cache_h 1

#include <glib.h>

#define LCFLAG_NOATIME 0x00000001

typedef struct limited_cache_s limited_cache_t;

typedef gpointer (*value_copier_f) (gconstpointer v);

struct limited_cache_callbacks {
	GHashFunc hash_k;
	GEqualFunc equal_k;
	GDestroyNotify free_k;
	value_copier_f copy_k;
	GDestroyNotify free_v;
	value_copier_f copy_v;
};

limited_cache_t* limited_cache_create (gssize limit, time_t expiration,
	struct limited_cache_callbacks *callbacks, guint32 flags, GError **err);

void limited_cache_destroy (limited_cache_t *lc);

void limited_cache_clean (limited_cache_t *lc);

void limited_cache_set_limit (limited_cache_t *lc, gssize s);

gssize limited_cache_get_limit (limited_cache_t *lc);

time_t limited_cache_get_expiration (limited_cache_t *lc);

void limited_cache_put (limited_cache_t *lc, gpointer k, gpointer v);

gboolean limited_cache_has(limited_cache_t *lc, gconstpointer k, gpointer *p_val);
gpointer limited_cache_get (limited_cache_t *lc, gconstpointer k);

void limited_cache_del (limited_cache_t *lc, gconstpointer k);

void limited_cache_flush (limited_cache_t *lc);

gssize limited_cache_get_size (limited_cache_t *lc);

#endif /*OIO_SDS__client__c__metacd_module__limited_cache_h*/