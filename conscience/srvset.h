/*
OpenIO SDS metautils
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef OIO_SDS__conscience__srvset_h
# define OIO_SDS__conscience__srvset_h 1
# include <glib.h>

struct service_info_s;

struct srvset_s;

typedef struct srvset_s srvset_t;

/* constructor */
srvset_t* srvset_new (void);

/* destructor */
void srvset_clean (srvset_t *ss);

/* remove all the items without freeing them */
void srvset_steal (srvset_t *ss);

/* flush by elderness */
void srvset_purge (srvset_t *ss, time_t pivot);

void srvset_purge_type (srvset_t *ss, const char *type);

/* DO NOT reuse <si> after */
struct service_info_s* srvset_push_and_clean (srvset_t *ss, struct service_info_s *si);

/* checks there is an item for key <k> */
gboolean srvset_has (srvset_t *ss, const char *k);

/* iterator on the types specified in <types> (come-separated string) */
guint srvset_run (srvset_t *ss, const char *types, void (*cb)(struct service_info_s *));

/* return the number of items in the set */
guint srvset_count (srvset_t *ss);

/* get a DIRECT POINTER, please be careful and know what you are doing */
struct service_info_s * srvset_get (srvset_t *ss, const char *k);
struct service_info_s * srvset_get_iso (srvset_t *ss, struct service_info_s *si);

/* removes the given element */
void srvset_delete (srvset_t *ss, const char *k);
void srvset_delete_iso (srvset_t *ss, struct service_info_s *si);

#endif /*OIO_SDS__conscience__srvset_h*/
