/*
OpenIO SDS meta1v2
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

#ifndef OIO_SDS__meta1v2__meta1_prefixes_h
# define OIO_SDS__meta1v2__meta1_prefixes_h 1

/**
 * @addtogroup meta1v2_prefixes 
 * @{
 */

struct sqlx_repository_s;

struct meta1_prefixes_set_s;

/** Constructor
 * @return
 */
struct meta1_prefixes_set_s* meta1_prefixes_init(void);

/** Load / Reload function.
 * @param m1ps
 * @param ns_name
 * @param local_url
 * @return NULL in case of success or the error that occured
 */
GError* meta1_prefixes_load(struct meta1_prefixes_set_s *m1ps,
		const gchar *ns_name,
		const gchar *local_url,
		GArray **updated_prefixes);

/**
 * @param m1ps
 * @param local_url
 * @return NULL in case of success or the error that occured
 */
GError* meta1_prefixes_manage_all(struct meta1_prefixes_set_s *m1ps,
		const gchar *local_url);

/** Destructor
 * @param m1ps destructor
 */
void meta1_prefixes_clean(struct meta1_prefixes_set_s *m1ps);

/**
 * Thread-safe / reentrant
 *
 * @param m1ps
 * @param bytes
 * @return
 */
gboolean meta1_prefixes_is_managed(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);

/**
 * Thread-safe / reentrant
 *
 * @param m1ps
 * @param bytes
 * @return
 */
gchar ** meta1_prefixes_get_peers(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);

/**
 * @param m1ps
 * @return
 */
gchar** meta1_prefixes_get_all(struct meta1_prefixes_set_s *m1ps);

guint8* meta1_prefixes_get_cache(struct meta1_prefixes_set_s *m1ps);

/** @} */

#endif /*OIO_SDS__meta1v2__meta1_prefixes_h*/