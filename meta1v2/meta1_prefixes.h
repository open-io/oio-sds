/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

struct sqlx_repository_s;
struct meta1_prefixes_set_s;

struct meta1_prefixes_set_s* meta1_prefixes_init(void);

GError* meta1_prefixes_load(struct meta1_prefixes_set_s *m1ps,
		const char *ns_name, const char *local_url,
		GArray **updated_prefixes, gboolean *meta0_ok,
		guint digits, gint64 deadline);

void meta1_prefixes_clean(struct meta1_prefixes_set_s *m1ps);

/* For testing purposes */
void meta1_prefixes_manage_all(struct meta1_prefixes_set_s *m1ps);

gboolean meta1_prefixes_is_managed(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);

gchar ** meta1_prefixes_get_peers(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);

gchar** meta1_prefixes_get_all(struct meta1_prefixes_set_s *m1ps);

GError * meta1_prefixes_check_coalescence(const guint8 *cache,
		const guint8 *bytes, guint digits);

GError * meta1_prefixes_check_coalescence_all(const guint8 *cache,
		guint digits);

#endif /*OIO_SDS__meta1v2__meta1_prefixes_h*/
