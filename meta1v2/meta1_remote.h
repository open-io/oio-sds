/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__meta1v2__meta1_remote_h
# define OIO_SDS__meta1v2__meta1_remote_h 1

# include <glib.h>

struct oio_url_s;

/**
 * @param properties A NULL-terminated sequence of strings where: [i*2] is the
 *					 i-th key and [(i*2)+1] is the i-th value
 * @return
 */
GError * meta1v2_remote_create_reference(const char *m1, struct oio_url_s *url,
		gchar **properties, gint64 deadline);

GError * meta1v2_remote_delete_reference(const char *m1, struct oio_url_s *url,
		gboolean force, gint64 deadline);

GError * meta1v2_remote_list_reference_services(const char *m1,
		struct oio_url_s *url, const char *srvtype, gchar ***out, gint64 deadline);

GError * meta1v2_remote_link_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gboolean ac, gchar ***out, gint64 deadline);

GError * meta1v2_remote_unlink_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gint64 deadline);

GError * meta1v2_remote_unlink_one_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gint64 seqid, gint64 deadline);

GError * meta1v2_remote_renew_reference_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, const char *last, gboolean ac, gchar ***out, gint64 deadline);

GError * meta1v2_remote_force_reference_service(const char *m1, struct oio_url_s *url,
		const char *m1url, gboolean ac, gboolean force, gint64 deadline);


GError * meta1v2_remote_reference_get_property(const char *m1, struct oio_url_s *url,
		gchar **keys, gchar ***result, gint64 deadline);

GError * meta1v2_remote_reference_set_property(const char *m1, struct oio_url_s *url,
		gchar **pairs, gboolean flush, gint64 deadline);

GError * meta1v2_remote_reference_del_property(const char *m1, struct oio_url_s *url,
		gchar **keys, gint64 deadline);

GError * meta1v2_remote_relink_service(const char *m1, struct oio_url_s *url,
		const char *kept, const char *replaced,
		gboolean dryrun, gchar ***out, gint64 deadline);


GError * meta1v2_remote_list_services_by_prefix(const char *to, struct oio_url_s *url,
		gchar ***out, gint64 deadline);

GError * meta1v2_remote_get_prefixes(const char *m1, gchar ***result, gint64 deadline);

#endif /*OIO_SDS__meta1v2__meta1_remote_h*/
