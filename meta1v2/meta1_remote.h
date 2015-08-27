/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

struct oio_url_s;

GError * meta1v2_remote_create_reference (const char *m1, struct oio_url_s *url);

GError * meta1v2_remote_delete_reference(const char *m1, struct oio_url_s *url,
		gboolean force);

GError * meta1v2_remote_has_reference(const char *m1, struct oio_url_s *url,
		struct oio_url_s ***out);


GError * meta1v2_remote_list_reference_services(const char *m1,
		struct oio_url_s *url, const char *srvtype, gchar ***out);

GError * meta1v2_remote_link_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gboolean dryrun, gboolean ac, gchar ***out);

GError * meta1v2_remote_unlink_service(const char *m1, struct oio_url_s *url,
		const char *srvtype);

GError * meta1v2_remote_unlink_one_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gint64 seqid);

GError * meta1v2_remote_poll_reference_service(const char *m1, struct oio_url_s *url,
		const char *srvtype, gboolean dryrun, gboolean ac, gchar ***out);

GError * meta1v2_remote_force_reference_service(const char *m1, struct oio_url_s *url,
		const char *m1url, gboolean ac, gboolean force);

GError * meta1v2_remote_configure_reference_service(const char *m1, struct oio_url_s *url,
		const char *m1url);


GError * meta1v2_remote_reference_get_property(const char *m1, struct oio_url_s *url,
		gchar **keys, gchar ***result);

GError * meta1v2_remote_reference_set_property(const char *m1, struct oio_url_s *url,
		gchar **pairs, gboolean flush);

GError * meta1v2_remote_reference_del_property(const char *m1, struct oio_url_s *url,
		gchar **keys);

GError * meta1v2_remote_list_services_by_prefix(const char *to, struct oio_url_s *url,
		gchar ***out);

GError * meta1v2_remote_get_prefixes(const char *m1, gchar ***result);

#endif /*OIO_SDS__meta1v2__meta1_remote_h*/
