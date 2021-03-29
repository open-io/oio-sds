/*
OpenIO SDS resolver
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

#ifndef OIO_SDS__resolver__hc_resolver_h
# define OIO_SDS__resolver__hc_resolver_h 1

# include <glib.h>

enum hc_resolver_flags_e
{
	HC_RESOLVER_DECACHEM0 = 0x08,
};

/* forward declarations */
struct meta1_service_url_s;
struct oio_url_s;

/* Hidden type */
struct hc_resolver_s;

/* the way any resolver locate the meta0: the proxy requires a direct touch
 * on the conscience while all the other services do it via the proxy.
 * (*result) must contains a NULL-terminated array of strings of
 * encoded meta1_url_s */
typedef GError * (*hc_resolver_m0locate_f) (
		const char *ns,
		gchar ***result,
		gint64 deadline);

/* Simple constructor */
struct hc_resolver_s* hc_resolver_create(
		hc_resolver_m0locate_f locate_m0);

/* Change the internal flags of the resolver */
void hc_resolver_configure (struct hc_resolver_s *r,
		enum hc_resolver_flags_e f);

/* Allows to resolver to prefer services that have no known problem.
 * The hook is called with the IP:PORT couple in a string. */
void hc_resolver_qualify (struct hc_resolver_s *r,
		gboolean (*qualify) (gconstpointer));

/* Allows to resolver to report for problematic services.
 * The hook is called with the IP:PORT couple in a string. */
void hc_resolver_notify (struct hc_resolver_s *r,
		void (*notify) (gconstpointer));

/* Cleanup all the internal structures. */
void hc_resolver_destroy(struct hc_resolver_s *r);

/* Applies time-based cache policies. */
guint hc_resolver_expire(struct hc_resolver_s *r);

void hc_resolver_tell (struct hc_resolver_s *r, struct oio_url_s *u,
		const char *srvtype, const char * const *urlv);

/* Applies cardinality-based cache policies. */
guint hc_resolver_purge(struct hc_resolver_s *r);

void hc_resolver_flush_csm0(struct hc_resolver_s *r);

void hc_resolver_flush_services(struct hc_resolver_s *r);

/* Fills 'result' with a NULL-terminated array on meta1 urls, those referenced
 * in the meta0/1 directory for the given service and the given URL.
 * Please note that calling this function with srvtype=meta1 will give the the
 * meta1 associated with the reference, and not the meta1 that should have been
 * returned by hc_resolve_reference_directory(). */
GError* hc_resolve_reference_service(struct hc_resolver_s *r,
		struct oio_url_s *url, const gchar *srvtype, gchar ***result,
		gint64 deadline);

/* Fills 'result' with a NULL-terminated array of IP:port couples, those
 * responsible for the given URL. */
GError* hc_resolve_reference_directory(struct hc_resolver_s *r,
		struct oio_url_s *url, gchar ***result,
		gboolean m0_only, gint64 deadline);

gboolean error_clue_for_decache(GError *err);

/* Removes from the cache the services associated to the given references.
 * It doesn't touch the directory services belonging to the reference. */
void hc_decache_reference_service(struct hc_resolver_s *r,
		struct oio_url_s *url, const gchar *srvtype);

/* Removes from the cache the directory services for the given references.
 * It doesn't touche the cache entries for the directory content. */
void hc_decache_reference(struct hc_resolver_s *r, struct oio_url_s *url);

struct hc_resolver_stats_s
{
	struct {
		gint64 count;
		guint max;
		time_t ttl;
	} csm0;

	struct {
		gint64 count;
		guint max;
		time_t ttl;
	} services;
};

void hc_resolver_info(struct hc_resolver_s *r, struct hc_resolver_stats_s *s);

#endif /*OIO_SDS__resolver__hc_resolver_h*/
