/*
OpenIO SDS meta2v2
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

#ifndef OIO_SDS__meta2v2__meta2_backend_internals_h
# define OIO_SDS__meta2v2__meta2_backend_internals_h 1

# include <stdlib.h>
# include <unistd.h>
# include <errno.h>

# include <glib.h>

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>
# include <sqliterepo/sqliterepo.h>
# include <sqliterepo/sqlite_utils.h>
# include <meta2v2/meta2_backend.h>
# include <meta2v2/meta2_events.h>

struct transient_s
{
	GMutex lock;
	GTree *tree;
};

struct meta2_backend_s
{
	struct meta_backend_common_s backend;
	struct service_update_policies_s *policies;
	struct hc_resolver_s *resolver;

	// TODO remove this as soon as the C SDK has be refactored.
	GMutex lock_transient;
	// TODO remove this as soon as the C SDK has be refactored.
	GHashTable *transient;

	struct { // Not owned, not to be freed
		gpointer udata;
		GError* (*hook) (gpointer udata, gchar *msg);
	} notify;

	// Trigger pre-check on alias upon a BEANS generation request
	gboolean flag_precheck_on_generate;
};

struct transient_element_s
{
	time_t expiration;
	GDestroyNotify cleanup;
	gpointer what;
};

void transient_put(GTree *t, const gchar *key, gpointer what, GDestroyNotify cleanup);

gpointer transient_get(GTree *t, const gchar *key);

void transient_del(GTree *t, const gchar *key);

void transient_tree_cleanup(GTree *t);

void transient_cleanup(struct transient_s *t);

/* ------------------------------------------------------------------------- */

GError* m2b_transient_put(struct meta2_backend_s *m2b, struct hc_url_s *url,
		gpointer what, GDestroyNotify cleanup);

gpointer m2b_transient_get(struct meta2_backend_s *m2b, struct hc_url_s *url, GError **err);

GError* m2b_transient_del(struct meta2_backend_s *m2b, struct hc_url_s *url);

void m2b_transient_cleanup(struct meta2_backend_s *m2b);

#endif /*OIO_SDS__meta2v2__meta2_backend_internals_h*/
