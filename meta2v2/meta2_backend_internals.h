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

# ifndef M2V2_ADMIN_PREFIX_SYS
# define M2V2_ADMIN_PREFIX_SYS SQLX_ADMIN_PREFIX_SYS "m2."
# endif

# ifndef M2V2_ADMIN_PREFIX_USER
# define M2V2_ADMIN_PREFIX_USER SQLX_ADMIN_PREFIX_USER "m2."
# endif

# ifndef M2V2_ADMIN_VERSION
# define M2V2_ADMIN_VERSION M2V2_ADMIN_PREFIX_SYS "version"
# endif

# ifndef M2V2_ADMIN_QUOTA
# define M2V2_ADMIN_QUOTA M2V2_ADMIN_PREFIX_SYS "quota"
# endif

# ifndef M2V2_ADMIN_SIZE
# define M2V2_ADMIN_SIZE M2V2_ADMIN_PREFIX_SYS "usage"
# endif

# ifndef M2V2_ADMIN_VERSIONING_POLICY
# define M2V2_ADMIN_VERSIONING_POLICY M2V2_ADMIN_PREFIX_SYS "policy.version"
# endif

# ifndef M2V2_ADMIN_STORAGE_POLICY
# define M2V2_ADMIN_STORAGE_POLICY M2V2_ADMIN_PREFIX_SYS "policy.storage"
# endif

# ifndef M2V2_ADMIN_KEEP_DELETED_DELAY
# define M2V2_ADMIN_KEEP_DELETED_DELAY "keep_deleted_delay"
# endif

# ifndef META2_INIT_FLAG
# define META2_INIT_FLAG M2V2_ADMIN_PREFIX_SYS "init"
# endif

# ifndef META2_EVTFIELD_M2ADDR
#  define META2_EVTFIELD_M2ADDR "M2ADDR"
# endif
# ifndef META2_EVTFIELD_CHUNKS
#  define META2_EVTFIELD_CHUNKS "CHUNKS"
# endif

# ifndef META2_URL_LOCAL_BASE
#  define META2_URL_LOCAL_BASE "__M2V2_LOCAL_BASE__"
# endif

struct transient_s
{
	GMutex lock;
	GTree *tree;
};

struct meta2_backend_s
{
	struct meta_backend_common_s backend;

	struct service_update_policies_s *policies;

	// TODO remove this as soon as the C SDK has be refactored.
	GMutex lock_transient;
	// TODO remove this as soon as the C SDK has be refactored.
	GHashTable *transient;

	// Not owned by the backend.
	GAsyncQueue *q_notify;
	
	// Not owned by the backend
	struct hc_resolver_s *resolver;

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

GError* m2b_transient_put(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid,
		gpointer what, GDestroyNotify cleanup);

gpointer m2b_transient_get(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid , GError **err);

GError* m2b_transient_del(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid);

void m2b_transient_cleanup(struct meta2_backend_s *m2b);

#endif /*OIO_SDS__meta2v2__meta2_backend_internals_h*/
