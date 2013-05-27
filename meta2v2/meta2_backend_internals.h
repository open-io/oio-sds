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

#ifndef META2V2_INTERNALS__H
# define META2V2_INTERNALS__H 1
# ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN "m2"
# endif
# include <stdlib.h>
# include <unistd.h>
# include <errno.h>
# include <glib.h>
# include "../metautils/lib/metautils.h"
# include "../metautils/lib/metacomm.h"
# include "../metautils/lib/resolv.h"
# include "../metautils/lib/lb.h"
# include "../metautils/lib/loggers.h"
# include "../metautils/lib/svc_policy.h"
# include "../metautils/lib/hc_url.h"
# include "../sqliterepo/sqliterepo.h"
# include "./meta2_backend.h"

# ifndef M2V2_KEY_VERSION
#  define M2V2_KEY_VERSION "m2vers"
# endif

# ifndef M2V2_KEY_QUOTA
#  define M2V2_KEY_QUOTA "quota"
# endif

# ifndef M2V2_KEY_SIZE
#  define M2V2_KEY_SIZE "container_size"
# endif

# ifndef M2V2_KEY_VERSIONING_POLICY
#  define M2V2_KEY_VERSIONING_POLICY "versioning_policy"
# endif

# ifndef  META2_EVTFIELD_NAMESPACE
#  define META2_EVTFIELD_NAMESPACE "NS"
# endif
# ifndef  META2_EVTFIELD_CNAME
#  define META2_EVTFIELD_CNAME "CNAME"
# endif
# ifndef  META2_EVTFIELD_CPATH
#  define META2_EVTFIELD_CPATH "CPATH"
# endif
# ifndef  META2_EVTFIELD_CID
#  define META2_EVTFIELD_CID "CID"
# endif
# ifndef  META2_EVTFIELD_RAWCONTENT
#  define META2_EVTFIELD_RAWCONTENT "RAW"
# endif
# ifndef  META2_EVTFIELD_RAWCONTENT_V2
#  define META2_EVTFIELD_RAWCONTENT_V2 "RAW.V2"
# endif
# ifndef META2_EVTFIELD_CEVT
#  define META2_EVTFIELD_CEVT "CEVT"
# endif
# ifndef META2_EVTFIELD_CEVTID
#  define META2_EVTFIELD_CEVTID "CEVTID"
# endif
# ifndef META2_EVTFIELD_URL
#  define META2_EVTFIELD_URL "URL"
# endif

struct meta2_backend_s
{
	gchar ns_name[256]; /* Read-only */

	struct sqlx_repository_s *repo;

	struct service_update_policies_s *policies;

	GMutex *lock;
	GTree  *tree_lb; /* maps names to services iterators */

	GMutex *lock_ns_info;
	struct namespace_info_s ns_info;

	GMutex *lock_transient;
	GTree *tree_transient;

	/* Events management */
	struct {
		GMutex *lock;
		gint64 seq;
		gchar *dir;
		gboolean agregate;
		time_t last_error;
		time_t delay_on_error;
	} event;
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

void transient_cleanup(GTree *t);

/* ------------------------------------------------------------------------- */

GError* m2b_transient_put(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid,
		gpointer what, GDestroyNotify cleanup);

gpointer m2b_transient_get(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid , GError **err);

GError* m2b_transient_del(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid);

void m2b_transient_cleanup(struct meta2_backend_s *m2b);

#endif /* META2V2_INTERNALS__H */
