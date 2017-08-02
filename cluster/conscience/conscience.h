/*
OpenIO SDS cluster conscience
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

#ifndef OIO_SDS__cluster__conscience__conscience_h
# define OIO_SDS__cluster__conscience__conscience_h 1

/**
 * @addtogroup gridcluster_backend
 * @{
 */

# include <metautils/lib/metatypes.h>

# include <cluster/conscience/conscience_srvtype.h>
# include <cluster/conscience/conscience_srv.h>

/**
 * Provide this value OR'ed in the conscience_srvtype_run_all() flags to
 * call the callback function with a NULL service when all the services
 * have been run.
 */
#define SRVTYPE_FLAG_ADDITIONAL_CALL 0x00000002

#define SRVTYPE_FLAG_LOCK_ENABLE     0x00000004

#define SRVTYPE_FLAG_LOCK_WRITER     0x00000008

struct conscience_s
{
	namespace_info_t ns_info;

	/*Data about the configuration elements sent to each agent */
	GStaticRWLock rwlock_srv;
	GHashTable *srvtypes;/**<Maps (gchar*) to (struct conscience_srvtype_s*)*/
	struct conscience_srvtype_s *default_srvtype;
};

enum mode_e
{
	MODE_AUTOCREATE,
	MODE_FALLBACK,
	MODE_STRICT
};

/* ------------------------------------------------------------------------- */

struct conscience_s *conscience_create(void);

struct conscience_s *conscience_create_named(const gchar *ns_name, GError **error);

void conscience_destroy(struct conscience_s *conscience);

struct conscience_srvtype_s *conscience_get_locked_srvtype(
		struct conscience_s *conscience, GError ** error,
		const gchar * type, enum mode_e mode, char lock_mode);

void conscience_release_locked_srvtype(struct conscience_srvtype_s *srvtype);

/**
 * @param lock_mode 'w','W','r','R'
 */
void conscience_lock_srvtypes(struct conscience_s *conscience, char lock_mode);

void conscience_unlock_srvtypes(struct conscience_s *conscience);

struct conscience_srvtype_s *conscience_get_srvtype(struct conscience_s *conscience, GError ** error,
    const gchar * type, enum mode_e mode);

struct conscience_srvtype_s *conscience_get_default_srvtype(
		struct conscience_s *conscience);

const gchar *conscience_get_nsname(struct conscience_s *conscience);

GSList *conscience_get_srvtype_names(struct conscience_s *conscience,
		GError ** error);

gboolean conscience_run_srvtypes(struct conscience_s * conscience,
		GError **error, guint32 flags, gchar ** names_array,
		service_callback_f * callback, gpointer udata);

#endif /*OIO_SDS__cluster__conscience__conscience_h*/
