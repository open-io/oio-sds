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

#include <string.h>
#include "./conscience_srvtype.h"
#include "./conscience_srv.h"
#include "./conscience.h"

static void
_lock_rw(GStaticRWLock * lock, char mode)
{
	if (mode == 'w' || mode == 'W')
		g_static_rw_lock_writer_lock(lock);
	else
		g_static_rw_lock_reader_lock(lock);
}

static void
_unlock_rw(GStaticRWLock * lock)
{
	if (lock->have_writer)
		g_static_rw_lock_writer_unlock(lock);
	else
		g_static_rw_lock_reader_unlock(lock);
}

struct conscience_srvtype_s *
conscience_get_locked_srvtype(struct conscience_s *conscience, GError ** error,
    const gchar * type, enum mode_e mode, char lock_mode)
{
	EXTRA_ASSERT(conscience != NULL);
	struct conscience_srvtype_s *srvtype;

	/* lock the conscience service-types storage. If an auto-creation is wanted,
	 * and the service type does not exist, we force a lock with writer rights
	 * because the storage itself will be modified during the creation. */
	conscience_lock_srvtypes(conscience, 'r');
	srvtype = conscience_get_srvtype(conscience, error, type, MODE_STRICT);
	if (!srvtype && mode == MODE_AUTOCREATE) {
		conscience_unlock_srvtypes(conscience);

		conscience_lock_srvtypes(conscience, 'w');
		srvtype = conscience_get_srvtype(conscience, error, type, MODE_AUTOCREATE);
	}

	if (!srvtype) {
		GSETERROR(error, "Service type not found, unlocking the conscience");
		conscience_unlock_srvtypes(conscience);
		return NULL;
	}

	/*now lock the service type itself */
	_lock_rw(&(srvtype->rw_lock), lock_mode);
	return srvtype;
}

void
conscience_release_locked_srvtype(struct conscience_srvtype_s *srvtype)
{
	EXTRA_ASSERT(srvtype != NULL);
	_unlock_rw(&(srvtype->rw_lock));
	_unlock_rw(&(srvtype->conscience->rwlock_srv));
}

void
conscience_lock_srvtypes(struct conscience_s *conscience, char lock_mode)
{
	_lock_rw(&(conscience->rwlock_srv), lock_mode);
}

void
conscience_unlock_srvtypes(struct conscience_s *conscience)
{
	_unlock_rw(&(conscience->rwlock_srv));
}

/* ------------------------------------------------------------------------- */

struct conscience_s *
conscience_create(void)
{
	struct conscience_s *conscience = g_malloc0(sizeof(struct conscience_s));
	namespace_info_init (&conscience->ns_info);

	g_static_rw_lock_init(&(conscience->rwlock_srv));

	conscience->srvtypes = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) conscience_srvtype_destroy);
	if (!conscience->srvtypes) {
		conscience_destroy(conscience);
		return NULL;
	}

	conscience->default_srvtype = conscience_srvtype_create(conscience, "default");
	if (!conscience->default_srvtype) {
		conscience_destroy(conscience);
		return NULL;
	}

	return conscience;
}

struct conscience_s*
conscience_create_named(const gchar *ns, GError **error)
{
	EXTRA_ASSERT(oio_str_is_set(ns));
	struct conscience_s *conscience = conscience_create();
	g_strlcpy (conscience->ns_info.name, ns, sizeof(conscience->ns_info.name));
	return conscience;
}

void
conscience_destroy(struct conscience_s *conscience)
{
	if (!conscience)
		return;

	g_static_rw_lock_free(&(conscience->rwlock_srv));

	if (conscience->srvtypes)
		g_hash_table_destroy(conscience->srvtypes);

	if (conscience->default_srvtype)
		conscience_srvtype_destroy(conscience->default_srvtype);

	namespace_info_clear(&conscience->ns_info);

	memset(conscience, 0x00, sizeof(struct conscience_s));
	g_free(conscience);
}

/* ------------------------------------------------------------------------- */

struct conscience_srvtype_s *
conscience_get_srvtype(struct conscience_s *conscience, GError ** error, const char *type, enum mode_e mode)
{
	struct conscience_srvtype_s *srvtype;

	if (!conscience || !type) {
		GSETERROR(error, "Invalid parameter (conscience=%p type=%s)", conscience, type);
		return NULL;
	}

	srvtype = g_hash_table_lookup(conscience->srvtypes, type);
	if (srvtype)
		return srvtype;

	if (mode == MODE_AUTOCREATE) {
		GRID_NOTICE("[NS=%s][SRVTYPE=%s] Autocreation wanted!", conscience_get_nsname(conscience), type);
		srvtype = conscience_srvtype_create(conscience, type);
		if (!srvtype) {
			GSETERROR(error, "ServiceType allocation failure");
			return NULL;
		}
		g_hash_table_insert(conscience->srvtypes, g_strdup(type), srvtype);
		return srvtype;
	}

	if (mode == MODE_FALLBACK)
		return conscience_get_default_srvtype(conscience);

	return NULL;
}

struct conscience_srvtype_s *
conscience_get_default_srvtype(struct conscience_s *conscience)
{
	EXTRA_ASSERT(conscience != NULL);
	return conscience->default_srvtype;
}

const gchar *
conscience_get_nsname(struct conscience_s *conscience)
{
	EXTRA_ASSERT(conscience != NULL);
	return conscience->ns_info.name;
}

GSList *
conscience_get_srvtype_names(struct conscience_s * conscience, GError ** error)
{
	EXTRA_ASSERT(conscience != NULL);

	GHashTableIter iterator;
	gpointer k, v;
	GSList *names = NULL;
	g_hash_table_iter_init(&iterator, conscience->srvtypes);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		struct conscience_srvtype_s *srvtype = v;
		gchar *str = g_strndup(srvtype->type_name, sizeof(srvtype->type_name));
		names = g_slist_prepend(names, str);
	}
	return names;
}

gboolean
conscience_run_srvtypes(struct conscience_s * conscience, GError ** error, guint32 flags,
    gchar ** names_array, service_callback_f * callback, gpointer udata)
{
	EXTRA_ASSERT(conscience != NULL);
	EXTRA_ASSERT(names_array != NULL);
	EXTRA_ASSERT(callback != NULL);

	gboolean rc = TRUE;
	register guint32 real_flags;
	GPtrArray *array_srvtypes = g_ptr_array_sized_new(8);

	/* XXX start of critical version */
	if (flags & SRVTYPE_FLAG_LOCK_ENABLE)
		conscience_lock_srvtypes(conscience, 'r');

	/*We do not run any service type if we are not sure that all exist */
	for (gchar **name = names_array; *name; name++) {
		struct conscience_srvtype_s *srvtype;

		srvtype = conscience_get_srvtype(conscience, error, *name, MODE_STRICT);
		if (!srvtype) {
			rc = FALSE;
			GSETCODE(error, CODE_SRVTYPE_NOTMANAGED, "Service type [%s] not managed", *name);
			goto unlock_and_exit;
		}
		g_ptr_array_add(array_srvtypes, srvtype);
	}

	/*we remove the additional call, we just want one call at the end */
	real_flags = flags & ~SRVTYPE_FLAG_ADDITIONAL_CALL;

	for (guint i = 0, max = array_srvtypes->len; rc && i < max; i++) {
		struct conscience_srvtype_s *srvtype;

		srvtype = g_ptr_array_index(array_srvtypes, i);

		if (flags & SRVTYPE_FLAG_LOCK_ENABLE) {
			/* XXX start of critical section */
			if (flags & SRVTYPE_FLAG_LOCK_WRITER)
				g_static_rw_lock_writer_lock(&(srvtype->rw_lock));
			else
				g_static_rw_lock_reader_lock(&(srvtype->rw_lock));
		}

		rc = conscience_srvtype_run_all(srvtype, error, real_flags, callback, udata);

		if (flags & SRVTYPE_FLAG_LOCK_ENABLE) {
			if (flags & SRVTYPE_FLAG_LOCK_WRITER)
				g_static_rw_lock_writer_unlock(&(srvtype->rw_lock));
			else
				g_static_rw_lock_reader_unlock(&(srvtype->rw_lock));
			/* XXX end of critical section */
		}

		if (!rc) {
			GSETERROR(error, "An error occured while running the services of type [%s]", srvtype->type_name);
			goto unlock_and_exit;
		}
	}

	if (rc && (flags & SRVTYPE_FLAG_ADDITIONAL_CALL))
		rc = callback(NULL, udata);

      unlock_and_exit:

	if (flags & SRVTYPE_FLAG_LOCK_ENABLE)
		conscience_unlock_srvtypes(conscience);
	/* XXX end of critical version */

	g_ptr_array_free(array_srvtypes, TRUE);
	return rc;
}
