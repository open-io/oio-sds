#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api"
#endif

#include <string.h>
#include "./conscience_broken_holder.h"
#include "./conscience_srvtype.h"
#include "./conscience_srv.h"
#include "./conscience.h"

static inline void
_lock_rw(GStaticRWLock * lock, char mode)
{
	if (mode == 'w' || mode == 'W')
		g_static_rw_lock_writer_lock(lock);
	else
		g_static_rw_lock_reader_lock(lock);
}

static inline void
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
	struct conscience_srvtype_s *srvtype;

	if (!conscience) {
		GSETERROR(error, "Invalid parameter");
		return NULL;
	}

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
	if (!srvtype) {
		ERROR("Invalid parameter");
		return;
	}

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

void
conscience_lock_broken_elements(struct conscience_s *conscience, char lock_mode)
{
	(void)lock_mode;
	if (conscience)
		g_static_rec_mutex_lock(&(conscience->srmut_brk));
}

void
conscience_unlock_broken_elements(struct conscience_s *conscience)
{
	if (conscience)
		g_static_rec_mutex_unlock(&(conscience->srmut_brk));
}

/* ------------------------------------------------------------------------- */

struct conscience_s *
conscience_create(void)
{
	struct conscience_s *conscience;

	conscience = g_try_malloc0(sizeof(struct conscience_s));
	if (!conscience)
		return NULL;

	g_static_rw_lock_init(&(conscience->rwlock_srv));
	g_static_rec_mutex_init(&(conscience->srmut_brk));

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

	conscience->broken_elements = conscience_create_broken_holder(conscience);
	if (!conscience->broken_elements) {
		conscience_destroy(conscience);
		return NULL;
	}

	return conscience;
}

struct conscience_s*
conscience_create_named(const gchar *ns_name, GError **error)
{
	struct conscience_s *conscience;

	if (!ns_name || !*ns_name) {
		GSETERROR(error,"NULL/empty namespace name (%p)", ns_name);
		return NULL;
	}

	conscience = conscience_create();
	if (!conscience) {
		GSETERROR(error,"Memory allocation failure");
		return NULL;
	}
	
	g_strlcpy(conscience->ns_info.name, ns_name, sizeof(conscience->ns_info.name));
	conscience->event_handler = gridcluster_eventhandler_create(ns_name, error, NULL, NULL);
	return conscience;
}

void
conscience_destroy(struct conscience_s *conscience)
{
	if (!conscience)
		return;

	g_static_rw_lock_free(&(conscience->rwlock_srv));
	g_static_rec_mutex_free(&(conscience->srmut_brk));

	if (conscience->srvtypes)
		g_hash_table_destroy(conscience->srvtypes);

	if (conscience->broken_elements)
		conscience_destroy_broken_holder(conscience->broken_elements);

	if (conscience->default_srvtype)
		conscience_srvtype_destroy(conscience->default_srvtype);

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
		NOTICE("[NS=%s][SRVTYPE=%s] Autocreation wanted!", conscience_get_namespace(conscience), type);
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
	if (!conscience)
		return NULL;
	return conscience->default_srvtype;
}

const gchar *
conscience_get_namespace(struct conscience_s *conscience)
{
	if (!conscience)
		return "";
	return conscience->ns_info.name;
}

GSList *
conscience_get_srvtype_names(struct conscience_s * conscience, GError ** error)
{
	GHashTableIter iterator;
	gpointer k, v;
	GSList *names;

	if (!conscience) {
		GSETERROR(error, "Invalid conscience parameter");
		return NULL;
	}
	names = NULL;
	g_hash_table_iter_init(&iterator, conscience->srvtypes);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		struct conscience_srvtype_s *srvtype;
		gchar *str;

		srvtype = v;
		str = g_strndup(srvtype->type_name, sizeof(srvtype->type_name));
		names = g_slist_prepend(names, str);
	}
	return names;
}

gboolean
conscience_run_srvtypes(struct conscience_s * conscience, GError ** error, guint32 flags,
    gchar ** names_array, service_callback_f * callback, gpointer udata)
{
	gboolean rc;
	register guint i, max;
	register guint32 real_flags;
	gchar **name;
	GPtrArray *array_srvtypes;

	if (!conscience || !names_array || !callback) {
		GSETERROR(error, "Invalid parameter (conscience=%p names_array=%p callback=%p)",
		    conscience, names_array, callback);
		return FALSE;
	}

	array_srvtypes = g_ptr_array_sized_new(8);
	rc = TRUE;

	/* XXX start of critical version */
	if (flags & SRVTYPE_FLAG_LOCK_ENABLE)
		conscience_lock_srvtypes(conscience, 'r');

	/*We do not run any service type if we are not sure that all exist */
	for (name = names_array; *name; name++) {
		struct conscience_srvtype_s *srvtype;

		srvtype = conscience_get_srvtype(conscience, error, *name, MODE_STRICT);
		if (!srvtype) {
			rc = FALSE;
			GSETCODE(error, 460, "Service type [%s] not managed", *name);
			goto unlock_and_exit;
		}
		g_ptr_array_add(array_srvtypes, srvtype);
	}

	/*we remove the additional call, we just want one call at the end */
	real_flags = flags & ~SRVTYPE_FLAG_ADDITIONAL_CALL;

	for (i = 0, max = array_srvtypes->len; rc && i < max; i++) {
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
