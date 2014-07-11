#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "hash.h"
#include "internals.h"

struct hashstr_s *
sqliterepo_hash_name(const gchar *name, const gchar *type)
{
	struct hashstr_s *result;

	GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(hash, (guint8*)name, strlen(name));
	g_checksum_update(hash, (guint8*)"", 1);
	g_checksum_update(hash, (guint8*)type, strlen(type));
	result = hashstr_create(g_checksum_get_string(hash));
	g_checksum_free(hash);

	hashstr_upper(result);
	return result;
}

