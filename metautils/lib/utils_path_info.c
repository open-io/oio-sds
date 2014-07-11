#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils.path_info"
#endif

#include "metautils.h"

gint
path_info_to_string(const path_info_t * src, gchar * dst, gsize dstSize)
{
	if (!src || !dst)
		return -1;
	if (!dstSize)
		return 0;

	return g_snprintf(dst, dstSize, "path=%*.*s size=%"G_GINT64_FORMAT" hasSize=%i",
	    1, LIMIT_LENGTH_CONTENTPATH, src->path, src->hasSize ? src->size : 0, src->hasSize ? 1 : 0);
}

void
path_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		path_info_clean((path_info_t *) d);
}

void
path_info_clean(path_info_t * pi)
{
	if (!pi)
		return;

	if (pi->system_metadata)
		g_byte_array_free(pi->system_metadata, TRUE);
	if (pi->user_metadata)
		g_byte_array_free(pi->user_metadata, TRUE);

	if (pi->version)
		g_free(pi->version);

	pi->version = NULL;
	pi->system_metadata = NULL;
	pi->user_metadata = NULL;
	g_free(pi);
}
