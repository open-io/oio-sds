#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils.score"
#endif

#include "metautils.h"

gint
score_to_string(const score_t * src, gchar * dst, gsize dstSize)
{
	if (!src || !dst)
		return -1;

	if (dstSize == 0)
		return 0;

	return g_snprintf(dst, dstSize, "%i:%i", src->value, src->timestamp);
}

