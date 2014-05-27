#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.meta1_raw_container"
#endif

#include <errno.h>

#include "metautils.h"

void
meta1_raw_container_clean(struct meta1_raw_container_s *r)
{
	if (!r)
		return;
	if (r->meta2) {
		g_slist_foreach(r->meta2, addr_info_gclean, NULL);
		g_slist_free(r->meta2);
	}
	g_free(r);
}

void
meta1_raw_container_gclean(gpointer r, gpointer ignored)
{
	(void) ignored;
	meta1_raw_container_clean(r);
}

