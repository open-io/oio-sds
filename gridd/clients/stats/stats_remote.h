#ifndef __SRVSTATS_STATS_REMOTE_H__
# define __SRVSTATS_STATS_REMOTE_H__
# include <glib.h>
# include <metautils/lib/metatypes.h>

GHashTable* gridd_stats_remote (addr_info_t *ai, gint ms, GError **err,
	const gchar *pattern);

#endif /*__SRVSTATS_STATS_REMOTE_H__*/
