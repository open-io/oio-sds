/**
 * @file metautils.h
 * The metautils API
 */

#ifndef __METAUTILS__H__
#define __METAUTILS__H__

/**
 * @defgroup metautils_utils Metautils
 * @ingroup metautils
 * @{
 * Coin!
 * }@
 */

# include <metautils/lib/metautils_macros.h>

# include <sys/types.h>
# include <sys/socket.h>

# include <glib.h>
# include <glib/gstdio.h>

# include <metautils/lib/metatypes.h>

# include <metautils/lib/metautils_bits.h>
# include <metautils/lib/metautils_errors.h>
# include <metautils/lib/metautils_strings.h>
# include <metautils/lib/metautils_sockets.h>
# include <metautils/lib/metautils_containers.h>
# include <metautils/lib/metautils_gba.h>
# include <metautils/lib/metautils_resolv.h>
# include <metautils/lib/metautils_loggers.h>
# include <metautils/lib/metautils_hashstr.h>
# include <metautils/lib/metautils_task.h>
# include <metautils/lib/metautils_l4v.h>
# include <metautils/lib/metautils_manifest.h>
# include <metautils/lib/metautils_svc_policy.h>

# include <metautils/lib/metatype_cid.h>
# include <metautils/lib/metatype_m0info.h>
# include <metautils/lib/metatype_nsinfo.h>
# include <metautils/lib/metatype_srvinfo.h>
# include <metautils/lib/metatype_m1url.h>
# include <metautils/lib/metatype_addrinfo.h>
# include <metautils/lib/metatype_v140.h>
# include <metautils/lib/metatype_kv.h>
# include <metautils/lib/metatype_metadata.h>
# include <metautils/lib/metatype_acl.h>

# include <metautils/lib/hc_url.h>
# include <metautils/lib/event_config.h>
# include <metautils/lib/lrutree.h>
# include <metautils/lib/storage_policy.h>
# include <metautils/lib/common_main.h>
# include <metautils/lib/volume_lock.h>
# include <metautils/lib/gridd_client.h>
# include <metautils/lib/gridd_client_ext.h>
# include <metautils/lib/gridd_client_pool.h>
# include <metautils/lib/grid_storage_client_stat.h>
# include <metautils/lib/expr.h>
# include <metautils/lib/lb.h>

#endif /*__METAUTILS__H__*/
