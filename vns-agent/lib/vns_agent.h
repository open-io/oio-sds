#ifndef __VNS_AGENT_H__
#define __VNS_AGENT_H__

#include <metautils/lib/metatypes.h>
#include <glib.h>

#ifndef KEY_URL
# define KEY_URL "url"
#endif

#ifndef KEY_NAMESPACE
# define KEY_NAMESPACE "namespace"
#endif

#ifndef KEY_NS_INFO_FUNC
# define KEY_NS_INFO_FUNC "ns_info_func"
#endif

#define KEY_SPACE_USED_REFRESH_RATE "space_used_refresh_rate"
#define DEFAULT_SPACE_USED_REFRESH_RATE 300
#define LIMIT_MIN_SPACE_USED_REFRESH_RATE 5
#define LIMIT_MAX_SPACE_USED_REFRESH_RATE 3600

#define VNS_AGENT_ERRCODE_CONFIG     510 /*wrong configuration string*/
#define VNS_AGENT_ERRCODE_DB         511 /*could not connect to the DB*/
#define VNS_AGENT_ERRCODE_OTHER      512 /*could not connect to the DB*/

status_t vns_agent_info(char *ns_name, GError ** error);

/**
 * Inits the internal structures needed by the VNS_AGENT
 *
 * @param params 
 * @param error
 */
status_t vns_agent_init (GHashTable *params, GError **error);

/**
 * Frees all the internal structures 
 *
 * Must be called after a call to vns_agent_init().
 */
void vns_agent_close (void);

/**
 *
 */
void vns_agent_space_used_refresh(gpointer d);

#endif /*__VNS_AGENT_H__*/
