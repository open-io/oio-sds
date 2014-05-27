#ifndef _CONFIG_H
#define _CONFIG_H

#include <glib.h>

#define USER_KEY                        "user"
#define GROUP_KEY                       "group"
#define SVC_CHECK_KEY                   "service_check"
#define SVC_CHECK_FREQ_KEY              "service_check_freq"

#define STATS_PERIOD                    "period_local_stats"

# define SOCK_TIMEOUT 10000

# define DEFAULT_SVC_CHECK       TRUE
# define DEFAULT_SVC_CHECK_FREQ  1

#define DEFAULT_BROKEN_MANAGE  TRUE
#define DEFAULT_BROKEN_FREQ    30
#define KEY_BROKEN_MANAGE      "enable_broken_elements"
#define KEY_BROKEN_FREQ_PUSH   "period_broken_push"
#define KEY_BROKEN_FREQ_GET    "period_broken_get"

// Default value for the next 5
#define DEFAULT_CS_UPDATE_FREQ           5
#define CS_DEFAULT_FREQ_KEY              "cluster_update_freq"

#define CS_GET_NS_PERIOD_KEY            "period_get_ns"
#define CS_GET_SRVLIST_PERIOD_KEY       "period_get_srv"
#define CS_GET_SRVTYPE_PERIOD_KEY       "period_get_srvtype"
#define CS_GET_EVTCFG_PERIOD_KEY        "period_get_evtconfig"
#define CS_PUSH_SRVLIST_PERIOD_KEY      "period_push_srv"

#define EVENTS_MODE_FILE_KEY            "events.mode.file"
#define EVENTS_MODE_DIR_KEY             "events.mode.dir"
#define EVENTS_SPOOL_DIR_KEY            "events.spool.dir"
#define EVENTS_SPOOL_SIZE_KEY           "events.spool.size"
#define EVENTS_MANAGE_ENABLE_KEY        "events.manage.enable"
#define EVENTS_RECEIVE_ENABLE_KEY       "events.receive.enable"
#define EVENTS_MAXPENDING_KEY           "events.max_pending"
#define EVENTS_DELAY_INCOMING_KEY       "events.incoming_delay"

#define EVENTS_MODE_FILE_DEFAULT        0444
#define EVENTS_MODE_DIR_DEFAULT         0755
#define EVENTS_SPOOL_DIR_DEFAULT        "/GRID/common/spool"
#define EVENTS_SPOOL_SIZE_DEFAULT       0
#define EVENTS_SPOOL_SIZE_DEFAULT       0
#define EVENTS_MANAGE_ENABLE_DEFAULT    1
#define EVENTS_RECEIVE_ENABLE_DEFAULT   1
#define EVENTS_MAXPENDING_ACTIONS_DEFAULT 500U
#define EVENTS_MAXPENDING_DEFAULT         100U
#define EVENTS_DELAY_INCOMING_DEFAULT   0L

#define NAME_SECTION_SERVER_INET "server.inet"
#define PORT_KEY "port"
#define BACKLOG_KEY "backlog"

#define UNIX_SOCK_DEFAULT_GID            -1
#define UNIX_SOCK_DEFAULT_UID            -1
#define UNIX_SOCK_DEFAULT_MODE         0660

#define UNIX_SOCK_KEY_GID           "unix_sock.gid"
#define UNIX_SOCK_KEY_UID           "unix_sock.uid"
#define UNIX_SOCK_KEY_MODE          "unix_sock.mode"

int parse_config(const char* config_file, GHashTable *params, GError **error);

#endif	/* _CONFIG_H */
