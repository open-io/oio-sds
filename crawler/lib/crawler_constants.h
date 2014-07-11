#ifndef CRAWLER_CONSTANTS_H
#define CRAWLER_CONSTANTS_H

#define SHORT_BUFFER_SIZE        512 /* bytes */
#define MAX_ACTION_TIMEOUT         5 /* seconds */
#define SLOW_VALUE                 3 /* seconds */
#define META2_CONNECTION_TIMEOUT   5 /* seconds */
#define LIMIT_LENGTH_URL          23 /* bytes */
#define SERVICENAME_MAX_BYTES    150 /* bytes */


#define META2_TYPE_ID    2
#define CHUNK_TYPE_ID    3
#define CONTENT_TYPE_ID  4
#define SQLX_TYPE_ID     5

/* Control */
#define CTRL_LIST         "ctrl_list"
#define CTRL_BYPASS       "ctrl_bypass"
#define CTRL_STOP         "ctrl_stop"
#define CTRL_PAUSE        "ctrl_pause"
#define CTRL_RESUME       "ctrl_resume"
#define CTRL_SLOW         "ctrl_slow"
#define CTRL_PROGRESS     "ctrl_progress"
/* ------- */

/* Acknowledgement */
#define ACK_OK "ack_ok"
#define ACK_KO "ack_ko"
/* ------- */

/* DBus conf */
#define SERVICE_CRAWLERCMD_NAME "atos.grid.Crawler_cmd"
#define SERVICE_CRAWLER_NAME    "atos.grid.Crawler"
#define SERVICE_ACTION_NAME     "atos.grid.Action"

#define SERVICE_OBJECT_NAME     "/atos/grid/Crawler"
#define SERVICE_PATH            "/atos/grid/Crawler"
#define SERVICE_IFACE_ACTION    "atos.grid.Crawler.Comm.Action"
#define SERVICE_IFACE_CONTROL   "atos.grid.Crawler.Comm.Control"
#define SERVICE_IFACE_ACK       "atos.grid.Crawler.Comm.Ack"


/* ------- */

/* Command line option */
#define opt_indicator "-"
#define opt_separator "."
#define opt_affectation "="
#define opt_value_list_separator ":"
/* ------- */

#define gvariant_action_param_type_string     "(tviast)"
#define gvariant_ack_param_type_string        "(tv)"
#define gvariant_control_progress_param_ret_type_string "(ti)"

#define CMD_STARTTRIP  "startTrip"
#define CMD_STOPTRIP   "stopTrip"




/* ------- */
#define DRYRUN_SENDTOLISTENER(/*(gchar*)*/ listenerURL, ...) {\
        fprintf(stdout, "(dryrun) SEND_TO_LISTENER(%s): ", listenerURL); \
        fprintf(stdout, __VA_ARGS__); \
    }
#define DRYRUN_GRID(...) {\
        fprintf(stdout, "(dryrun) "); \
        fprintf(stdout, __VA_ARGS__); \
    }
#define DRYRUN_SENDTOACTION(...)   {\
        fprintf(stdout, "(dryrun) SEND_TO_ACTION  : "); \
        fprintf(stdout, __VA_ARGS__); \
    }


#endif
