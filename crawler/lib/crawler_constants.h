/*
OpenIO SDS crawler
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__crawler__lib__crawler_constants_h
# define OIO_SDS__crawler__lib__crawler_constants_h 1

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

#endif /*OIO_SDS__crawler__lib__crawler_constants_h*/