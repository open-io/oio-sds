/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRAWLER_CONSTANTS_H
#define CRAWLER_CONSTANTS_H

#define SHORT_BUFFER_SIZE 512 /* bytes */
#define MAX_ACTION_TIMEOUT 5 /* seconds */
#define SLOW_VALUE 3 /* seconds */
#define META2_CONNECTION_TIMEOUT 5 /* seconds */
#define CMD_RESULT_TIMEOUT 5 /* seconds */
#define DBUS_LISTENING_TIMEOUT 100 /* milliseconds */

#define META2_TYPE_ID 2
#define CHUNK_TYPE_ID 3
#define CONTENT_TYPE_ID 4

/* Control */
#define CTRL_BYPASS "ctrl_bypass"
#define CTRL_STOP "ctrl_stop"
#define CTRL_PAUSE "ctrl_pause"
#define CTRL_RESUME "ctrl_resume"
#define CTRL_SLOW "ctrl_slow"
#define CTRL_PROGRESS "ctrl_progress"
#define CTRL_PROGRESS_RET "ctrl_progress_ret"
/* ------- */

/* Acknowledgement */
#define ACK_OK "ack_ok"
#define ACK_KO "ack_ko"
/* ------- */

/* DBus conf */
#define signal_object_name "/atos/grid/Crawler"
#define signal_action_interface_name "atos.grid.Crawler.Comm.Action"
#define signal_control_interface_name "atos.grid.Crawler.Comm.Control"
#define signal_ack_interface_name "atos.grid.Crawler.Comm.Ack"
/* ------- */

/* Command line option */
#define opt_indicator "-"
#define opt_separator "."
#define opt_affectation "="
#define opt_value_list_separator ":"
/* ------- */

#define gvariant_action_param_type_string "(tviast)"
#define gvariant_ack_param_type_string "(tv)"
#define gvariant_control_progress_param_ret_type_string "(ti)"
#define end_signal_tile "end"
#define default_trip_lib_dir "/usr/lib64/grid"

#endif
