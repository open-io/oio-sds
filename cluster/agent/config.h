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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <glib.h>

#define USER_KEY                        "user"
#define GROUP_KEY                       "group"
#define SVC_CHECK_FREQ_KEY              "service_check_freq"
#define CS_UPDATE_FREQ_KEY              "cluster_update_freq"

#define CS_UPDATE_NS_PERIOD_KEY         "period_update_ns"
#define CS_UPDATE_SRV_PERIOD_KEY        "period_update_srv"
#define CS_UPDATE_SRVTYPE_PERIOD_KEY    "period_update_srvtype"
#define CS_UPDATE_EVTCFG_PERIOD_KEY     "period_update_evtcfg"
#define CS_UPDATE_SRVLST_PERIOD_KEY     "period_update_srvlist"

#define EVENTS_MODE_FILE_KEY            "events.mode.file"
#define EVENTS_MODE_DIR_KEY             "events.mode.dir"
#define EVENTS_SPOOL_DIR_KEY            "events.spool.dir"
#define EVENTS_SPOOL_SIZE_KEY           "events.spool.size"
#define EVENTS_MANAGE_ENABLE_KEY        "events.manage.enable"
#define EVENTS_RECEIVE_ENABLE_KEY       "events.receive.enable"
#define EVENTS_MAXPENDING_KEY           "events.max_pending"
#define EVENTS_DELAY_INCOMING_KEY       "events.incoming_delay"
#define EVENTS_DELAY_REFRESH_KEY        "events.refresh_delay"

#define NSINFO_DELAY_REFRESH_KEY        "nsinfo.refresh_delay"

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
#define EVENTS_DELAY_REFRESH_DEFAULT    30L

#define NSINFO_DELAY_REFRESH_DEFAULT    5L

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
