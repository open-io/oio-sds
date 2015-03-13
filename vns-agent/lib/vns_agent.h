/*
OpenIO SDS vns-agent
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

#ifndef OIO_SDS__vns_agent__lib__vns_agent_h
# define OIO_SDS__vns_agent__lib__vns_agent_h 1

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

#endif /*OIO_SDS__vns_agent__lib__vns_agent_h*/