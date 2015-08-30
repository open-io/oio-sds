/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__conscience__remote_h
# define OIO_SDS__conscience__remote_h 1

# include <glib.h>

# define NAME_MSGNAME_CS_GET_NSINFO   "REQ_CS_GET_NSINFO"
# define NAME_MSGNAME_CS_GET_SRVNAMES "REQ_GET_SRVNAMES"
# define NAME_MSGNAME_CS_GET_SRV      "REQ_GET_SRV"
# define NAME_MSGNAME_CS_PUSH_SRV     "REQ_PUSH_SRV"
# define NAME_MSGNAME_CS_RM_SRV       "REQ_RM_SRV"

# define OIO_CFG_ZOOKEEPER    "zookeeper"
# define OIO_CFG_CONSCIENCE   "conscience"
# define OIO_CFG_ACCOUNTAGENT "event-agent"

# define gridcluster_get_zookeeper(ns)  oio_cfg_get_value((ns), OIO_CFG_ZOOKEEPER)
# define gridcluster_get_eventagent(ns) oio_cfg_get_value((ns), OIO_CFG_ACCOUNTAGENT)
# define gridcluster_get_conscience(ns) oio_cfg_get_value((ns), OIO_CFG_CONSCIENCE)

struct namespace_info_s;

/* Actions to a specific target (conscience protocol) ----------------------- */

GError* gcluster_get_namespace (const char *cs, struct namespace_info_s **out);
GError* gcluster_get_services (const char *cs, const char *type, gboolean full, gboolean local, GSList **out);
GError* gcluster_get_service_types (const char *cs, GSList **out); 
GError* gcluster_push_services (const char *cs, GSList *ls);
GError* gcluster_remove_services (const char *cs, const char *type, GSList *ls);

/* Actions to a namespace (proxy protocol) ---------------------------------- */

GError* conscience_get_namespace (const char *ns, struct namespace_info_s **out);
GError* conscience_list_services (const char *ns, const char *type, gboolean full, gboolean local, GSList **out);
GError* conscience_list_service_types (const char *ns, GSList **out);
GError* conscience_clear_services (const char *ns, const char *type, GSList *ls);
GError* conscience_register_service (struct service_info_s *si);

#endif /*OIO_SDS__conscience__remote_h*/
