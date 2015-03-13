/*
OpenIO SDS polix
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

#ifndef OIO_SDS__polix__polix_action_h
# define OIO_SDS__polix__polix_action_h 1

#include <glib.h>

typedef struct {
	guint  nb_del;    // nb chunk deleted
	gint64 del_size;  // size deleted
} polix_action_purge_result_t;

struct hc_url_s;

char* polix_action_get_meta2_url_byhexid(char* ns, char* hexid, GError **error);

gboolean polix_action_purge(char* namespace, char* hexid, const char* meta2_url,
		gdouble timeout_request, gboolean dryrun,
		polix_action_purge_result_t* result, GError **error);

gboolean polix_action_purge_byurl(struct hc_url_s *url, const char* meta2_url,
		gdouble timeout_request, gboolean dryrun,
		polix_action_purge_result_t* result, GError **error);

gboolean polix_action_drop_chunks(gboolean dryrun, GSList *del_chunks_list,
        polix_action_purge_result_t* result, GError **error);

#endif /*OIO_SDS__polix__polix_action_h*/