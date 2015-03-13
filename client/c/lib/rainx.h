/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__client__c__lib__rainx_h
# define OIO_SDS__client__c__lib__rainx_h 1

#include "./gs_internals.h"

#define RAINX_UPLOAD "PUT"
#define RAINX_DOWNLOAD "GET"

gboolean stg_pol_is_rainx(namespace_info_t *ni, const gchar *stgpol);
gboolean stg_pol_rainx_get_param(namespace_info_t *ni, const gchar *stgpol, const gchar *param, gint64 *p_val);

GSList* rainx_get_spare_chunks(gs_container_t *container, gchar *content_path, gint64 count,
		gint64 distance, GSList *notin_list, GSList *broken_rawx_list, gs_error_t **err);

addr_info_t* get_rainx_from_conscience(const gchar *nsname, GError **error);

gboolean rainx_ask_reconstruct(struct dl_status_s *dl_status, gs_content_t *content, GSList *aggregated_chunks,
		GSList *filtered, GSList *beans, GSList *broken_rawx_list, GHashTable *failed_chunks,
		const gchar *storage_policy, gs_error_t **err);

#endif /*OIO_SDS__client__c__lib__rainx_h*/