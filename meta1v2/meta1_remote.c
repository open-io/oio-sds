/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>

#include <sqliterepo/sqlite_utils.h>

#include "./internals.h"
#include "./meta1_remote.h"

static GError *array_request(const char *to, GByteArray *req,
		GError* (*decoder) (guint8*, gsize, gchar***), gchar ***out,
		gint64 deadline)
{
	EXTRA_ASSERT(to != NULL);
	EXTRA_ASSERT(req != NULL);

	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat(to,
			oio_clamp_timeout(oio_m1_client_timeout_common, deadline),
			req, out ? &gba : NULL);

	if (NULL != err) {
		if (gba)
			g_byte_array_free(gba, TRUE);
		return err;
	}
	/* TODO check the reply even if not interested in the result */
	err = gba ? (*decoder)(gba->data, gba->len, out) : NULL;
	if (gba)
		g_byte_array_free(gba, TRUE);
	return err;
}

static GError *STRV_request(const char *to, GByteArray *req, gchar ***out, gint64 deadline) {
	return array_request(to, req, STRV_decode_buffer, out, deadline);
}

static GError *KV_request(const char *to, GByteArray *req, gchar ***out, gint64 deadline) {
	return array_request(to, req, KV_decode_buffer, out, deadline);
}

static GError *oneway_request (const char *to, GByteArray *req, gint64 deadline) {
	return STRV_request(to, req, NULL, deadline);
}

/* ------------------------------------------------------------------------- */

GError *
meta1v2_remote_create_reference (const char *to, struct oio_url_s *url,
		gchar **properties, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERCREATE, deadline);
	metautils_message_add_url_no_type (req, url);
	if (properties && *properties)
		metautils_message_add_body_unref(req, KV_encode_gba(properties));
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_delete_reference (const char *to, struct oio_url_s *url,
		gboolean force, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERDESTROY, deadline);
	metautils_message_add_url_no_type (req, url);
	if (force)
		metautils_message_add_field_str (req, NAME_MSGKEY_FORCE, "1");
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_link_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gboolean dryrun, gboolean ac,
		gchar ***result, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLINK, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	if (ac)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return STRV_request(to, message_marshall_gba_and_clean(req), result, deadline);
}

GError *
meta1v2_remote_list_reference_services(const char *to, struct oio_url_s *url,
		const char *srvtype, gchar ***result, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	GError *err = NULL;
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLIST, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	/* Ask the server for the "extended" version, which adds account and
	 * container names to the response. */
	metautils_message_add_field_str(req, NAME_MSGKEY_EXTEND, "1");

	gchar **_tmp_result = NULL;

	err = STRV_request(to, message_marshall_gba_and_clean(req), &_tmp_result,
			deadline);

	// Fill oio_url_s from the response and return the usual results
	if (!err) {
		GPtrArray *srv_array = g_ptr_array_new();
		for (gchar **srvc = _tmp_result; *srvc; srvc++) {
			if (g_str_has_prefix(*srvc, SQLX_ADMIN_ACCOUNT)) {
				if (!oio_url_has(url, OIOURL_ACCOUNT)) {
					oio_url_set(url, OIOURL_ACCOUNT,
							(*srvc) + sizeof(SQLX_ADMIN_ACCOUNT));
				}
				g_free(*srvc);
			} else if (g_str_has_prefix(*srvc, SQLX_ADMIN_USERNAME)) {
				if (!oio_url_has(url, OIOURL_USER)) {
					oio_url_set(url, OIOURL_USER,
							(*srvc) + sizeof(SQLX_ADMIN_USERNAME));
				}
				g_free(*srvc);
			} else {
				g_ptr_array_add(srv_array, *srvc);
			}
			*srvc = NULL;  // Either freed or sent to the other array
		}
		g_ptr_array_add(srv_array, NULL);
		g_free(_tmp_result);

		*result = (gchar **) g_ptr_array_free(srv_array, FALSE);
	}
	return err;
}

GError *
meta1v2_remote_unlink_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVUNLINK, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_renew_reference_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gboolean dryrun, gboolean autocreate,
		gchar ***result, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVRENEW, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return STRV_request(to, message_marshall_gba_and_clean(req), result, deadline);
}

GError *
meta1v2_remote_force_reference_service(const char *to, struct oio_url_s *url,
		const char *m1url, gboolean autocreate, gboolean force, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVFORCE, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, metautils_gba_from_string(m1url));
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	if (force)
		metautils_message_add_field_str (req, NAME_MSGKEY_FORCE, "1");
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_reference_set_property(const char *to, struct oio_url_s *url,
		gchar **pairs, gboolean flush, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPSET, deadline);
	metautils_message_add_url_no_type (req, url);
	if (flush)
		metautils_message_add_field_str (req, NAME_MSGKEY_FLUSH, "1");
	metautils_message_add_body_unref (req, KV_encode_gba(pairs));
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_reference_get_property(const char *to, struct oio_url_s *url,
		gchar **keys, gchar ***result, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPGET, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, STRV_encode_gba(keys));
	return KV_request(to, message_marshall_gba_and_clean(req), result, deadline);
}

GError *
meta1v2_remote_reference_del_property(const char *to, struct oio_url_s *url,
		gchar **keys, gint64 deadline)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPDEL, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, STRV_encode_gba(keys));
	return oneway_request(to, message_marshall_gba_and_clean(req), deadline);
}

GError *
meta1v2_remote_relink_service(const char *m1, struct oio_url_s *url,
		const char *kept, const char *replaced, gboolean dryrun,
		gchar ***out, gint64 deadline)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVRELINK, deadline);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_OLD, kept);
	if (replaced)
		metautils_message_add_field_str (req, NAME_MSGKEY_NOTIN, replaced);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	return STRV_request(m1, message_marshall_gba_and_clean(req), out, deadline);
}
