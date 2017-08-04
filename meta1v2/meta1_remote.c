/*
OpenIO SDS meta1v2
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

#include <metautils/lib/metautils.h>

#include "./internals.h"
#include "./meta1_remote.h"

static GError *array_request(const char *to, GByteArray *req,
		GError* (*decoder) (guint8*, gsize, gchar***), gchar ***out) {
	EXTRA_ASSERT(to != NULL);
	EXTRA_ASSERT(req != NULL);

	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat(to, 30.0, req, out ? &gba : NULL);

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

static GError *STRV_request(const char *to, GByteArray *req, gchar ***out) {
	return array_request(to, req, STRV_decode_buffer, out);
}

static GError *KV_request(const char *to, GByteArray *req, gchar ***out) {
	return array_request(to, req, KV_decode_buffer, out);
}

static GError *oneway_request (const char *to, GByteArray *req) {
	return STRV_request(to, req, NULL);
}

/* ------------------------------------------------------------------------- */

GError *
meta1v2_remote_create_reference (const char *to, struct oio_url_s *url,
		gchar **properties)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERCREATE);
	metautils_message_add_url_no_type (req, url);
	if (properties && *properties)
		metautils_message_add_body_unref(req, KV_encode_gba(properties));
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_delete_reference (const char *to, struct oio_url_s *url,
		gboolean force)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERDESTROY);
	metautils_message_add_url_no_type (req, url);
	if (force)
		metautils_message_add_field_str (req, NAME_MSGKEY_FORCE, "1");
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_link_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gboolean ac, gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLINK);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (ac)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return STRV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_list_reference_services(const char *to, struct oio_url_s *url,
		const char *srvtype, gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLIST);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	return STRV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_unlink_service(const char *to, struct oio_url_s *url,
		const char *srvtype)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVUNLINK);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_unlink_one_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gint64 seqid)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVUNLINK);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (seqid > 0) {
		gchar str[24];
		g_snprintf(str, sizeof(str), "%"G_GINT64_FORMAT"\n", seqid);
		metautils_message_add_body_unref (req, metautils_gba_from_string (str));
	}
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_renew_reference_service(const char *to, struct oio_url_s *url,
		const char *srvtype, const char *last, gboolean autocreate,
		gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVRENEW);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (oio_str_is_set(last))
		metautils_message_add_field_str(req, NAME_MSGKEY_LAST, last);
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return STRV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_force_reference_service(const char *to, struct oio_url_s *url,
		const char *m1url, gboolean autocreate, gboolean force)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVFORCE);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, metautils_gba_from_string(m1url));
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	if (force)
		metautils_message_add_field_str (req, NAME_MSGKEY_FORCE, "1");
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_reference_set_property(const char *to, struct oio_url_s *url,
		gchar **pairs, gboolean flush)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPSET);
	metautils_message_add_url_no_type (req, url);
	if (flush)
		metautils_message_add_field_str (req, NAME_MSGKEY_FLUSH, "1");
	metautils_message_add_body_unref (req, KV_encode_gba(pairs));
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_reference_get_property(const char *to, struct oio_url_s *url,
		gchar **keys, gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPGET);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, STRV_encode_gba(keys));
	return KV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_reference_del_property(const char *to, struct oio_url_s *url,
		gchar **keys)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPDEL);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, STRV_encode_gba(keys));
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_list_services_by_prefix(const char *to, struct oio_url_s *url,
		gchar ***result)
{
    EXTRA_ASSERT(url != NULL);
    MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVALLONM1);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_cid (req, NAME_MSGKEY_PREFIX, oio_url_get_id(url));
    return STRV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_get_prefixes(const char *to, gchar *** result)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_GETPREFIX);
	return STRV_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_relink_service(const char *m1, struct oio_url_s *url,
		const char *kept, const char *replaced, gboolean dryrun,
		gchar ***out)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVRELINK);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_OLD, kept);
	if (replaced)
		metautils_message_add_field_str (req, NAME_MSGKEY_NOTIN, replaced);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	return STRV_request(m1, message_marshall_gba_and_clean(req), out);
}

