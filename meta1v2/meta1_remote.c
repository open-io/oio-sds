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

static gboolean
on_reply(gpointer ctx, MESSAGE reply)
{
	GByteArray *out = ctx;
	gsize bsize = 0;
	void *b = metautils_message_get_BODY(reply, &bsize);
	if (b) {
		if (out != NULL)
			g_byte_array_append(out, b, bsize);
	}

	g_byte_array_append(out, (const guint8*)"", 1);
	g_byte_array_set_size(out, out->len - 1);
	return TRUE;
}

static GError *
list_request(const char *to, GByteArray *req, gchar ***out)
{
	EXTRA_ASSERT(to != NULL);
	EXTRA_ASSERT(req != NULL);

	GByteArray *gba = g_byte_array_new();
	struct gridd_client_s *client = gridd_client_create(to, req, gba, on_reply);
	g_byte_array_unref (req);

	GError *e = gridd_client_run(client);
	gridd_client_free(client);

	if (e) {
		g_byte_array_free(gba, TRUE);
		return e;
	}

	if (out)
		*out = metautils_decode_lines((gchar*)gba->data, (gchar*)(gba->data + gba->len));
	if (out && !*out)
		e = NEWERROR(CODE_BAD_REQUEST, "Invalid buffer content");
	g_byte_array_free(gba, TRUE);
	return e;
}

static GError *
oneway_request (const char *to, GByteArray *req)
{
	return list_request (to, req, NULL);
}

/* ------------------------------------------------------------------------- */

GError *
meta1v2_remote_create_reference (const char *to, struct oio_url_s *url)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERCREATE);
	metautils_message_add_url_no_type (req, url);
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_has_reference (const char *to, struct oio_url_s *url,
		struct oio_url_s ***out)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_USERINFO);
	metautils_message_add_url_no_type (req, url);
	if (!out)
		return oneway_request(to, message_marshall_gba_and_clean(req));

	*out = NULL;
	gchar **tab = NULL;
	GError *e = list_request (to, message_marshall_gba_and_clean(req), &tab);
	if (e) return e;

	gsize len = g_strv_length (tab);
	*out = g_malloc0 ((1 + len) * sizeof(void*));
	struct oio_url_s **p = *out;
	for (guint i=0; i<len ;i++) {
		*p = oio_url_init (tab[i]);
		if (*p) p++;
	}
	g_strfreev (tab);
	return NULL;
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
		const char *srvtype, gboolean dryrun, gboolean ac,
		gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLINK);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	if (ac)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return list_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_list_reference_services(const char *to, struct oio_url_s *url,
		const char *srvtype, gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVLIST);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	return list_request(to, message_marshall_gba_and_clean(req), result);
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
meta1v2_remote_poll_reference_service(const char *to, struct oio_url_s *url,
		const char *srvtype, gboolean dryrun, gboolean autocreate,
		gchar ***result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVPOLL);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, srvtype);
	if (dryrun)
		metautils_message_add_field_str (req, NAME_MSGKEY_DRYRUN, "1");
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	return list_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_force_reference_service(const char *to, struct oio_url_s *url,
		const char *m1url, gboolean autocreate, gboolean force)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVSET);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, metautils_gba_from_string(m1url));
	if (autocreate)
		metautils_message_add_field_str (req, NAME_MSGKEY_AUTOCREATE, "1");
	if (force)
		metautils_message_add_field_str (req, NAME_MSGKEY_FORCE, "1");
	return oneway_request(to, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_configure_reference_service(const char *to, struct oio_url_s *url,
		const char *m1url)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_SRVCONFIG);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, metautils_gba_from_string(m1url));
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
	metautils_message_add_body_unref (req, metautils_encode_lines(pairs));
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
	metautils_message_add_body_unref (req, metautils_encode_lines(keys));
	return list_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_reference_del_property(const char *to, struct oio_url_s *url,
		gchar **keys)
{
	EXTRA_ASSERT(url != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_PROPDEL);
	metautils_message_add_url_no_type (req, url);
	metautils_message_add_body_unref (req, metautils_encode_lines(keys));
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
    return list_request(to, message_marshall_gba_and_clean(req), result);
}

GError *
meta1v2_remote_get_prefixes(const char *to, gchar *** result)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_M1V2_GETPREFIX);
	return list_request(to, message_marshall_gba_and_clean(req), result);
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
	return list_request (m1, message_marshall_gba_and_clean(req), out);
}

