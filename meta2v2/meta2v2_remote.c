/*
OpenIO SDS meta2v2
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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2"
#endif

#include <errno.h>
#include <strings.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

static MESSAGE
_m2v2_build_request(const gchar *name, struct hc_url_s *url, GByteArray *body)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE msg = metautils_message_create_named(name);
	metautils_message_add_url (msg, url);
	if (body)
		metautils_message_add_body_unref (msg, body);
	return msg;
}

static MESSAGE
_m2v2_build_request_with_flags (const gchar *name, struct hc_url_s *url,
		GByteArray *body, guint32 flags)
{
	flags = g_htonl(flags);
	MESSAGE msg = _m2v2_build_request(name, url, body);
	metautils_message_add_field(msg, NAME_MSGKEY_FLAGS, &flags, sizeof(flags));
	return msg;
}

static GByteArray *
_m2v2_pack_request_with_flags(const gchar *name, struct hc_url_s *url,
		GByteArray *body, guint32 flags)
{
	return message_marshall_gba_and_clean(
			_m2v2_build_request_with_flags (name, url, body, flags));
}

static GByteArray *
_m2v2_pack_request(const gchar *name, struct hc_url_s *url, GByteArray *body)
{
	return message_marshall_gba_and_clean(_m2v2_build_request(name, url, body));
}

//------------------------------------------------------------------------------

void
m2v2_list_result_clean (struct list_result_s *p)
{
	if (!p) return;
	_bean_cleanl2(p->beans);
	p->beans = NULL;
	metautils_str_clean(&p->next_marker);
	p->truncated = FALSE;
}

GByteArray*
m2v2_remote_pack_CREATE(struct hc_url_s *url, struct m2v2_create_params_s *pols)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_CREATE, url, NULL);
	if (pols && pols->storage_policy)
		metautils_message_add_field_str(msg, NAME_MSGKEY_STGPOLICY, pols->storage_policy);
	if (pols && pols->version_policy)
		metautils_message_add_field_str(msg, NAME_MSGKEY_VERPOLICY, pols->version_policy);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_DESTROY(struct hc_url_s *url, guint32 flags)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_DESTROY, url, NULL);
	if (flags & M2V2_DESTROY_FORCE)
		metautils_message_add_field_str(msg, NAME_MSGKEY_FORCE, "1");
	if (flags & M2V2_DESTROY_FLUSH)
		metautils_message_add_field_str(msg, NAME_MSGKEY_FLUSH, "1");
	if (flags & M2V2_DESTROY_PURGE)
		metautils_message_add_field_str(msg, NAME_MSGKEY_PURGE, "1");
	if (flags & M2V2_DESTROY_LOCAL)
		metautils_message_add_field_str(msg, NAME_MSGKEY_LOCAL, "1");

	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_HAS(struct hc_url_s *url)
{
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_HAS, url, NULL);
}

GByteArray*
m2v2_remote_pack_PURGE(struct hc_url_s *url, gboolean dry_run)
{
	guint32 flags = 0;
	if (dry_run)
		flags |= M2V2_MODE_DRYRUN;
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_PURGE, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_DEDUP(struct hc_url_s *url, gboolean dry_run)
{
	guint32 flags = 0;
	if (dry_run)
		flags |= M2V2_MODE_DRYRUN;
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_DEDUP, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_PUT(struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_PUT, url, body);
}

GByteArray*
m2v2_remote_pack_OVERWRITE(struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_PUT, url, body);
	metautils_message_add_field_str(msg, NAME_MSGKEY_OVERWRITE, "1");
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_APPEND(struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_APPEND, url, body);
}

GByteArray*
m2v2_remote_pack_COPY(struct hc_url_s *url, const gchar *src)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_PUT, url, NULL);
	metautils_message_add_field_str(msg, NAME_MSGKEY_COPY, src);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_DEL(struct hc_url_s *url)
{
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_DEL, url, NULL, 0);
}

GByteArray*
m2v2_remote_pack_RAW_DEL(struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_RAW_DEL, url, body);
}

GByteArray*
m2v2_remote_pack_RAW_ADD(struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_RAW_ADD, url, body);
}

GByteArray*
m2v2_remote_pack_RAW_SUBST(struct hc_url_s *url,
		GSList *new_chunks, GSList *old_chunks)
{
	GByteArray *new_chunks_gba = bean_sequence_marshall(new_chunks);
	GByteArray *old_chunks_gba = bean_sequence_marshall(old_chunks);
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_RAW_SUBST, url, NULL);
	metautils_message_add_fields_gba(msg,
			NAME_MSGKEY_NEW, new_chunks_gba,
			NAME_MSGKEY_OLD, old_chunks_gba,
			NULL);
	g_byte_array_unref (new_chunks_gba);
	g_byte_array_unref (old_chunks_gba);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_GET(struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_GET, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_GET_BY_CHUNK(struct hc_url_s *url,
		const gchar *chunk_id, gint64 limit)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_GET, url, NULL);
	metautils_message_add_field_str (msg, NAME_MSGKEY_CHUNKID, chunk_id);
	metautils_message_add_field_strint64 (msg, NAME_MSGKEY_MAX_KEYS, limit);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_LIST(struct hc_url_s *url, struct list_params_s *p)
{
	guint32 flags = 0;
	if (p->flag_allversion)
		flags |= M2V2_FLAG_ALLVERSION;
	if (p->flag_headers)
		flags |= M2V2_FLAG_HEADERS;
	if (p->flag_nodeleted)
		flags |= M2V2_FLAG_NODELETED;

	MESSAGE msg = _m2v2_build_request_with_flags(NAME_MSGNAME_M2V2_LIST, url, NULL, flags);

	metautils_message_add_field_str(msg, NAME_MSGKEY_PREFIX, p->prefix);
	metautils_message_add_field_str(msg, NAME_MSGKEY_MARKER, p->marker_start);
	metautils_message_add_field_str(msg, NAME_MSGKEY_MARKER_END, p->marker_end);
	if (p->maxkeys > 0)
		metautils_message_add_field_strint64(msg, NAME_MSGKEY_MAX_KEYS, p->maxkeys);

	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_PROP_DEL(struct hc_url_s *url, GSList *names)
{
	GByteArray *body = strings_marshall_gba(names, NULL);
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_PROP_DEL, url, body);
}

GByteArray*
m2v2_remote_pack_PROP_SET(struct hc_url_s *url, guint32 flags,
		GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_PROP_SET, url, body, flags);
}

GByteArray*
m2v2_remote_pack_PROP_GET(struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V2_PROP_GET, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_BEANS(struct hc_url_s *url, const gchar *pol, gint64 size, gboolean append)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_BEANS, url, NULL);
	metautils_message_add_field_strint64 (msg, NAME_MSGKEY_CONTENTLENGTH, size);
	metautils_message_add_field_str (msg, NAME_MSGKEY_STGPOLICY, pol);
	if (append)
		metautils_message_add_field_str (msg, NAME_MSGKEY_APPEND, "true");

	/* si policy est NULL, le paramètre ne sera pas ajouté. On profite que
	 * ce soit ldernier argument de la liste */
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_SPARE(struct hc_url_s *url, const gchar *pol,
		GSList *notin_list, GSList *broken_list)
{
	gchar *spare_type = M2V2_SPARE_BY_STGPOL;
	GSList *beans = NULL;

	if (notin_list != NULL) {
		spare_type = M2V2_SPARE_BY_BLACKLIST;
		for (GSList *l = notin_list; l != NULL; l = l->next) {
			if (DESCR(l->data) != &descr_struct_CHUNKS)
				continue;
			beans = g_slist_prepend(beans, _bean_dup(l->data));
		}
	}

	for (GSList *l = broken_list; l != NULL; l = l->next) {
		if (DESCR(l->data) != &descr_struct_CHUNKS)
			continue;
		struct bean_CHUNKS_s *chunk = _bean_dup(l->data);
		// This makes difference between valid and broken chunks
		CHUNKS_set_size(chunk, -1);
		beans = g_slist_prepend(beans, chunk);
	}

	/* body is only mandatory for M2V2_SPARE_BY_BLACKLIST so when
	 * notin_list != NULL. If not_in_list != NULL, beans is always
	 * != NULL so body is sent.
	 */
	GByteArray *body = NULL;
	if (beans != NULL)
		body = bean_sequence_marshall(beans);

	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_BEANS, url, body);
	metautils_message_add_field_str (msg, NAME_MSGKEY_STGPOLICY, pol);
	metautils_message_add_field_str (msg, NAME_MSGKEY_SPARE, spare_type);
	_bean_cleanl2(beans);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_STGPOL(struct hc_url_s *url, const gchar *pol)
{
	MESSAGE msg = _m2v2_build_request(NAME_MSGNAME_M2V2_STGPOL, url, NULL);
	metautils_message_add_field_str(msg, NAME_MSGKEY_STGPOLICY, pol);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_EXITELECTION(struct hc_url_s *url)
{
	return _m2v2_pack_request(NAME_MSGNAME_M2V2_EXITELECTION, url, NULL);
}

GByteArray*
m2v2_remote_pack_TOUCH_content(struct hc_url_s *url)
{
	return _m2v2_pack_request(NAME_MSGNAME_M2V1_TOUCH_CONTENT, url, NULL);
}

GByteArray*
m2v2_remote_pack_TOUCH_container(struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags(NAME_MSGNAME_M2V1_TOUCH_CONTAINER, url, NULL, flags);
}

/* ------------------------------------------------------------------------- */

static GError*
_m2v2_request_ex(const gchar *url, GByteArray *req, gdouble timeout, GSList **out)
{
	EXTRA_ASSERT (req != NULL);
	GError *err = gridd_client_exec_and_decode (url, timeout, req, out, bean_sequence_decoder);
	g_byte_array_free(req, TRUE);
	return err;
}

static GError*
_m2v2_request(const gchar *url, GByteArray *req, GSList **out)
{
	return _m2v2_request_ex(url, req, M2V2_CLIENT_TIMEOUT, out);
}

GError*
m2v2_request(const gchar *url, GByteArray *req, gdouble timeout, GSList **out)
{
	return _m2v2_request_ex(url, req, timeout, out);
}

GError*
m2v2_remote_execute_CREATE(const gchar *target, struct hc_url_s *url, struct m2v2_create_params_s *pols)
{
	return _m2v2_request(target, m2v2_remote_pack_CREATE(url, pols), NULL);
}

GError*
m2v2_remote_execute_DESTROY(const gchar *target, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_request(target, m2v2_remote_pack_DESTROY(url, flags), NULL);
}

GError*
m2v2_remote_execute_DESTROY_many(gchar **targets, struct hc_url_s *url, guint32 flags)
{
	if (!targets)
		return NEWERROR(CODE_INTERNAL_ERROR, "invalid target array (NULL)");

	// TODO: factorize with sqlx_remote_execute_DESTROY_many
	GByteArray *req = m2v2_remote_pack_DESTROY(url, flags | M2V2_DESTROY_LOCAL);
	struct gridd_client_s **clients = gridd_client_create_many(targets, req, NULL, NULL);
	metautils_gba_unref(req);
	req = NULL;

	if (clients == NULL)
		return NEWERROR(0, "Failed to create gridd clients");

	gridd_clients_start(clients);
	GError *err = gridd_clients_loop(clients);
	for (struct gridd_client_s **p = clients; !err && p && *p ;p++) {
		if (!(err = gridd_client_error(*p)))
			continue;
		GRID_DEBUG("Database destruction attempts failed: (%d) %s",
				err->code, err->message);
		if (err->code == CODE_CONTAINER_NOTFOUND || err->code == CODE_NOT_FOUND) {
			g_clear_error(&err);
			continue;
		}
	}

	gridd_clients_free(clients);
	return err;
}

GError*
m2v2_remote_execute_HAS(const gchar *target, struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_HAS(url), NULL);
}

GError*
m2v2_remote_execute_BEANS(const gchar *target, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_BEANS(url, pol, size, append), out);
}

GError*
m2v2_remote_execute_SPARE(const gchar *target, struct hc_url_s *url,
		const gchar *pol, GSList *notin_list, GSList *broken_list,
		GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_SPARE(url, pol, notin_list, broken_list), out);
}

GError*
m2v2_remote_execute_STGPOL(const gchar *target, struct hc_url_s *url,
		const char *pol, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_STGPOL(url, pol), out);
}

GError*
m2v2_remote_execute_PUT(const gchar *target, struct hc_url_s *url,
		GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PUT(url, in), out);
}

GError*
m2v2_remote_execute_OVERWRITE(const gchar *target, struct hc_url_s *url, GSList *in)
{
	return _m2v2_request(target, m2v2_remote_pack_OVERWRITE(url, in), NULL);
}

GError*
m2v2_remote_execute_APPEND(const gchar *target, struct hc_url_s *url, GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_APPEND(url, in), out);
}

GError*
m2v2_remote_execute_COPY(const gchar *target, struct hc_url_s *url, const gchar *src)
{
	return _m2v2_request(target, m2v2_remote_pack_COPY(url, src), NULL);
}

GError*
m2v2_remote_execute_PURGE(const gchar *target, struct hc_url_s *url, gboolean dry_run,
		gdouble timeout, GSList **out)
{
	return _m2v2_request_ex(target, m2v2_remote_pack_PURGE(url, dry_run), timeout, out);
}

GError*
m2v2_remote_execute_EXITELECTION(const gchar *target, struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_EXITELECTION(url), NULL);
}

GError*
m2v2_remote_execute_DEDUP(const gchar *target, struct hc_url_s *url,
		gboolean dry_run, gchar **out)
{
	GByteArray *req = m2v2_remote_pack_DEDUP(url, dry_run);
	GError *err = gridd_client_exec_and_concat_string (target, M2V2_CLIENT_TIMEOUT, req, out);
	g_byte_array_unref (req);
	return err;
}

GError*
m2v2_remote_execute_GET(const gchar *target, struct hc_url_s *url,
		guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_GET(url, flags), out);
}

GError*
m2v2_remote_execute_GET_BY_CHUNK(const gchar *target, struct hc_url_s *url,
		const gchar *chunk_id, gint64 limit, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_GET_BY_CHUNK(url, chunk_id, limit), out);
}

GError*
m2v2_remote_execute_DEL(const gchar *target, struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_DEL(url), NULL);
}

GError*
m2v2_remote_execute_RAW_ADD(const gchar *target, struct hc_url_s *url,
		GSList *beans)
{
	return _m2v2_request(target, m2v2_remote_pack_RAW_ADD(url, beans), NULL);
}

GError*
m2v2_remote_execute_RAW_DEL(const gchar *target, struct hc_url_s *url, GSList *beans)
{
	return _m2v2_request(target, m2v2_remote_pack_RAW_DEL(url, beans), NULL);
}

GError*
m2v2_remote_execute_RAW_SUBST(const gchar *target, struct hc_url_s *url,
		GSList *new_chunks, GSList *old_chunks)
{
	return _m2v2_request(target, m2v2_remote_pack_RAW_SUBST(url, new_chunks, old_chunks), NULL);
}

GError*
m2v2_remote_execute_RAW_SUBST_single(const gchar *target, struct hc_url_s *url,
		struct bean_CHUNKS_s *new_chunk,
		struct bean_CHUNKS_s *old_chunk)
{
	GSList *new_chunks = g_slist_prepend(NULL, new_chunk);
	GSList *old_chunks = g_slist_prepend(NULL, old_chunk);
	GError *res = m2v2_remote_execute_RAW_SUBST(target, url, new_chunks, old_chunks);
	g_slist_free(new_chunks);
	g_slist_free(old_chunks);
	return res;
}

GError*
m2v2_remote_execute_PROP_DEL(const gchar *target, struct hc_url_s *url, GSList *names)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_DEL(url, names), NULL);
}

GError*
m2v2_remote_execute_PROP_SET(const gchar *target, struct hc_url_s *url, guint32 flags, GSList *in)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_SET(url, flags, in), NULL);
}

GError*
m2v2_remote_execute_PROP_GET(const gchar *target, struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_GET(url, flags), out);
}

GError*
m2v2_remote_touch_content(const gchar *target, struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_TOUCH_content(url), NULL);
}

GError*
m2v2_remote_touch_container_ex(const gchar *target, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_request(target, m2v2_remote_pack_TOUCH_container(url, flags), NULL);
}

// Not factorized because we need to extract some headers from the replies
GError*
m2v2_remote_execute_LIST(const gchar *target, struct hc_url_s *url,
		struct list_params_s *p, struct list_result_s *out)
{
	GError *err = NULL;

	gboolean _cb(gpointer ctx, MESSAGE reply) {
		(void) ctx;
		GSList *l = NULL;
		GError *e = metautils_message_extract_body_encoded(reply, FALSE, &l, bean_sequence_decoder);
		if (!e) {

			for (GSList *tmp; l ;l=tmp) { // faster than g_slist_concat
				tmp = l->next;
				l->next = out->beans;
				out->beans = l;
			}

			e = metautils_message_extract_boolean (reply, NAME_MSGKEY_TRUNCATED, FALSE, &out->truncated);
			if (e)
				g_clear_error (&e);
			gchar *tok = NULL;
			tok = metautils_message_extract_string_copy (reply, NAME_MSGKEY_NEXTMARKER);
			metautils_str_reuse (&out->next_marker, tok);
			return TRUE;
		} else {
			GRID_DEBUG("Callback error : %s", e->message);
			err = e;
			return FALSE;
		}
	}

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(target != NULL);

	GByteArray *req = m2v2_remote_pack_LIST(url, p);
	struct gridd_client_s *client = gridd_client_create_idle(target);
	if (!client)
		err = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	if (!err)
		err = gridd_client_request(client, req, NULL, out ? _cb : NULL);
	if (!err)
		err = gridd_client_run (client);
	gridd_client_free(client);
	g_byte_array_free(req, TRUE);

	return err;
}

