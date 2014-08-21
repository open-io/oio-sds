#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2.remote"
#endif

#include <errno.h>
#include <strings.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#define GBA_POOL_CLEAN(P) g_slist_free_full((P), (GDestroyNotify)metautils_gba_unref)

static GByteArray *
gba_poolify(GSList **pool, GByteArray *gba)
{
	if (!gba)
		return NULL;
	*pool = g_slist_prepend(*pool, gba);
	return gba;
}

static GByteArray *
_url_2_gba(struct hc_url_s *url)
{
	GByteArray *gba = g_byte_array_new();
	if (hc_url_get_id(url))
		g_byte_array_append(gba, hc_url_get_id(url), hc_url_get_id_size(url));
	return gba;
}

static MESSAGE
_m2v2_build_request(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body)
{
	struct message_s *msg;
	GSList *pool = NULL;

	EXTRA_ASSERT(url != NULL);
	msg = message_create_request(NULL, sid, name,
			body ? gba_poolify(&pool, body) : NULL,
			"HC_URL", gba_poolify(&pool,
				metautils_gba_from_string(hc_url_get(url, HCURL_WHOLE))),
			"NAMESPACE", gba_poolify(&pool,
				metautils_gba_from_string(hc_url_get(url, HCURL_NS))),
			"CONTAINER_ID", gba_poolify(&pool,
				_url_2_gba(url)),
			NULL);
	GBA_POOL_CLEAN(pool);

	return msg;
}

static GByteArray *
_m2v2_pack_request(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body)
{
	return message_marshall_gba_and_clean(
			_m2v2_build_request(name, sid, url, body));
}

static GByteArray *
_m2v2_pack_request_with_flags(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body, guint32 flags)
{
	struct message_s *msg;

	msg = _m2v2_build_request(name, sid, url, body);
	flags = g_htonl(flags);
	(void) message_add_field(msg, "FLAGS", sizeof("FLAGS")-1,
			&flags, sizeof(flags), NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_CREATE(GByteArray *sid, struct hc_url_s *url,
		struct m2v2_create_params_s *pols)
{
	struct message_s *msg;

	msg = _m2v2_build_request("M2V2_CREATE", sid, url, NULL);
	if (pols && pols->storage_policy) {
		(void) message_add_field(msg,
				M2_KEY_STORAGE_POLICY, sizeof(M2_KEY_STORAGE_POLICY)-1,
				pols->storage_policy, strlen(pols->storage_policy),
				NULL);
	}
	if (pols && pols->version_policy) {
		(void) message_add_field(msg,
				M2_KEY_VERSION_POLICY, sizeof(M2_KEY_VERSION_POLICY)-1,
				pols->version_policy, strlen(pols->version_policy),
				NULL);
	}
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_DESTROY(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	struct message_s *msg;
	msg = _m2v2_build_request("M2V2_DESTROY", sid, url, NULL);
	if (flags & M2V2_DESTROY_FORCE)
		message_add_fields_str(msg, "FORCE", "1", NULL);
	if (flags & M2V2_DESTROY_FLUSH)
		message_add_fields_str(msg, "FLUSH", "1", NULL);
	if (flags & M2V2_DESTROY_PURGE)
		message_add_fields_str(msg, "PURGE", "1", NULL);
	if (flags & M2V2_DESTROY_LOCAL)
		message_add_fields_str(msg, "LOCAL", "1", NULL);

	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_HAS(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_HAS", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_PURGE(GByteArray *sid, struct hc_url_s *url, gboolean dry_run)
{
    guint32 flags = 0;
    if (dry_run)
		flags |= M2V2_MODE_DRYRUN;

    return _m2v2_pack_request_with_flags("M2V2_PURGE", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_DEDUP(GByteArray *sid, struct hc_url_s *url, gboolean dry_run)
{
	guint32 flags = 0;
	if (dry_run)
		flags |= M2V2_MODE_DRYRUN;
	return _m2v2_pack_request_with_flags("M2V2_DEDUP", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_PUT(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_PUT", sid, url, body);
}

GByteArray*
m2v2_remote_pack_OVERWRITE(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	struct message_s *msg;
	GByteArray *body = bean_sequence_marshall(beans);
	msg = _m2v2_build_request("M2V2_PUT", sid, url, body);
	(void) message_add_field(msg,
				M2_KEY_OVERWRITE, sizeof(M2_KEY_OVERWRITE)-1,
				"1", 1,
				NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_APPEND(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_APPEND", sid, url, body);
}

GByteArray*
m2v2_remote_pack_COPY(GByteArray *sid, struct hc_url_s *url, const gchar *src)
{
	struct message_s *msg;

	msg = _m2v2_build_request("M2V2_PUT", sid, url, NULL);
	(void) message_add_field(msg,
				M2_KEY_COPY_SOURCE, sizeof(M2_KEY_COPY_SOURCE)-1,
				src, strlen(src),
				NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_DEL(GByteArray *sid, struct hc_url_s *url, gboolean sync_del)
{
	return _m2v2_pack_request_with_flags("M2V2_DEL", sid, url, NULL,
			sync_del? M2V2_FLAG_SYNCDEL : 0);
}

GByteArray*
m2v2_remote_pack_RAW_DEL(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_RAW_DEL", sid, url, body);
}

GByteArray*
m2v2_remote_pack_SUBST_CHUNKS(GByteArray *sid, struct hc_url_s *url,
		GSList *new_chunks, GSList *old_chunks, gboolean restrict_to_alias)
{
	struct message_s *msg;
	GByteArray *new_chunks_gba = bean_sequence_marshall(new_chunks);
	GByteArray *old_chunks_gba = bean_sequence_marshall(old_chunks);
	msg = _m2v2_build_request("M2V2_SUBST_CHUNKS", sid, url, NULL);
	if (restrict_to_alias) {
		(void) message_add_field(msg,
				M2_KEY_RESTRICT_TO_ALIAS, sizeof(M2_KEY_RESTRICT_TO_ALIAS)-1,
				"TRUE", 5, NULL);
	}
	message_add_fields_gba(msg,
			M2_KEY_NEW_CHUNKS, new_chunks_gba,
			M2_KEY_OLD_CHUNKS, old_chunks_gba,
			NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_GET(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_GET", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_GET_BY_CHUNK(GByteArray *sid, struct hc_url_s *url,
		const gchar *chunk_id, gint64 limit)
{
	struct message_s *msg;
	gchar limit_str[16];
	g_snprintf(limit_str, 16, "%"G_GINT64_FORMAT, limit);
	msg = _m2v2_build_request("M2V2_GET", sid, url, NULL);
	message_add_fields_str(msg,
			M2_KEY_CHUNK_ID, chunk_id,
			M2_KEY_MAX_KEYS, limit_str,
			NULL);
    return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_LIST(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_LIST", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_PROP_SET(GByteArray *sid, struct hc_url_s *url, guint32 flags,
		GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request_with_flags("M2V2_PROP_SET", sid, url, body, flags);
}

GByteArray*
m2v2_remote_pack_PROP_GET(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_PROP_GET", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_BEANS(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append)
{
	gchar strsize[128];
	struct message_s *msg;

	g_snprintf(strsize, sizeof(strsize), "%"G_GINT64_FORMAT, size);

	msg = _m2v2_build_request("M2V2_BEANS", sid, url, NULL);
	if(!append) {
		message_add_fields_str(msg,
				NAME_MSGKEY_CONTENTLENGTH, strsize,
				"STORAGE_POLICY", pol, NULL);
	} else {
		message_add_fields_str(msg,
				NAME_MSGKEY_CONTENTLENGTH, strsize,
				"APPEND", "true",
				"STORAGE_POLICY", pol, NULL);
	}
	/* si policy est NULL, le paramètre ne sera pas ajouté. On profite que
	 * ce soit ldernier argument de la liste */
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_SPARE(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, GSList *notin_list, GSList *broken_list)
{
	struct message_s *msg;
	gchar *spare_type = M2V2_SPARE_BY_STGPOL;
	GByteArray *body = NULL;
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
	if (beans != NULL)
		body = bean_sequence_marshall(beans);

	msg = _m2v2_build_request("M2V2_BEANS", sid, url, body);
	message_add_fields_str(msg,
			M2_KEY_STORAGE_POLICY, pol,
			M2_KEY_SPARE, spare_type,
			NULL);

	_bean_cleanl2(beans);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_STGPOL(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol)
{
	struct message_s *msg;

	msg = _m2v2_build_request("M2V2_STGPOL", sid, url, NULL);
	message_add_fields_str(msg, "STORAGE_POLICY", pol, NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_EXITELECTION(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_EXITELECTION", sid, url, NULL);

}

GByteArray*
m2v2_remote_pack_SNAP_TAKE(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_SNAP_TAKE", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_SNAP_LIST(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_SNAP_LIST", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_SNAP_RESTORE(GByteArray *sid, struct hc_url_s *url,
		gboolean hard_restore)
{
	struct message_s *msg;
	msg = _m2v2_build_request("M2V2_SNAP_RESTORE", sid, url, NULL);
	message_add_field(msg,
			M2_KEY_SNAPSHOT_HARDRESTORE, sizeof(M2_KEY_SNAPSHOT_HARDRESTORE),
			(guint8*)&hard_restore, sizeof(guint8), NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_SNAP_DELETE(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_SNAP_DEL", sid, url, NULL);
}


GByteArray*
m2v2_remote_pack_TOUCH_content(GByteArray *sid, struct hc_url_s *url)
{
	    return _m2v2_pack_request("REQ_M2RAW_TOUCH_CONTENT", sid, url, NULL);
}


GByteArray*
m2v2_remote_pack_TOUCH_container(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("REQ_M2RAW_TOUCH_CONTAINER", sid, url, NULL, flags);
}


/* ------------------------------------------------------------------------- */



/**
 * if timeout_to_step or timeout_to_overall = -1: 
 * used default value
 */
static GError*
_m2v2_request_ex(const gchar *url, GByteArray *req, 
				gdouble timeout_to_step, gdouble timeout_to_overall,
				GSList **out)
{
	GError *err = NULL;
	struct client_s *client;

	gboolean _cb(gpointer ctx, struct message_s *reply) {
		GSList *l = NULL;
		GError *e = NULL;
		if (0 < message_has_BODY(reply, NULL)) {
			e = message_extract_body_encoded(reply, &l, bean_sequence_decoder);
		}
		if (!e) {
			if (l) {
				*((GSList**)ctx) = g_slist_concat(*((GSList**)ctx), l);
			}
			return TRUE;
		}
		else {
			GRID_DEBUG("Callback error : %s", e->message);
			err = e;
			return FALSE;
		}
	}

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(req != NULL);

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	client = gridd_client_create_idle(url);
	if (!client)
		err = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	else {
		if ((timeout_to_step >= 0)&&(timeout_to_overall>=0))
			gridd_client_set_timeout(client, timeout_to_step, timeout_to_overall);

		if (!gridd_client_start(client))
			err = gridd_client_error(client);
		if (!err)
			err = gridd_client_request(client, req, out, out ? _cb : NULL);
		if (!err) {
			if (!(err = gridd_client_loop(client))) {
				err = gridd_client_error(client);
			}
		}
		gridd_client_free(client);
	}

	g_byte_array_free(req, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return err;
}


static GError*
_m2v2_request(const gchar *url, GByteArray *req, GSList **out)
{
    return _m2v2_request_ex(url, req, -1, -1, out);
}



GError*
m2v2_remote_execute_CREATE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, struct m2v2_create_params_s *pols)
{
	return _m2v2_request(target, m2v2_remote_pack_CREATE(sid, url, pols), NULL);
}

GError*
m2v2_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags)
{
	return _m2v2_request(target, m2v2_remote_pack_DESTROY(sid, url, flags), NULL);
}

GError*
m2v2_remote_execute_DESTROY_many(gchar **targets, GByteArray *sid,
		struct hc_url_s *url, guint32 flags)
{
	GError *err = NULL;
	GByteArray *req = NULL;

	if (!targets) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "invalid target array (NULL)");
		return err;
	}

	req = m2v2_remote_pack_DESTROY(sid, url, flags | M2V2_DESTROY_LOCAL);

	// TODO: factorize with sqlx_remote_execute_DESTROY_many
	struct client_s **clients = gridd_client_create_many(targets, req,
			NULL, NULL);
	metautils_gba_unref(req);
	req = NULL;

	if (clients == NULL) {
		err = NEWERROR(0, "Failed to create gridd clients");
		return err;
	}

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);

	for (struct client_s **p = clients; !err && p && *p ;p++) {
		if (!(err = gridd_client_error(*p)))
			continue;
		GRID_DEBUG("Database destruction attempts failed: (%d) %s",
				err->code, err->message);
		if (err->code == CODE_CONTAINER_NOTFOUND || err->code == 404) {
			g_clear_error(&err);
			continue;
		}
	}

	gridd_clients_free(clients);
	return err;
}

GError*
m2v2_remote_execute_HAS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_HAS(sid, url), NULL);
}

GError*
m2v2_remote_execute_BEANS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *pol, gint64 size,
		gboolean append, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_BEANS(sid, url, pol, size, append), out);
}

GError*
m2v2_remote_execute_SPARE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *pol,
		GSList *notin_list, GSList *broken_list,
		GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_SPARE(sid, url, pol,
			notin_list, broken_list), out);
}

GError*
m2v2_remote_execute_STGPOL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const char *pol, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_STGPOL(sid, url, pol), out);
}

GError*
m2v2_remote_execute_PUT(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PUT(sid, url, in), out);
}

GError*
m2v2_remote_execute_OVERWRITE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in)
{
	return _m2v2_request(target, m2v2_remote_pack_OVERWRITE(sid, url, in), NULL);
}

GError*
m2v2_remote_execute_APPEND(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_APPEND(sid, url, in), out);
}

GError*
m2v2_remote_execute_COPY(const gchar *target, GByteArray *sid, 
		struct hc_url_s *url, const gchar *src)
{
	return _m2v2_request(target, m2v2_remote_pack_COPY(sid, url, src), NULL);
}

GError*
m2v2_remote_execute_PURGE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean dry_run, 
		gdouble timeout_to_step, gdouble timeout_to_overall, GSList **out)
{
        return _m2v2_request_ex(target, m2v2_remote_pack_PURGE(sid, url, dry_run), 
								timeout_to_step, timeout_to_overall, out);
}

GError*
m2v2_remote_execute_EXITELECTION(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_EXITELECTION(sid, url), NULL);
}

GError*
m2v2_remote_execute_DEDUP(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean dry_run, gchar **out)
{
	struct client_s *client;
	GError *err = NULL;

	gboolean _cb(gpointer ctx, struct message_s *reply) {
		GError *e = NULL;
		if (0 < message_has_BODY(reply, NULL)) {
			e = message_extract_body_string(reply, (gchar**)ctx);
		}
		if (!e)
			return TRUE;
		else {
			err = e;
			return FALSE;
		}
	}

	client = gridd_client_create_idle(target);
	if (!client)
		err = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	else {
		if (!gridd_client_start(client))
			err = gridd_client_error(client);
		if (!err) {
			GByteArray *req = m2v2_remote_pack_DEDUP(sid, url, dry_run);
			err = gridd_client_request(client, req, out, out ? _cb : NULL);
			g_byte_array_unref(req);
		}
		if (!err) {
			if (!(err = gridd_client_loop(client))) {
				err = gridd_client_error(client);
			}
		}
		gridd_client_free(client);
	}

	return err;
}

GError*
m2v2_remote_execute_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_GET(sid, url, flags), out);
}

GError*
m2v2_remote_execute_GET_BY_CHUNK(const gchar *target, GByteArray *sid,
        struct hc_url_s *url, const gchar *chunk_id, gint64 limit, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_GET_BY_CHUNK(sid, url,
			chunk_id, limit), out);
}

GError*
m2v2_remote_execute_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean sync_del, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_DEL(sid, url, sync_del), out);
}

GError*
m2v2_remote_execute_RAW_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *beans)
{
	return _m2v2_request(target, m2v2_remote_pack_RAW_DEL(sid, url, beans), NULL);
}

GError*
m2v2_remote_execute_SUBST_CHUNKS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *new_chunks, GSList *old_chunks,
		gboolean restrict_to_alias)
{
	return _m2v2_request(target, m2v2_remote_pack_SUBST_CHUNKS(sid, url,
			new_chunks, old_chunks, restrict_to_alias), NULL);
}

GError*
m2v2_remote_execute_SUBST_CHUNKS_single(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, struct bean_CHUNKS_s *new_chunk,
		struct bean_CHUNKS_s *old_chunk, gboolean restrict_to_alias)
{
	GSList *new_chunks = g_slist_prepend(NULL, new_chunk);
	GSList *old_chunks = g_slist_prepend(NULL, old_chunk);
	GError *res = m2v2_remote_execute_SUBST_CHUNKS(target, sid, url,
			new_chunks, old_chunks, restrict_to_alias);
	g_slist_free(new_chunks);
	g_slist_free(old_chunks);
	return res;
}

GError*
m2v2_remote_execute_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_LIST(sid, url, flags), out);
}

GError*
m2v2_remote_execute_PROP_SET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList *in)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_SET(sid, url, flags, in), NULL);
}

GError*
m2v2_remote_execute_PROP_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_GET(sid, url, flags), out);
}

GError*
m2v2_remote_execute_SNAP_TAKE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_SNAP_TAKE(sid, url), NULL);
}

GError*
m2v2_remote_execute_SNAP_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_SNAP_LIST(sid, url), out);
}

GError*
m2v2_remote_execute_SNAP_RESTORE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean hard_restore)
{
	return _m2v2_request(target,
			m2v2_remote_pack_SNAP_RESTORE(sid, url, hard_restore), NULL);
}

GError*
m2v2_remote_execute_SNAP_DELETE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_SNAP_DELETE(sid, url), NULL);
}


GError* m2v2_remote_touch_content(const gchar *target, GByteArray *sid,
        struct hc_url_s *url)
{
	    return _m2v2_request(target, m2v2_remote_pack_TOUCH_content(sid, url), NULL);
}


GError* m2v2_remote_touch_container_ex(const gchar *target, GByteArray *sid,
        struct hc_url_s *url, guint32 flags)
{
	return _m2v2_request(target, m2v2_remote_pack_TOUCH_container(sid, url, flags), NULL);
}





