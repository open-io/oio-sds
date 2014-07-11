#include "internals.h"

static GByteArray*
_addrinfo_pack_singleton(const addr_info_t *ai, GError **err)
{
	addr_info_t wrkaddr;
	GSList *l;
	GByteArray *gba;

	memcpy(&wrkaddr, ai, sizeof(addr_info_t));

	l = g_slist_prepend(NULL, &wrkaddr);
	gba = addr_info_marshall_gba(l, err);
	g_slist_free(l);

	return gba;
}

static gboolean
_add_singleton_address(MESSAGE req, const gchar *field, gsize field_size,
	const addr_info_t *ai, GError **err)
{
	gboolean rc;
	GByteArray *gba;

	if (!(gba = _addrinfo_pack_singleton(ai, err))) {
		GSETERROR(err, "serializa error");
		return FALSE;
	}
	
        rc = message_add_field(req, field, field_size, gba->data,  gba->len, err);
	g_byte_array_free(gba, TRUE);

	return rc;
}

static gint
manage_progress(GError **err, gpointer udata, gint code, MESSAGE req)
{
	(void) udata;
	(void) err;
	(void) code;
	(void) req;
	DEBUG("Restore still in progress");
	return 1;
}

status_t
meta2_remote_restorev1_container(
		struct metacnx_ctx_s *dst_cnx, const container_id_t dst_cid,
		const addr_info_t *src_addr, const container_id_t src_cid,
		GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 201, 0, NULL, manage_progress },
		{ 0,0,NULL,NULL}
	};

	MESSAGE request = NULL;
	status_t status = 0;
	struct reply_sequence_data_s data = { NULL, 0 , codes };

	if (!dst_cnx || !src_addr || !dst_cid || !src_cid) {
		GSETCODE(err, EINVAL, "Invalid parameter (%p %p %p %p)", dst_cnx, dst_cid, src_addr, src_cid);
		return 0;
	}

	/*prepare the request, fill all the fields*/
	request = meta2_remote_build_request( err, dst_cnx->id, "REQ_M2RAW_RESTORE_CONTAINER");
	if (!request) {
		GSETERROR(err,"message error");
		goto error_check;
	}
	if (!message_add_field(request, STATIC_STRLEN("DST_CID"), (guint8*)dst_cid, sizeof(container_id_t), err)) {
		GSETERROR(err, "message error");
		goto error_label;
	}
	if (!message_add_field(request, STATIC_STRLEN("SRC_CID"), (guint8*)src_cid, sizeof(container_id_t), err)) {
		GSETERROR(err, "message error");
		goto error_label;
	}
	if (!_add_singleton_address(request, STATIC_STRLEN("SRC_ADDR"), src_addr, err)) {
		GSETERROR(err, "message error");
		goto error_label;
	}

	/*Now send the request*/
	if (!metacnx_open(dst_cnx, err)) {
		GSETERROR(err,"Failed to open the connexion");
		goto error_label;
	}

	if (!metaXClient_reply_sequence_run_context (err, dst_cnx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request,NULL);
error_check:
	return status;
}

