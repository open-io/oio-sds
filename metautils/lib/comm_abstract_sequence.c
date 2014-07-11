#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.as"
#endif /*G_LOG_DOMAIN */
#include "metautils_internals.h"
#include <INTEGER.h>
#include <asn_SEQUENCE_OF.h>

struct anonymous_sequence_s
{
	asn_anonymous_set_ list;
	asn_struct_ctx_t _asn_ctx;
};

static void api_gclean(gpointer p1, gpointer p2) {
	abstract_api_cleaner_f cleanAPI;
	if (!p1)
		return;
	cleanAPI = p2;
	cleanAPI(p1);
}

gssize
abstract_sequence_unmarshall(const struct abstract_sequence_handler_s *h,
    GSList ** list, const void *asn1_encoded, gsize asn1_encoded_size, GError ** err)
{
	gssize consumed;
	void *result = NULL;
	gint i = 0, max = 0;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	struct anonymous_sequence_s *abstract_sequence;
	GSList *api_result = NULL;

	void func_free(void *d)
	{
		if (!d)
			return;
		h->clean_ASN1(d, FALSE);
	}

	if (!asn1_encoded || !list) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	codecCtx.max_stack_size = 1 << 19;
	decRet = ber_decode(&codecCtx, h->asn1_descriptor, &(result), asn1_encoded, asn1_encoded_size);

	switch (decRet.code) {
	case RC_OK:
		abstract_sequence = (struct anonymous_sequence_s *) result;

		/*fill the list with the content of the array */
		for (i = 0, max = abstract_sequence->list.count; i < max; i++) {
			void *api_structure;

			if (!(api_structure = g_try_malloc0(h->api_size))
				|| !h->map_ASN1_to_API(abstract_sequence->list.array[i], api_structure))
			{
				GSETERROR(err,"Element of type [%s] ASN-to-API conversion error", h->type_name);

				if (api_structure)
					h->clean_API(api_structure);

				abstract_sequence->list.free = &func_free;
				asn_set_empty(abstract_sequence);
				g_free(abstract_sequence);

				if (api_result) {
					g_slist_foreach(api_result, api_gclean, h->clean_API);
					g_slist_free(api_result);
				}
				return -1;
			}
			api_result = g_slist_prepend(api_result, api_structure);
		}
		if (abstract_sequence->list.size > 0) {
			abstract_sequence->list.free = &func_free;
			asn_set_empty(abstract_sequence);
		}
		g_free(abstract_sequence);
		*list = g_slist_concat(*list, api_result);
		consumed = decRet.consumed;
		return consumed;

	case RC_FAIL:
		GSETERROR(err, "sequence unmarshalling error (%i consumed)", decRet.consumed);
		return -1;

	case RC_WMORE:
		GSETERROR(err, "sequence unmarshalling error (uncomplete)");
		return 0;
	default:
		GSETERROR(err, "Serialisation produced an unknow return code : %d", decRet.code);
		return -1;
	}


	return -1;
}

GByteArray *
abstract_sequence_marshall(const struct abstract_sequence_handler_s * h, GSList * api_sequence, GError ** err)
{
	gboolean error_occured = FALSE;
	gsize probable_size;
	asn_enc_rval_t encRet;
	struct anonymous_sequence_s asnSeq;
	GByteArray *gba;

	int func_write(const void *b, gsize bSize, void *key)
	{
		(void) key;
		return g_byte_array_append(gba, (guint8 *) b, bSize) ? 0 : -1;
	}

	void func_free(void *d)
	{
		if (!d)
			return;
		h->clean_ASN1(d, FALSE);
	}

	void func_fill(gpointer d, gpointer u)
	{
		asn_anonymous_set_ *p_set;
		void *asn1_form;

		if (error_occured || !d)
			return;
		asn1_form = g_malloc0(h->asn1_size);
		if (!h->map_API_to_ASN1(d, asn1_form)) {
			g_free(asn1_form);
			GSETERROR(err, "Element of type [%s] serialization failed!", h->type_name);
			error_occured = TRUE;
		} else {
			p_set = &(((struct anonymous_sequence_s *) u)->list);
			asn_set_add(_A_SET_FROM_VOID(p_set), asn1_form);
		}
	}

	probable_size = g_slist_length(api_sequence) * (h->asn1_size + 6) + 64;
	probable_size = MIN(probable_size, 4096);

	gba = g_byte_array_sized_new(probable_size);
	if (!gba) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	/*fills the ASN.1 structure */
	memset(&asnSeq, 0x00, sizeof(asnSeq));
	g_slist_foreach(api_sequence, &func_fill, &asnSeq);
	if (error_occured) {
		g_byte_array_free(gba, TRUE);
		GSETERROR(err, "list serialisation error");
		return NULL;
	}

	/*serializes the structure */
	encRet = der_encode(h->asn1_descriptor, &asnSeq, func_write, NULL);
	if (encRet.encoded == -1) {
		GSETERROR(err, "Cannot encode the ASN.1 sequence (error on %s)", encRet.failed_type->name);
		g_byte_array_free(gba, TRUE);
		asnSeq.list.free = &func_free;
		asn_set_empty(&(asnSeq.list));
		return NULL;
	}

	/*free the ASN.1 structure and the working buffer */
	asnSeq.list.free = &func_free;
	asn_set_empty(&asnSeq);
	return gba;
}

/**
 * Contacts a distant server with the usual Message protocol and
 * require an abstract list of structures.
 *
 * Pass an additional NULL-terminated list of (gchar*,GByteArray*), they will
 * be used ah headers in the requests
 */

static MESSAGE
build_request(const gchar * req_name, void *body, gsize body_size, GError ** error)
{
	MESSAGE req = NULL;

	if (!message_create(&req, error)) {
		GSETERROR(error, "Failed to create a new message named %s", req_name);
		return NULL;
	}

	if (!message_set_NAME(req, req_name, strlen(req_name), error)) {
		GSETERROR(error, "Failed to set message name %s", req_name);
		message_destroy(req, NULL);
		return NULL;
	}

	if (body && !message_set_BODY(req, body, body_size, error)) {
		GSETERROR(error, "Failed to set a body to message named %s", req_name);
		message_destroy(req, NULL);
		return NULL;
	}

	return (req);
}

struct alist_request_s
{
	GSList *result;
	const struct abstract_sequence_handler_s *h;
};

static gboolean
abstract_list_content_handler(GError ** error, gpointer u, gint c, guint8 * b, gsize bS)
{
	(void) c;
	struct alist_request_s *al_req = u;
	GSList *list_from_body = NULL;

	if (0 > abstract_sequence_unmarshall(al_req->h, &list_from_body, b, bS, error)) {
		GSETERROR(error, "Cannot unmarshall body of message as service_info");
		return (FALSE);
	}

	al_req->result = g_slist_concat(list_from_body, al_req->result);

	return (TRUE);
}

GSList *
abstract_sequence_request(struct metacnx_ctx_s * cnx, GError ** error,
    const struct abstract_sequence_handler_s * h, const gchar * req_name, GByteArray * body, va_list args)
{
	(void) body;
	(void) args;
	MESSAGE req = NULL;
	struct alist_request_s al_req;

	void element_gclean(gpointer p1, gpointer p2)
	{
		(void) p2;
		if (p1)
			h->clean_API(p1);
	}

	static struct code_handler_s codes[] = {
		{206, REPSEQ_BODYMANDATORY, &abstract_list_content_handler, NULL},
		{200, REPSEQ_FINAL, &abstract_list_content_handler, NULL},
		{0, 0, NULL, NULL}
	};

	struct reply_sequence_data_s data = { &al_req, 0, codes };

	if (!h || !cnx) {
		GSETERROR(error, "Invalid parameter");
		return NULL;
	}

	al_req.h = h;
	al_req.result = NULL;

	/*Create the request, send it and read the answers */
	req = build_request(req_name, NULL, 0, error);
	if (req == NULL) {
		GSETERROR(error, "Failed to build request");
		return NULL;
	}
	for (;;) {
		char *k;
		GByteArray *v;
		k = va_arg(args,char*);
		if (!k) break;
		v = va_arg(args,GByteArray*);
		if (!v) break;
		message_add_field(req, k, strlen(k), v->data, v->len, error);
	}
	if (metaXClient_reply_sequence_run_context(error, cnx, req, &data)) {
		message_destroy(req, NULL);
		return (al_req.result);
	}

	/*an error happened */
	message_destroy(req, NULL);
	GSETERROR(error, "Cannot execute the query %s and receive all the responses", req_name);
	if (al_req.result) {
		if (h->clean_API)
			g_slist_foreach(al_req.result, element_gclean, NULL);
		g_slist_free(al_req.result);
		al_req.result = NULL;
	}
	return (NULL);
}
