#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "bean"
#endif

#include <stdlib.h>
#include <string.h>

#include <asn_SEQUENCE_OF.h>

#include <metautils/lib/metautils.h>
#include <M2V2BeanSequence.h>

#include <meta2v2/generic.h>
#include <meta2v2/meta2_bean.h>

struct anonymous_sequence_s
{
	asn_anonymous_set_ list;
	asn_struct_ctx_t _asn_ctx;
};

static void bean_gclean(gpointer bean, gpointer ignored)
{
	(void) ignored;
	if (!bean)
		return;
	_bean_clean(bean);
}

GByteArray *
bean_sequence_marshall(GSList *beans)
{
	gboolean error_occured = FALSE;
	gsize probable_size;
	asn_enc_rval_t encRet;
	struct anonymous_sequence_s asnSeq;
	GByteArray *gba = NULL;

	int func_write(const void *b, gsize bSize, void *key)
	{
		(void) key;
		return g_byte_array_append(gba, (guint8 *) b, bSize) ? 0 : -1;
	}

	void func_free(void *d)
	{
		if (!d)
			return;
		bean_cleanASN(d, FALSE);
	}

	void func_fill(gpointer d, gpointer u)
	{
		asn_anonymous_set_ *p_set;
		M2V2Bean_t *asn1;

		if (error_occured || !d)
			return;
		asn1 = g_malloc0(sizeof(M2V2Bean_t));
		if (!bean_API2ASN(d, asn1)) {
			g_free(asn1);
			GRID_ERROR("Element of type [M2V2Bean] serialization failed!");
			error_occured = TRUE;
		} else {
			p_set = &(((struct anonymous_sequence_s *) u)->list);
			asn_set_add(_A_SET_FROM_VOID(p_set), asn1);
		}
	}

	GRID_TRACE("Serializing a list of %d elements", g_slist_length(beans));

	probable_size = g_slist_length(beans) * (sizeof(M2V2Bean_t) + 6) + 64;
	probable_size = MIN(probable_size, 4096);

	gba = g_byte_array_sized_new(probable_size);
	if (!gba) {
		GRID_ERROR("Memory allocation failure");
		return NULL;
	}

	/*fills the ASN.1 structure */
	memset(&asnSeq, 0x00, sizeof(asnSeq));
	g_slist_foreach(beans, &func_fill, &asnSeq);
	if (error_occured) {
		g_byte_array_free(gba, TRUE);
		GRID_ERROR("list serialisation error");
		return NULL;
	}

	/*serializes the structure */
	encRet = der_encode(&asn_DEF_M2V2BeanSequence, &asnSeq, func_write, NULL);
	if (encRet.encoded == -1) {
		GRID_ERROR("Cannot encode the ASN.1 sequence (error on %s)", encRet.failed_type->name);
		g_byte_array_free(gba, TRUE);
		asnSeq.list.free = &func_free;
		asn_set_empty(&(asnSeq.list));
		return NULL;
	}

	GRID_TRACE("marshalling done (%p size=%i/%u)", gba->data, gba->len, gba->len);

	/*free the ASN.1 structure and the working buffer */
	asnSeq.list.free = &func_free;
	asn_set_empty(&asnSeq);
	return gba;
}

GSList *
bean_sequence_unmarshall(const guint8 *buf, gsize buf_len)
{
	GSList *l = NULL;
	GError *err = NULL;
	gint rc = 0;
	
	rc = bean_sequence_decoder(&l, buf, &buf_len, &err);
	if (rc <= 0) {
	//if (!bean_sequence_decoder(&l, buf, &buf_len, &err)) {
		if (err)
			GRID_ERROR("Decoder error: (%d) %s", err->code, err->message);
		else
			GRID_ERROR("Decoder error: (%d) %s", 0, "unknown error");
		g_clear_error(&err);
		return NULL;
	}

	return l;
}

gint
bean_sequence_decoder(GSList **l, const void *buf, gsize *buf_len, GError **err)
{
	void *result = NULL;
	gint i = 0, max = 0;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	struct anonymous_sequence_s *abstract_sequence;
	GSList *beans = NULL;

	void func_free(void *d) {
		if (!d)
			return;
		bean_cleanASN(d, FALSE);
	}

	if (!buf || !buf_len || !*buf_len) {
		GRID_DEBUG("Invalid parameter, nothing to unmarshall");
		return -1;
	}

	codecCtx.max_stack_size = 1 << 19;
	decRet = ber_decode(&codecCtx, &asn_DEF_M2V2BeanSequence, &(result), buf, *buf_len);

	switch (decRet.code) {
		case RC_OK:
			abstract_sequence = (struct anonymous_sequence_s *) result;

			GRID_TRACE("Sequence of M2V2Bean successfully decoded, %d/%d elements",
					abstract_sequence->list.count, abstract_sequence->list.size);

			/*fill the list with the content of the array */
			for (i = 0, max = abstract_sequence->list.count; i < max; i++) {
				gpointer bean = NULL;
				bean = bean_ASN2API(abstract_sequence->list.array[i]);
				if(!bean) {
					GSETERROR(err, "[M2V2Bean] ASN-to-API conversion error");

					abstract_sequence->list.free = &func_free;
					asn_set_empty(abstract_sequence);
					g_free(abstract_sequence);

					if (beans) {
						g_slist_foreach(beans, bean_gclean, NULL);
						g_slist_free(beans);
					}
					return -1;
				}
				beans = g_slist_prepend(beans, bean);
			}
			if (abstract_sequence->list.size > 0) {
				abstract_sequence->list.free = &func_free;
				asn_set_empty(abstract_sequence);
			}
			g_free(abstract_sequence);
			*l = beans;
			return decRet.consumed;

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

