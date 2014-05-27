#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.service_info"
#endif

#include <errno.h>

#include "./metautils_internals.h"
#include "./ServiceTag.h"
#include "./ServiceInfo.h"
#include "./ServiceInfoSequence.h"

#include "./asn_SET_OF.h"
#include "./asn_AddrInfo.h"
#include "./asn_Score.h"
#include "./asn_ServiceInfo.h"

static const struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ServiceInfo_t),
	sizeof(service_info_t),
	&asn_DEF_ServiceInfoSequence,
	(abstract_converter_f) service_info_ASN2API,
	(abstract_converter_f) service_info_API2ASN,
	(abstract_asn_cleaner_f) service_info_cleanASN,
	(abstract_api_cleaner_f) service_info_clean,
	"service_info"
};

static gboolean
service_tag_ASN2API(ServiceTag_t * asn, service_tag_t * api)
{
	if (!api || !asn)
		return FALSE;

	memset(api, 0x00, sizeof(service_tag_t));

	/*name */
	memcpy(api->name, asn->name.buf, MIN((size_t) asn->name.size, sizeof(api->name)));

	/*value */
	switch (asn->value.present) {
	case ServiceTag__value_PR_b:
		api->type = STVT_BOOL;
		api->value.b = asn->value.choice.b;
		return TRUE;
	case ServiceTag__value_PR_i:
		api->type = STVT_I64;
		asn_INTEGER_to_int64(&(asn->value.choice.i), &(api->value.i));
		return TRUE;
	case ServiceTag__value_PR_r:
		api->type = STVT_REAL;
		asn_REAL2double(&(asn->value.choice.r), &(api->value.r));
		return TRUE;
	case ServiceTag__value_PR_s:
		api->type = STVT_STR;
		api->value.s = g_strndup((const gchar*)asn->value.choice.s.buf, asn->value.choice.s.size);
		return TRUE;
	case ServiceTag__value_PR_macro:
		api->type = STVT_MACRO;
		api->value.macro.type = g_strndup((const gchar*)asn->value.choice.macro.type.buf, asn->value.choice.macro.type.size);
		api->value.macro.param =
		    g_strndup((const gchar*)asn->value.choice.macro.param.buf, asn->value.choice.macro.param.size);
		return TRUE;
	case ServiceTag__value_PR_NOTHING:
		return FALSE;
	}
	return FALSE;
}

gboolean
service_info_ASN2API(ServiceInfo_t * asn, service_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	memset(api, 0x00, sizeof(service_info_t));

	/*header */

	memcpy(api->ns_name, asn->nsName.buf, MIN((size_t) asn->nsName.size, sizeof(api->ns_name)));
	memcpy(api->type, asn->type.buf, MIN((size_t) asn->type.size, sizeof(api->type)));
	addr_info_ASN2API(&(asn->addr), &(api->addr));

	if (asn->score)
		score_ASN2API(asn->score, &(api->score));
	else {
		api->score.value = -2;
		api->score.timestamp = time(0);
	}

	/*tags */
	if (!asn->tags) {
		api->tags = g_ptr_array_new();
	}
	else {
		int i, max;

		api->tags = g_ptr_array_sized_new(asn->tags->list.count);
		for (i = 0, max = asn->tags->list.count; i < max; i++) {
			service_tag_t *api_tag;
			ServiceTag_t *asn_tag;

			api_tag = g_try_malloc0(sizeof(service_tag_t));
			asn_tag = asn->tags->list.array[i];
			service_tag_ASN2API(asn_tag, api_tag);
			g_ptr_array_add(api->tags, api_tag);
		}
	}

	return TRUE;
}

static gboolean
service_tag_API2ASN(service_tag_t * api, ServiceTag_t * asn)
{
	gsize name_len;

	if (!api || !asn) {
		return FALSE;
	}

	memset(asn, 0x00, sizeof(ServiceTag_t));

	/*name */
	name_len = strlen_len((const guint8*)api->name, sizeof(api->name));
	OCTET_STRING_fromBuf(&(asn->name), api->name, name_len);

	/*value */
	switch (api->type) {
	case STVT_STR:
		asn->value.present = ServiceTag__value_PR_s;
		OCTET_STRING_fromBuf(&(asn->value.choice.s), api->value.s, strlen(api->value.s));
		break;
	case STVT_BUF:
		asn->value.present = ServiceTag__value_PR_s;
		OCTET_STRING_fromBuf(&(asn->value.choice.s), api->value.buf, strlen_len((const guint8*)api->value.buf,
			sizeof(api->value.buf)));
		break;
	case STVT_REAL:
		asn->value.present = ServiceTag__value_PR_r;
		asn_double2REAL(&(asn->value.choice.r), api->value.r);
		break;
	case STVT_I64:
		asn->value.present = ServiceTag__value_PR_i;
		asn_int64_to_INTEGER(&(asn->value.choice.i), api->value.i);
		break;
	case STVT_BOOL:
		asn->value.present = ServiceTag__value_PR_b;
		asn->value.choice.b = api->value.b;
		break;
	case STVT_MACRO:
		asn->value.present = ServiceTag__value_PR_macro;
		OCTET_STRING_fromBuf(&(asn->value.choice.macro.type), api->value.macro.type,
		    strlen(api->value.macro.type));
		if (api->value.macro.param)
			OCTET_STRING_fromBuf(&(asn->value.choice.macro.param), api->value.macro.param,
			    strlen(api->value.macro.param));
		else
			OCTET_STRING_fromBuf(&(asn->value.choice.macro.param), "", 0);
		break;
	}
	return TRUE;
}


gboolean
service_info_API2ASN(service_info_t * api, ServiceInfo_t * asn)
{
	if (!api || !asn)
		return FALSE;

	memset(asn, 0x00, sizeof(ServiceInfo_t));

	/*header */
	OCTET_STRING_fromBuf(&(asn->type), api->type, strlen_len((const guint8*)api->type, sizeof(api->type)));
	OCTET_STRING_fromBuf(&(asn->nsName), api->ns_name, strlen_len((const guint8*)api->ns_name, sizeof(api->ns_name)));
	addr_info_API2ASN(&(api->addr), &(asn->addr));

	if (api->score.value >= -1) {
		asn->score = calloc(1, sizeof(Score_t));
		score_API2ASN(&(api->score), asn->score);
	}

	/*tags */
	if (api->tags) {
		service_tag_t *api_tag;
		ServiceTag_t *asn_tag;
		int i, max;

		/*init the array */
		asn->tags = calloc(1, sizeof(struct ServiceInfo__tags));

		/*fill the array */
		for (max = api->tags->len, i = 0; i < max; i++) {
			api_tag = (service_tag_t *)
			    g_ptr_array_index(api->tags, i);
			if (!api_tag)
				continue;
			asn_tag = calloc(1, sizeof(ServiceTag_t));
			if (!asn_tag)
				continue;
			service_tag_API2ASN(api_tag, asn_tag);
			asn_set_add(&(asn->tags->list), asn_tag);
		}
	}

	return TRUE;
}

static void
free_service_tag_ASN(ServiceTag_t * tag)
{
	if (tag) {
		asn_DEF_ServiceTag.free_struct(&asn_DEF_ServiceTag, tag, 0);
	}
}

void
service_info_cleanASN(ServiceInfo_t * asn, gboolean only_content)
{
	if (!asn)
		return;

	if (asn->tags)
		asn->tags->list.free = free_service_tag_ASN;

	if (only_content) {
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ServiceInfo, asn);
		bzero(asn, sizeof(*asn));
	}
	else
		ASN_STRUCT_FREE(asn_DEF_ServiceInfo, asn);

	errno = 0;
}

DEFINE_MARSHALLER(service_info_marshall);
DEFINE_UNMARSHALLER(service_info_unmarshall);
DEFINE_MARSHALLER_GBA(service_info_marshall_gba);
DEFINE_BODY_MANAGER(service_info_concat, service_info_unmarshall);

GSList *
service_info_sequence_request(struct metacnx_ctx_s *cnx, GError ** error,
    const gchar * req_name, GByteArray * body, ...)
{
	GSList *result;
	va_list args;

	va_start(args, body);
	result = abstract_sequence_request(cnx, error, &seq_descriptor, req_name, body, args);
	va_end(args);

	return result;
}

static int
func_write(const void *b, gsize bSize, void *key)
{
	GByteArray *gba = key;
	return g_byte_array_append(gba, (guint8 *) b, bSize) ? 0 : -1;
}

GByteArray*
service_info_marshall_1(service_info_t *si, GError **err)
{
	ServiceInfo_t asn;
	asn_enc_rval_t encRet;
	GByteArray *gba;

	if (!si) {
		GSETERROR(err, "invalid parameter");
		return NULL;
	}

	if (!service_info_API2ASN(si, &asn))
		ALERT("Conversion error");

	gba = g_byte_array_sized_new(64);
	encRet = der_encode(&asn_DEF_ServiceInfo, &asn, func_write, gba);
	service_info_cleanASN(&asn, TRUE);

	if (encRet.encoded == -1) {
		GSETERROR(err, "Serialization error on '%s'",
				encRet.failed_type->name);
		g_byte_array_free(gba, TRUE);
		return NULL;
	}

	return gba;
}

