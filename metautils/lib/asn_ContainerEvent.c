#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.container_event.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_ContainerEvent.h"


gboolean
container_event_ASN2API(const ContainerEvent_t * asn, container_event_t * api)
{
	if (!api || !asn) {
		errno = EINVAL;
		return FALSE;
	}
	if (!asn->eventMessage.buf) {
		errno = EINVAL;
		return FALSE;
	}

	asn_INTEGER_to_int64(&(asn->timestamp), &(api->timestamp));
	asn_INTEGER_to_int64(&(asn->rowid), &(api->rowid));
	memcpy(api->type, asn->type.buf, MIN(LIMIT_LENGTH_TYPE, asn->type.size));
	memcpy(api->ref, asn->ref.buf, MIN(LIMIT_LENGTH_REF, asn->ref.size));
	api->message = g_byte_array_append(g_byte_array_new(), asn->eventMessage.buf, asn->eventMessage.size);

	errno = 0;
	return TRUE;
}


gboolean
container_event_API2ASN(const container_event_t * api, ContainerEvent_t * asn)
{
	char ref[LIMIT_LENGTH_REF];
	char type[LIMIT_LENGTH_TYPE];

	if (!api || !asn || !api->message) {
		errno = EINVAL;
		return FALSE;
	}

	if (0 != asn_int64_to_INTEGER(&(asn->rowid), api->rowid))
		return FALSE;

	if (0 != asn_int64_to_INTEGER(&(asn->timestamp), api->timestamp))
		return FALSE;
	
	memset(type, '\0', sizeof(type));
	memcpy(type, api->type, sizeof(type) - 1);
	OCTET_STRING_fromBuf(&(asn->type), type, strlen(type));

	memset(ref, '\0', sizeof(ref));
	memcpy(ref, api->ref, sizeof(ref) - 1);
	OCTET_STRING_fromBuf(&(asn->ref), ref, strlen(ref));

	g_byte_array_append(api->message, (guint8*)"", 1);
	g_byte_array_set_size(api->message, api->message->len - 1 );

	OCTET_STRING_fromBuf(&(asn->eventMessage), (gchar*)api->message->data,
			api->message->len);

	errno = 0;
	return TRUE;
}


void
container_event_cleanASN(ContainerEvent_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ContainerEvent, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_ContainerEvent, asn);

	errno = 0;
}

