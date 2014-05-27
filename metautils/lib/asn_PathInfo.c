#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.path_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_PathInfo.h"


gboolean
path_info_ASN2API(const PathInfo_t * asn, path_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	memset(api->path, 0x00, LIMIT_LENGTH_CONTENTPATH);
	memcpy(api->path, asn->path.buf, MIN(LIMIT_LENGTH_CONTENTPATH - 1, asn->path.size));
	/*set the size */
	api->size = 0;
	if (asn->size) {
		asn_INTEGER_to_int64(asn->size, &(api->size));
		api->hasSize = TRUE;
	}
	else {
		api->hasSize = FALSE;
	}

	/*set the user_metadata */
	if (asn->userMetadata && asn->userMetadata->buf && asn->userMetadata->size > 0) {
		api->user_metadata = g_byte_array_sized_new(asn->userMetadata->size);
		g_byte_array_append(api->user_metadata, asn->userMetadata->buf, asn->userMetadata->size);
	}

	/*set the system_metadata */
	if (asn->systemMetadata && asn->systemMetadata->buf && asn->systemMetadata->size > 0) {
		api->system_metadata = g_byte_array_sized_new(asn->systemMetadata->size);
		g_byte_array_append(api->system_metadata, asn->systemMetadata->buf, asn->systemMetadata->size);
	}

	return TRUE;
}


gboolean
path_info_API2ASN(const path_info_t * api, PathInfo_t * asn)
{
	char path_name[LIMIT_LENGTH_CONTENTPATH];

	if (!api || !asn)
		return FALSE;

	if (api->hasSize) {
		asn->size = g_try_malloc0(sizeof(INTEGER_t));
		if (!asn->size) {
			WARN("<%s> memory allocation failure", __FUNCTION__);
			return FALSE;
		}
		asn_int64_to_INTEGER(asn->size, api->size);
	}

	memset(path_name, '\0', sizeof(path_name));
	memcpy(path_name, api->path, sizeof(path_name) - 1);

	OCTET_STRING_fromBuf(&(asn->path), path_name, strlen(path_name));

	/*setting the user_metadata */
	if (api->user_metadata && api->user_metadata->data && api->user_metadata->len > 0) {
		asn->userMetadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
		    (const char*)api->user_metadata->data, api->user_metadata->len);
	}

	/*setting the system_metadata */
	if (api->system_metadata && api->system_metadata->data && api->system_metadata->len > 0) {
		asn->systemMetadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
		    (const char*)api->system_metadata->data, api->system_metadata->len);
	}

	return TRUE;
}


void
path_info_cleanASN(PathInfo_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_PathInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_PathInfo, asn);

	errno = 0;
}
