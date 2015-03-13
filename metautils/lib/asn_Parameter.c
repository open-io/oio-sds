/*
OpenIO SDS metautils
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
#define G_LOG_DOMAIN "metacomm.parameter.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_Parameter.h"

gboolean
key_value_pair_ASN2API(const Parameter_t * asn, key_value_pair_t * api)
{
	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}
	if (!asn->name.buf || !asn->value.buf) {
		errno = EINVAL;
		return FALSE;
	}

	memset(api,0x00,sizeof(key_value_pair_t));
	api->key = g_strndup((const gchar*)asn->name.buf, asn->name.size);
	api->value = g_byte_array_append(g_byte_array_new(), asn->value.buf, asn->value.size);

	if (!api->key || !api->value) {
		if (api->key)
			g_free(api->key);
		if (api->value)
			g_byte_array_free(api->value, TRUE);
		memset(api,0x00,sizeof(key_value_pair_t));
		errno = ENOMEM;
		return FALSE;
	}

	errno = 0;
	return TRUE;
}

gboolean
key_value_pair_API2ASN(const key_value_pair_t * api, Parameter_t * asn)
{
	if (!asn || !api || !api->key || !api->value) {
		ERROR("Invalid parameter");
		return FALSE;
	}

	memset(asn, 0x00, sizeof(Parameter_t));

	if (0>OCTET_STRING_fromBuf(&(asn->name), api->key, strlen(api->key))) {
		WARN("Serialization error (key)");
		return FALSE;
	}

	if (0>OCTET_STRING_fromBuf(&(asn->value), (const char*)api->value->data, api->value->len)) {
		WARN("Serialization error (value)");
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &(asn->name));
		return FALSE;
	}

	return TRUE;
}

void
key_value_pair_cleanASN(Parameter_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Parameter, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Parameter, asn);

	errno = 0;
}

