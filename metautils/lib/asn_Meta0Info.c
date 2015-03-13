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
#define G_LOG_DOMAIN "metacomm.meta0_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_Meta0Info.h"
#include "./asn_AddrInfo.h"

gboolean
meta0_info_ASN2API(const Meta0Info_t * asn, meta0_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	memset(api, 0x00, sizeof(meta0_info_t));
	api->prefixes_size = asn->prefix.size;
	api->prefixes = g_malloc(api->prefixes_size);
	memcpy(api->prefixes, asn->prefix.buf, asn->prefix.size);
	addr_info_ASN2API(&(asn->addr), &(api->addr));
	return TRUE;
}

gboolean
meta0_info_API2ASN(const meta0_info_t * api, Meta0Info_t * asn)
{
	if (!api || !asn)
		return FALSE;

	memset(asn, 0x00, sizeof(Meta0Info_t));
	OCTET_STRING_fromBuf(&(asn->prefix), (char *) api->prefixes, api->prefixes_size);
	addr_info_API2ASN(&(api->addr), &(asn->addr));
	return TRUE;
}

void
meta0_info_cleanASN(Meta0Info_t * asn, gboolean only_content)
{
	if (!asn)
		return;
	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta0Info, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta0Info, asn);
	errno = 0;
}
