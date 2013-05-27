/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "metacomm.volume_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_VolumeInfo.h"
#include "./asn_AddrInfo.h"
#include "./asn_Score.h"


gboolean
volume_info_ASN2API(const VolumeInfo_t * asn, volume_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	memcpy(api->name, asn->volume.buf, MIN(LIMIT_LENGTH_VOLUMENAME, asn->volume.size));
	score_ASN2API(&(asn->score), &(api->score));
	addr_info_ASN2API(&(asn->addr), &(api->addr));

	return TRUE;
}


gboolean
volume_info_API2ASN(const volume_info_t * api, VolumeInfo_t * asn)
{
	if (!api || !asn)
		return FALSE;

	OCTET_STRING_fromBuf(&(asn->volume), api->name, MIN(strlen(api->name), LIMIT_LENGTH_VOLUMENAME));
	addr_info_API2ASN(&(api->addr), &(asn->addr));
	score_API2ASN(&(api->score), &(asn->score));

	return TRUE;
}


void
volume_info_cleanASN(VolumeInfo_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_VolumeInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_VolumeInfo, asn);

	errno = 0;
}
