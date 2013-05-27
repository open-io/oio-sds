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
#define LOG_DOMAIN "metacomm.score.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "asn_Score.h"


gboolean
score_ASN2API(const Score_t * asn, score_t * api)
{
	if (!api || !asn)
		return FALSE;

	asn_INTEGER_to_int32(&(asn->value), &(api->value));
	asn_INTEGER_to_int32(&(asn->timestamp), &(api->timestamp));

	return TRUE;
}


gboolean
score_API2ASN(const score_t * api, Score_t * asn)
{
	if (!api || !asn)
		return FALSE;

	asn_int32_to_INTEGER(&(asn->value), api->value);
	asn_int32_to_INTEGER(&(asn->timestamp), api->timestamp);

	return TRUE;
}


void
score_cleanASN(Score_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Score, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Score, asn);

	errno = 0;
}
