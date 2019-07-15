/*
OpenIO SDS metautils
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

/*
Copyright (c) 2003-2014  Lev Walkin <vlm@lionet.info>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
*/

#include <errno.h>

#include "metautils.h"
#include "codec.h"

int
metautils_asn_INTEGER_to_int64(const INTEGER_t *iptr, int64_t *pI64)
{
	uint8_t *b, *end;
	size_t size;
	int64_t ll;

	/* Sanity checking */
	if(!iptr || !iptr->buf || !pI64) {
		errno = EINVAL;
		return -1;
	}

	/* Cache the begin/end of the buffer */
	b = iptr->buf;  /* Start of the INTEGER buffer */
	size = iptr->size;
	end = b + size; /* Where to stop */

	if(size > sizeof(ll)) {
		uint8_t *end1 = end - 1;
		/* Slightly more advanced processing,
		 * able to >sizeof(long) bytes,
		 * when the actual value is small
		 * (0x0000000000abcdef would yield a fine 0x00abcdef)
		 */
		/* Skip out the insignificant leading bytes */
		for(; b < end1; b++) {
			switch(*b) {
				case 0x00: if((b[1] & 0x80) == 0) continue; break;
				case 0xff: if((b[1] & 0x80) != 0) continue; break;
			}
			break;
		}

		size = end - b;
		if(size > sizeof(ll)) {
			/* Still cannot fit the long */
			errno = ERANGE;
			return -1;
		}
	}

	/* Shortcut processing of a corner case */
	if(end == b) {
		*pI64 = 0;
		return 0;
	}

	/* Perform the sign initialization */
	/* Actually ll = -(*b >> 7); gains nothing, yet unreadable! */
	if((*b >> 7)) ll = -1; else ll = 0;

	/* Conversion engine */
	for(; b < end; b++)
		ll = (ll << 8) | *b;

	*pI64 = ll;
	return 0;
}

int
metautils_asn_INTEGER_to_int32(const INTEGER_t *st, int32_t *pI32)
{
	int64_t i64=0;
	if (!pI32 || !st) {
		errno = EINVAL;
		return -1;
	}
	if (-1== metautils_asn_INTEGER_to_int64(st, &i64))
		return -1;
	if (i64>INT32_MAX || i64<INT32_MIN) {
		errno=ERANGE;
		return -1;
	}
	*pI32 = i64;
	return 0;
}

int
metautils_asn_INTEGER_to_uint16(const INTEGER_t *st, uint16_t *pU16)
{
	int64_t i64=0;
	if (!pU16 || !st) {
		errno = EINVAL;
		return -1;
	}
	if (-1== metautils_asn_INTEGER_to_int64(st, &i64))
		return -1;
	if (i64>UINT16_MAX || i64<0) {
		errno=ERANGE;
		return -1;
	}
	*pU16 = i64;
	return 0;
}

static int
asn_intX_to_INTEGER(INTEGER_t *st, void* pValue, size_t valueSize)
{
	uint8_t *buf, *bp;
	uint8_t *p;
	uint8_t *pstart;
	uint8_t *pend1;
	int littleEndian = 1;   /* Run-time detection */
	int add;

	if(!st) {
		errno = EINVAL;
		return -1;
	}

	if (!pValue || valueSize>8 || valueSize<1) {
		errno = EINVAL;
		return -1;
	}

	buf = (uint8_t *)MALLOC(valueSize);
	if(!buf) return -1;

	if(*(char *)&littleEndian) {
		pstart = (uint8_t *)pValue + valueSize - 1;
		pend1 = (uint8_t *)pValue;
		add = -1;
	} else {
		pstart = (uint8_t *)pValue;
		pend1 = pstart + valueSize - 1;
		add = 1;
	}

	/*
	 * If the contents octet consists of more than one octet,
	 * then bits of the first octet and bit 8 of the second octet:
	 * a) shall not all be ones; and
	 * b) shall not all be zero.
	 */
	for(p = pstart; p != pend1; p += add) {
		switch(*p) {
			case 0x00: if((*(p+add) & 0x80) == 0)
						   continue;
					   break;
			case 0xff: if((*(p+add) & 0x80))
						   continue;
					   break;
		}
		break;
	}
	/* Copy the integer body */
	for(pstart = p, bp = buf, pend1 += add; p != pend1; p += add)
		*bp++ = *p;

	if(st->buf) FREEMEM(st->buf);
	st->buf = buf;
	st->size = bp - buf;

	return 0;
}

int
metautils_asn_int64_to_INTEGER(INTEGER_t *st, int64_t v)
{
	return asn_intX_to_INTEGER(st, &v, sizeof(v));
}

int
metautils_asn_int32_to_INTEGER(INTEGER_t *st, int32_t v)
{
	return asn_intX_to_INTEGER(st, &v, sizeof(v));
}

int
metautils_asn_uint32_to_INTEGER(INTEGER_t *st, uint32_t v)
{
	int64_t i64 = v;
	return asn_intX_to_INTEGER(st, &i64, sizeof(i64));
}

int
metautils_asn_uint16_to_INTEGER(INTEGER_t *st, uint16_t v)
{
	int32_t i32 = v;
	return asn_intX_to_INTEGER(st, &i32, sizeof(i32));
}
