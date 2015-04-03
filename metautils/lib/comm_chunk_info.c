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
#define G_LOG_DOMAIN "metacomm.chunk_info"
#endif

#include "./metautils_internals.h"

#include "./asn_AddrInfo.h"
#include "./asn_ChunkInfo.h"

#include "./AddrInfo.h"
#include "./AddrInfoSequence.h"
#include "./ChunkInfo.h"
#include "./ChunkInfoSequence.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ChunkInfo_t),
	sizeof(chunk_info_t),
	&asn_DEF_ChunkInfoSequence,
	(abstract_converter_f) chunk_info_ASN2API,
	(abstract_converter_f) chunk_info_API2ASN,
	(abstract_asn_cleaner_f) chunk_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"chunk_info"
};

DEFINE_MARSHALLER(chunk_info_marshall);
DEFINE_MARSHALLER_GBA(chunk_info_marshall_gba);
DEFINE_UNMARSHALLER(chunk_info_unmarshall);
DEFINE_BODY_MANAGER(chunk_info_concat, chunk_info_unmarshall);

