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
#define G_LOG_DOMAIN "metacomm.meta0_info"
#endif

#include "./metautils_internals.h"
#include "./asn_Meta0Info.h"
#include "./Meta0Info.h"
#include "./Meta0InfoSequence.h"

static const struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(Meta0Info_t),
	sizeof(meta0_info_t),
	&asn_DEF_Meta0InfoSequence,
	(abstract_converter_f) meta0_info_ASN2API,
	(abstract_converter_f) meta0_info_API2ASN,
	(abstract_asn_cleaner_f) meta0_info_cleanASN,
	(abstract_api_cleaner_f) meta0_info_clean,
	"meta0_info"
};

DEFINE_MARSHALLER(meta0_info_marshall)
DEFINE_UNMARSHALLER(meta0_info_unmarshall)
DEFINE_MARSHALLER_GBA(meta0_info_marshall_gba)

