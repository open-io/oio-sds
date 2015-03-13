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
# define G_LOG_DOMAIN "metacomm.path_info"
#endif

#include "./metautils_internals.h"
#include "./PathInfo.h"
#include "./PathInfoSequence.h"
#include "./asn_PathInfo.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(PathInfo_t),
	sizeof(path_info_t),
	&asn_DEF_PathInfoSequence,
	(abstract_converter_f) path_info_ASN2API,
	(abstract_converter_f) path_info_API2ASN,
	(abstract_asn_cleaner_f) path_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"path_info"
};

DEFINE_MARSHALLER_GBA(path_info_marshall_gba);
DEFINE_MARSHALLER(path_info_marshall);
DEFINE_UNMARSHALLER(path_info_unmarshall);
DEFINE_BODY_MANAGER(path_info_concat, path_info_unmarshall);

