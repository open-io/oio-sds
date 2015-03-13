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

#ifndef OIO_SDS__metautils__lib__asn_Meta0Info_h
# define OIO_SDS__metautils__lib__asn_Meta0Info_h 1

#include "./metatypes.h"
#include "./AddrInfo.h"
#include "./Meta0Info.h"

gboolean meta0_info_ASN2API(const Meta0Info_t * asn, meta0_info_t * api);
gboolean meta0_info_API2ASN(const meta0_info_t * api, Meta0Info_t * asn);
void meta0_info_cleanASN(Meta0Info_t * asn, gboolean only_content);

#endif /*OIO_SDS__metautils__lib__asn_Meta0Info_h*/