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

#ifndef OIO_SDS__metautils__lib__asn_ServiceInfo_h
# define OIO_SDS__metautils__lib__asn_ServiceInfo_h 1

#include "./metatypes.h"
#include "./ServiceInfo.h"
#include "./ServiceInfoSequence.h"

gboolean service_info_ASN2API(ServiceInfo_t * asn, service_info_t * api);
gboolean service_info_API2ASN(service_info_t * api, ServiceInfo_t * asn);
void service_info_cleanASN(ServiceInfo_t * asn, gboolean only_content);

#endif /*OIO_SDS__metautils__lib__asn_ServiceInfo_h*/