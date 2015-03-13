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

#ifndef OIO_SDS__metautils__lib__asn_Parameter_h
# define OIO_SDS__metautils__lib__asn_Parameter_h 1

#include "./metatypes.h"
#include "./Parameter.h"

gboolean key_value_pair_ASN2API(const Parameter_t * asn, key_value_pair_t * api);
gboolean key_value_pair_API2ASN(const key_value_pair_t * api, Parameter_t * asn);
void key_value_pair_cleanASN(Parameter_t * asn, gboolean only_content);

#endif /*OIO_SDS__metautils__lib__asn_Parameter_h*/