/*
OpenIO SDS core library
Copyright (C) 2017-2018 OpenIO SAS, as part of OpenIO SDS

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
#ifndef OIO_SDS__sdk__http_del_h
# define OIO_SDS__sdk__http_del_h 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

GError * http_poly_delete (gchar **urlv);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__sdk__http_del_h*/
