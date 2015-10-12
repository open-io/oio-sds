/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__sdk__http_internals_h
# define OIO_SDS__sdk__http_internals_h 1

#ifdef __cplusplus
extern "C" {
#endif

# ifndef  OIOSDS_http_agent
#  define OIOSDS_http_agent "OpenIO-SDS/SDK-2.0"
# endif

CURL * _curl_get_handle (void);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__sdk__http_internals_h*/
