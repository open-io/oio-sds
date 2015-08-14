/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core__core_h
# define OIO_SDS__core__core_h 1

# define GQ() g_quark_from_static_string(G_LOG_DOMAIN)
# define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)

# include "core/oiocfg.h"
# include "core/oioext.h"
# include "core/oiolog.h"
# include "core/oiostr.h"
# include "core/oiourl.h"
#endif /*OIO_SDS__core__core_h*/
