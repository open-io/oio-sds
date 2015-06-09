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

#ifndef OIO_SDS__metautils__lib__metautils_internals_h
# define OIO_SDS__metautils__lib__metautils_internals_h 1

# include <stdarg.h>
# include <stdlib.h>
# include <unistd.h>
# include "metatypes.h"
# include "metautils.h"
# include "metacomm.h"

#define YY_INPUT(buf,result,max_size) \
	if ( YY_CURRENT_BUFFER_LVALUE->yy_is_interactive ) { \
		int c = '*'; size_t n; size_t max = max_size; /*tmp var to avoid a warning*/\
		for ( n = 0; n < max && \
			(c = getc( yyin )) != EOF && c != '\n'; ++n ) \
		buf[n] = (char) c; \
		if ( c == '\n' ) \
			buf[n++] = (char) c; \
		if ( c == EOF && ferror( yyin ) ) \
			YY_FATAL_ERROR( "input in flex scanner failed" ); \
		result = n; \
	} else { \
		size_t max = max_size; /*tmp var to avoid a warning*/\
		errno=0; \
		while ( (result = fread(buf, 1, max, yyin))==0 && ferror(yyin)) { \
			if( errno != EINTR) { \
				YY_FATAL_ERROR( "input in flex scanner failed" ); \
				break; \
			} \
			errno=0; \
			clearerr(yyin); \
		} \
	}\

#define ERRNO_RESETBYPEER 104
#define ERRNO_NOTCONNECTED 107
#define ERRNO_CONNREFUSED 111
#define ERRNO_NOROUTETOHOST 113

static inline gint
errno_to_errcode(int e)
{
	switch (e) {
	case ERRNO_RESETBYPEER:
		return ERRCODE_CONN_RESET;
	case ERRNO_CONNREFUSED:
		return ERRCODE_CONN_REFUSED;
	case ERRNO_NOROUTETOHOST:
		return ERRCODE_CONN_TIMEOUT;
	case ERRNO_NOTCONNECTED:
		return ERRCODE_CONN_NOTCONNECTED;
	}
	return 0;
}

#endif /*OIO_SDS__metautils__lib__metautils_internals_h*/
