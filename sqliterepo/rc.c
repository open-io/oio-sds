/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <errno.h>

#include <glib.h>
#include <sqlite3.h>

#include "sqliterepo.h"

#define _RC_ERRBUF_LEN 192
static __thread gchar buf[_RC_ERRBUF_LEN];

const char *
sqlite_strerror(int err)
{
	if (err > 0xFF) {
		gchar *end = g_stpcpy(buf, sqlite_strerror(err & 0xFF));
		g_snprintf(end, _RC_ERRBUF_LEN - (end - buf),
				" (+ ext code %d) (errno %d: %s)",
				err >> 8, errno, strerror(errno));
		return buf;
	}
	switch (err) {
		case SQLITE_OK:
			return "SQLITE_OK";
		case SQLITE_ERROR:
			return "SQLITE_ERROR";
		case SQLITE_INTERNAL:
			return "SQLITE_INTERNAL";
		case SQLITE_PERM:
			return "SQLITE_PERM";
		case SQLITE_ABORT:
			return "SQLITE_ABORT";
		case SQLITE_BUSY:
			return "SQLITE_BUSY";
		case SQLITE_LOCKED:
			return "SQLITE_LOCKED";
		case SQLITE_NOMEM:
			return "SQLITE_NOMEM";
		case SQLITE_READONLY:
			return "SQLITE_READONLY";
		case SQLITE_INTERRUPT:
			return "SQLITE_INTERRUPT";
		case SQLITE_IOERR:
			return "SQLITE_IOERR";
		case SQLITE_CORRUPT:
			return "SQLITE_CORRUPT";
		case SQLITE_NOTFOUND:
			return "SQLITE_NOTFOUND";
		case SQLITE_FULL:
			return "SQLITE_FULL";
		case SQLITE_CANTOPEN:
			return "SQLITE_CANTOPEN";
		case SQLITE_PROTOCOL:
			return "SQLITE_PROTOCOL";
		case SQLITE_EMPTY:
			return "SQLITE_EMPTY";
		case SQLITE_SCHEMA:
			return "SQLITE_SCHEMA";
		case SQLITE_TOOBIG:
			return "SQLITE_TOOBIG";
		case SQLITE_CONSTRAINT:
			return "SQLITE_CONSTRAINT";
		case SQLITE_MISMATCH:
			return "SQLITE_MISMATCH";
		case SQLITE_MISUSE:
			return "SQLITE_MISUSE";
		case SQLITE_NOLFS:
			return "SQLITE_NOLFS";
		case SQLITE_AUTH:
			return "SQLITE_AUTH";
		case SQLITE_FORMAT:
			return "SQLITE_FORMAT";
		case SQLITE_RANGE:
			return "SQLITE_RANGE";
		case SQLITE_NOTADB:
			return "SQLITE_NOTADB";
		case SQLITE_ROW:
			return "SQLITE_ROW";
		case SQLITE_DONE:
			return "SQLITE_DONE";
		default:
			return "SQLITE_?";
	}
}
