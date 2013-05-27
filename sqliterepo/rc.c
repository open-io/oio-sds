/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.rc"
#endif

#include <glib.h>

#include <sqlite3.h>

#include "./internals.h"
#include "./sqliterepo.h"

const char *
sqlx_strerror(int rc)
{
	switch (rc) {
		case SQLX_RC_BASE_LOCKED:
			return "SQLX_RC_BASE_LOCKED";
		case SQLX_RC_TOOMANY:
			return "SQLX_RC_TOOMANY";
		case SQLX_RC_INVALID_BASE_ID:
			return "SQLX_RC_INVALID_BASE_ID";
		case SQLX_RC_BASE_CLOSED:
			return "SQLX_RC_BASE_CLOSED";
		case SQLX_RC_NOT_IMPLEMENTED:
			return "SQLX_RC_NOT_IMPLEMENTED";
		case SQLX_RC_DESIGN_ERROR:
			return "SQLX_RC_DESIGN_ERROR";
		case SQLX_RC_NOERROR:
			return "SQLX_RC_NOERROR";
		case SQLX_RC_INVALID_SCHEMA:
			return "SQLX_RC_INVALID_SCHEMA";
		default:
			return "SQLX_UNEXPECTED_ERROR";
	}
}

const char *
sqlite_strerror(int err)
{
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

const gchar *
sqlite_op2str(int op)
{
	switch (op) {
		case SQLITE_CREATE_INDEX:
			return "CREATE INDEX";
		case SQLITE_CREATE_TABLE:
			return "CREATE TABLE";
		case SQLITE_ALTER_TABLE:
			return "ALTER TABLE";
		case SQLITE_CREATE_TRIGGER:
			return "CREATE TRIGGER";
		case SQLITE_CREATE_VIEW:
			return "CREATE VIEW";
		case SQLITE_DROP_TRIGGER:
			return "DROP TRIGGER";
		case SQLITE_DROP_VIEW:
			return "DROP VIEW";
		case SQLITE_DROP_INDEX:
			return "DROP INDEX";
		case SQLITE_DROP_TABLE:
			return "DROP TABLE";
		case SQLITE_CREATE_TEMP_INDEX:
			return "CREATE TEMP INDEX";
		case SQLITE_CREATE_TEMP_TABLE:
			return "CREATE TEMP TABLE";
		case SQLITE_CREATE_TEMP_TRIGGER:
			return "CREATE TEMP TRIGGER";
		case SQLITE_CREATE_TEMP_VIEW:
			return "CREATE TEMP VIEW";
		case SQLITE_DROP_TEMP_INDEX:
			return "DROP TEMP INDEX";
		case SQLITE_DROP_TEMP_TABLE:
			return "DROP TEMP INDEX";
		case SQLITE_DROP_TEMP_TRIGGER:
			return "DROP TEMP TRIGGER";
		case SQLITE_DROP_TEMP_VIEW:
			return "DROP TEMP VIEW";
		case SQLITE_READ:
			return "READ";
		case SQLITE_SELECT:
			return "SELECT";
		case SQLITE_TRANSACTION:
			return "TRANSACTION";
		case SQLITE_SAVEPOINT:
			return "SAVEPOINT";
		case SQLITE_INSERT:
			return "INSERT";
		case SQLITE_UPDATE:
			return "UPDATE";
		case SQLITE_DELETE:
			return "DELETE";
		case SQLITE_PRAGMA:
			return "PRAGMA";
		case SQLITE_ATTACH:
			return "ATTACH";
		case SQLITE_DETACH:
			return "DETACH";
		case SQLITE_REINDEX:
			return "REINDEX";
		case SQLITE_ANALYZE:
			return "ANAYZE";
		case SQLITE_CREATE_VTABLE:
			return "CREATE VTABLE";
		case SQLITE_DROP_VTABLE:
			return "DROP VTABLE";
		case SQLITE_FUNCTION:
			return "FUNCTION";
		case SQLITE_COPY:
			return "COPY";
	}

	return "UNEXPECTED";
}

