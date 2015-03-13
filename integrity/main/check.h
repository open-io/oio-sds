/*
OpenIO SDS integrity
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__integrity__main__check_h
# define OIO_SDS__integrity__main__check_h 1

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>

#define CHECK_ARG_POINTER(P,E) \
	do { \
		if ((P) == NULL) { \
			GSETERROR(E, "Argument "#P" can't be NULL"); \
			return FALSE; \
		} \
	} while(0);

#define CHECK_ARG_VALID_DIR(D,E) \
	do { \
		struct stat file_stat; \
		memset(&file_stat, 0, sizeof(struct stat)); \
		if (0 != stat((D), &file_stat) || !S_ISDIR(file_stat.st_mode)) { \
			GSETERROR(E, "Argument "#D" is not a valid directory : %s", strerror(errno)); \
			return FALSE; \
		} \
	} while(0);

#define CHECK_ARG_VALID_FILE(F,E) \
	do { \
		struct stat file_stat; \
		memset(&file_stat, 0, sizeof(struct stat)); \
		if (0 != stat((F), &file_stat) || !S_ISREG(file_stat.st_mode)) { \
			GSETERROR(E, "Argument "#F" is not a valid file : %s", strerror(errno)); \
			return FALSE; \
		} \
	} while(0);

#define CHECK_POINTER_ALLOC(P,E) \
	do { \
		if ((P) == NULL) { \
			GSETERROR(E, "Memory allocation failure"); \
			return FALSE; \
		} \
	} while(0);

#endif /*OIO_SDS__integrity__main__check_h*/