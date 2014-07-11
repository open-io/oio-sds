#ifndef CHECK_H
#define CHECK_H

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

#endif /* CHECK_H */
