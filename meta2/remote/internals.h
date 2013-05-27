#ifndef GRIDSTORAGE__META2_REMOTE_INTERNALS__H
# define GRIDSTORAGE__META2_REMOTE_INTERNALS__H 1
# ifdef HAVE_CONFIG_H
#  include "../config.h"
# endif
# ifndef LOG_DOMAIN
#  define LOG_DOMAIN "meta2.remote"
# endif
# include <stdlib.h>
# include <errno.h>
# include <string.h>
# include <unistd.h>
# include <glib.h>
# include <metatypes.h>
# include <metautils.h>
# include <metacomm.h>
# include "./meta2_remote.h"

# define STRING_2_GBA(res,st,st_len) do {\
	(res)=NULL;\
	GByteArray *gba = g_byte_array_new();\
	if (!gba) { (res) = NULL; break; }\
	g_byte_array_append( gba, st, st_len);\
	(res) = gba;\
} while (0)

# define STRUCT_2_GBA(res,st) do {\
	GByteArray *gba = g_byte_array_new();\
	if (!gba) { (res) = NULL; break; }\
	g_byte_array_append( gba, (void*)(&(st)), sizeof(st));\
	(res) = gba;\
} while (0)

#define CID_2_GBA(res,cid) do {\
	GByteArray *gba = g_byte_array_new();\
	if (!gba) abort();\
	if (!g_byte_array_append( gba, (void*)cid, sizeof(container_id_t))) abort();\
	(res) = gba;\
} while (0)

#define CONSTR_2_GBA(res,buf) do {\
	GByteArray *gba = g_byte_array_new();\
	if (!gba) { (res) = NULL; break; }\
	g_byte_array_append( gba, buf, sizeof(buf)-1);\
	(res) = gba;\
} while (0)

#define STATIC_STRLEN(S) (S),sizeof(S)-1

MESSAGE meta2_remote_build_request(GError **err, GByteArray *id, char *name);

#endif
