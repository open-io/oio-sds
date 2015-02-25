#ifndef __REDCURRANT_metautils_macros_h
#define __REDCURRANT_metautils_macros_h 1

# ifndef LOG_DEFAULT_DOMAIN
#  define LOG_DEFAULT_DOMAIN "default"
# endif

#ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN LOG_DEFAULT_DOMAIN
#endif

# ifndef API_VERSION
#  define API_VERSION ((const char*)"")
# endif

# ifdef HAVE_EXTRA_ASSERT
#  define EXTRA_ASSERT(X) g_assert(X)
# else
#  define EXTRA_ASSERT(X)
# endif

/*
 * Some well known service types
 */
# define NAME_SRVTYPE_META0 "meta0"
# define NAME_SRVTYPE_META1 "meta1"
# define NAME_SRVTYPE_META2 "meta2"
# define NAME_SRVTYPE_RAWX  "rawx"
# define NAME_SRVTYPE_ZOOKEEPER "zookeeper"

/*
 * Some well known service tags macro names
 */
# define NAME_MACRO_SPACE_NAME "stat.space"
# define NAME_MACRO_SPACE_TYPE "space"

# define NAME_MACRO_CPU_NAME "stat.cpu"
# define NAME_MACRO_CPU_TYPE "cpu"

# define NAME_MACRO_IOIDLE_NAME "stat.io"
# define NAME_MACRO_IOIDLE_TYPE "io"

# define NAME_MACRO_GRIDD_TYPE "gridd.macro"

# define NAME_TAGNAME_RAWX_VOL "tag.vol"
# define NAME_TAGNAME_RAWX_FIRST "tag.first"
# define NAME_TAGNAME_RAWX_LOC "tag.loc"
# define NAME_TAGNAME_INTERNAL "tag.internal"
# define NAME_TAGNAME_RAWX_STGCLASS "tag.stgclass"
# define NAME_TAGNAME_REQIDLE "stat.req_idle"

# define NAME_TAGNAME_AGENT_CHECK "tag.agent_check"

#endif // __REDCURRANT_metautils_macros_h
