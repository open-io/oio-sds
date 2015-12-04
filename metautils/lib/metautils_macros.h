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

#ifndef OIO_SDS__metautils__lib__metautils_macros_h
# define OIO_SDS__metautils__lib__metautils_macros_h 1

# ifndef LOG_DEFAULT_DOMAIN
#  define LOG_DEFAULT_DOMAIN "default"
# endif

# ifndef API_VERSION
#  define API_VERSION ((const char*)"")
# endif

# ifdef HAVE_EXTRA_ASSERT
#  define EXTRA_ASSERT(X) g_assert(X)
# else
#  define EXTRA_ASSERT(X)
# endif

# define SLICE_NEW0(T)    g_slice_new0(T)
# define SLICE_NEW(T)     g_slice_new(T)
# define SLICE_ALLOC(S)   g_slice_alloc(S)
# define SLICE_FREE(T,P)  g_slice_free(T,(P))
# define SLICE_FREE1(S,P) g_slice_free1((S),(P))

/* size [in bytes] asn1c can require on the stack. Use 0 for as many bytes
 * as necessary (with the risk of stack smashing). */
#define ASN1C_MAX_STACK 0

/* Some well known service types */

# define NAME_SRVTYPE_META0 "meta0"
# define NAME_SRVTYPE_META1 "meta1"
# define NAME_SRVTYPE_META2 "meta2"
# define NAME_SRVTYPE_RAWX  "rawx"
# define NAME_SRVTYPE_SQLX  "sqlx"
# define NAME_SRVTYPE_RDIR  "rdir"

# define NAME_ACCOUNT_RDIR  "_RDIR"

# ifndef COMMON_CLIENT_TIMEOUT
#  define COMMON_CLIENT_TIMEOUT 30.0
# endif

# ifndef M2V2_CLIENT_TIMEOUT
#  define M2V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef M1V2_CLIENT_TIMEOUT
#  define M1V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef M0V2_CLIENT_TIMEOUT
#  define M0V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef CS_CLIENT_TIMEOUT
#  define CS_CLIENT_TIMEOUT 3.0
# endif

/* Some well known service tags macro names */
# define NAME_MACRO_SPACE_NAME "stat.space"
# define NAME_MACRO_CPU_NAME "stat.cpu"
# define NAME_MACRO_IOIDLE_NAME "stat.io"

# define NAME_TAGNAME_RAWX_VOL "tag.vol"
# define NAME_TAGNAME_RAWX_FIRST "tag.first"
# define NAME_TAGNAME_RAWX_LOC "tag.loc"
# define NAME_TAGNAME_INTERNAL "tag.internal"
# define NAME_TAGNAME_RAWX_STGCLASS "tag.stgclass"

# define NAME_TAGNAME_AGENT_CHECK "tag.agent_check"

#ifndef RAWX_LOSTFOUND_FOLDER
# define RAWX_LOSTFOUND_FOLDER "_lost+found"
#endif

#ifndef RAWX_HEADER_PREFIX
# define RAWX_HEADER_PREFIX "X-oio-chunk-meta-"
#endif

/* A flag usable in metacnx_ctx_s.flags to keep the connection alive */
#define METACNX_FLAGMASK_KEEPALIVE 0x00000001

#define REPSEQ_FINAL         0x00000001
#define REPSEQ_ERROR         0X00000002
#define REPSEQ_BODYMANDATORY 0x00000004

#define NAME_MSGNAME_METAREPLY         "RP"

#define NAME_MSGKEY_ACCOUNT            "ACCOUNT"
#define NAME_MSGKEY_ACTION             "ACTION"
#define NAME_MSGKEY_ALLOWUPDATE        "ALLOW_UPDATE"
#define NAME_MSGKEY_APPEND             "APPEND"
#define NAME_MSGKEY_AUTOCREATE         "AUTOCREATE"
#define NAME_MSGKEY_BASENAME           "BASE_NAME"
#define NAME_MSGKEY_BASETYPE           "BASE_TYPE"
#define NAME_MSGKEY_BROKEN             "BROKEN"
#define NAME_MSGKEY_CHECK              "CHECK_FLAGS"
#define NAME_MSGKEY_CHECKONLY          "CHECKONLY"
#define NAME_MSGKEY_CHUNKED            "CHUNKED"
#define NAME_MSGKEY_CONTAINERID        "CID"
#define NAME_MSGKEY_CONTAINERNAME      "CN"
#define NAME_MSGKEY_CONTENTLENGTH      "CL"
#define NAME_MSGKEY_CONTENTPATH        "CP"
#define NAME_MSGKEY_CONTENTID          "CI"
#define NAME_MSGKEY_COPY               "COPY"
#define NAME_MSGKEY_COUNT              "COUNT"
#define NAME_MSGKEY_DISTANCE           "DISTANCE"
#define NAME_MSGKEY_DRYRUN             "DRYRUN"
#define NAME_MSGKEY_DST                "DST"
#define NAME_MSGKEY_FLAGS              "FLAGS"
#define NAME_MSGKEY_FLUSH              "FLUSH"
#define NAME_MSGKEY_FORCE              "FORCE"
#define NAME_MSGKEY_FULL               "FULL"
#define NAME_MSGKEY_HCURL              "HC_URL"
#define NAME_MSGKEY_KEY                "K"
#define NAME_MSGKEY_LOCAL              "LOCAL"
#define NAME_MSGKEY_LOCK               "LOCK"
#define NAME_MSGKEY_MARKER             "MARKER"
#define NAME_MSGKEY_MARKER_END         "MARKER_END"
#define NAME_MSGKEY_MAX_KEYS           "MAX_KEYS"
#define NAME_MSGKEY_M1_MASTER          "M1_MASTER"
#define NAME_MSGKEY_MESSAGE            "MSG"
#define NAME_MSGKEY_METAURL            "METAURL"
#define NAME_MSGKEY_NAMESPACE          "NS"
#define NAME_MSGKEY_NEXTMARKER         "NEXT_MARKER"
#define NAME_MSGKEY_NEW                "NEW"
#define NAME_MSGKEY_NOCHECK            "NOCHECK"
#define NAME_MSGKEY_NODIST             "NODIST"
#define NAME_MSGKEY_NOREAL             "NOREAL"
#define NAME_MSGKEY_NOTIN              "NOT-IN"
#define NAME_MSGKEY_OLD                "OLD"
#define NAME_MSGKEY_OVERWRITE          "OVERWRITE"
#define NAME_MSGKEY_PREFIX             "PREFIX"
#define NAME_MSGKEY_POSITIONPREFIX     "POSITION_PREFIX"
#define NAME_MSGKEY_PURGE              "PURGE"
#define NAME_MSGKEY_QUERY              "QUERY"
#define NAME_MSGKEY_REPLICAS           "REPLICAS"
#define NAME_MSGKEY_SPARE              "SPARE"
#define NAME_MSGKEY_SRC                "SRC"
#define NAME_MSGKEY_STATUS             "S"
#define NAME_MSGKEY_STGPOLICY          "STORAGE_POLICY"
#define NAME_MSGKEY_TRUNCATED          "TRUNCATED"
#define NAME_MSGKEY_TYPENAME           "T"
#define NAME_MSGKEY_URL                "URL"
#define NAME_MSGKEY_USER               "USER"
#define NAME_MSGKEY_VALUE              "V"
#define NAME_MSGKEY_VERPOLICY          "VERPOL"
#define NAME_MSGKEY_VERSION            "VERSION"
#define NAME_MSGKEY_WARNING            "WARNING"

#define NAME_MSGKEY_PREFIX_PROPERTY    "P:"

enum {
	SCORE_UNSET = -2,
	SCORE_UNLOCK = -1,
	SCORE_DOWN = 0,
	SCORE_MAX = 100
};

#ifndef PROXYD_DEFAULT_TTL_SERVICES
#define PROXYD_DEFAULT_TTL_SERVICES 3600
#endif

#ifndef PROXYD_DEFAULT_MAX_SERVICES
#define PROXYD_DEFAULT_MAX_SERVICES 200000
#endif

#ifndef PROXYD_DEFAULT_TTL_CSM0
#define PROXYD_DEFAULT_TTL_CSM0 0
#endif

#ifndef PROXYD_DEFAULT_MAX_CSM0
#define PROXYD_DEFAULT_MAX_CSM0 0
#endif

#ifndef PROXYD_PATH_MAXLEN
#define PROXYD_PATH_MAXLEN 2048
#endif

#ifndef PROXYD_DIR_TIMEOUT_SINGLE
#define PROXYD_DIR_TIMEOUT_SINGLE 10.0
#endif

#ifndef PROXYD_DIR_TIMEOUT_GLOBAL
#define PROXYD_DIR_TIMEOUT_GLOBAL 30.0
#endif

#ifndef PROXYD_M2_TIMEOUT_SINGLE
#define PROXYD_M2_TIMEOUT_SINGLE 10.0
#endif

#ifndef PROXYD_M2_TIMEOUT_GLOBAL
#define PROXYD_M2_TIMEOUT_GLOBAL 30.0
#endif

#ifndef PROXYD_DEFAULT_TIMEOUT_CONSCIENCE
#define PROXYD_DEFAULT_TIMEOUT_CONSCIENCE 5000 /*ms*/
#endif

#ifndef PROXYD_DEFAULT_PERIOD_DOWNSTREAM
#define PROXYD_DEFAULT_PERIOD_DOWNSTREAM 10 /*s*/
#endif

#ifndef PROXYD_DEFAULT_PERIOD_UPSTREAM
#define PROXYD_DEFAULT_PERIOD_UPSTREAM 1 /*s*/
#endif

#ifndef PROXYD_HEADER_NOEMPTY
#define PROXYD_HEADER_NOEMPTY PROXYD_HEADER_PREFIX "no-empty-list"
#endif

#ifndef GCLUSTER_RUN_DIR
# define GCLUSTER_RUN_DIR "/var/run"
#endif

#ifndef GCLUSTER_AGENT_SOCK_PATH
# define GCLUSTER_AGENT_SOCK_PATH GCLUSTER_RUN_DIR "/oio-sds-agent.sock"
#endif

#ifndef OIO_M2V2_LISTRESULT_BATCH
# define OIO_M2V2_LISTRESULT_BATCH 1000
#endif

#endif /*OIO_SDS__metautils__lib__metautils_macros_h*/
