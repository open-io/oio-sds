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

# ifndef EVENT_TOPIC
#  define EVENT_TOPIC "oio.sds"
# endif

/* Some well known service types */

# define NAME_SRVTYPE_META0 "meta0"
# define NAME_SRVTYPE_META1 "meta1"
# define NAME_SRVTYPE_META2 "meta2"
# define NAME_SRVTYPE_RAWX  "rawx"

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
#  define CS_CLIENT_TIMEOUT 10.0
# endif

/* Some well known service tags macro names */
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

#ifndef RAWX_LOSTFOUND_FOLDER
# define RAWX_LOSTFOUND_FOLDER "_lost+found"
#endif

/* A flag usable in metacnx_ctx_s.flags to keep the connection alive */
#define METACNX_FLAGMASK_KEEPALIVE 0x00000001

#define REPSEQ_FINAL         0x00000001
#define REPSEQ_ERROR         0X00000002
#define REPSEQ_BODYMANDATORY 0x00000004

#define NAME_MSGNAME_METAREPLY         "REPLY"
#define NAME_MSGKEY_STATUS             "STATUS"
#define NAME_MSGKEY_MESSAGE            "MSG"
#define NAME_MSGKEY_HCURL              "HC_URL"
#define NAME_MSGKEY_URL                "URL"
#define NAME_MSGKEY_METAURL            "METAURL"
#define NAME_MSGKEY_ACTION             "ACTION"
#define NAME_MSGKEY_CHECKONLY          "CHECKONLY"
#define NAME_MSGKEY_FLAG               "FLAG"
#define NAME_MSGKEY_FLAGS              "FLAGS"
#define NAME_MSGKEY_FLUSH              "FLUSH"
#define NAME_MSGKEY_CHUNKED            "CHUNKED"
#define NAME_MSGKEY_NOREAL             "NOREAL"
#define NAME_MSGKEY_FULL               "FULL"
#define NAME_MSGKEY_SPARE              "SPARE"
#define NAME_MSGKEY_FORCE              "FORCE"
#define NAME_MSGKEY_PURGE              "PURGE"
#define NAME_MSGKEY_LOCAL              "LOCAL"
#define NAME_MSGKEY_APPEND             "APPEND"
#define NAME_MSGKEY_PREFIX             "PREFIX"
#define NAME_MSGKEY_AUTOCREATE         "AUTOCREATE"
#define NAME_MSGKEY_REPLICAS           "REPLICAS"
#define NAME_MSGKEY_NODIST             "NODIST"
#define NAME_MSGKEY_NOCHECK            "NOCHECK"
#define NAME_MSGKEY_WARNING            "WARNING"
#define NAME_MSGKEY_QUERY              "QUERY"
#define NAME_MSGKEY_TIMESTAMP          "TIMESTAMP"
#define NAME_MSGKEY_CONTAINERID        "CONTAINER_ID"
#define NAME_MSGKEY_VIRTUALNAMESPACE   "VIRTUAL_NAMESPACE"
#define NAME_MSGKEY_NAMESPACE          "NAMESPACE"
#define NAME_MSGKEY_SRVTYPE            "SRVTYPE"
#define NAME_MSGKEY_TYPENAME           "TYPENAME"
#define NAME_MSGKEY_CONTAINERNAME      "CONTAINER_NAME"
#define NAME_MSGKEY_CONTENTPATH        "CONTENT_PATH"
#define NAME_MSGKEY_CONTENTLENGTH      "CONTENT_LENGTH"
#define NAME_MSGKEY_CHUNKID            "CHUNKID"
#define NAME_MSGKEY_STGPOLICY          "STORAGE_POLICY"
#define NAME_MSGKEY_VERPOLICY          "VERSION_POLICY"
#define NAME_MSGKEY_M1_MASTER          "M1_MASTER"
#define NAME_MSGKEY_TRUNCATED          "TRUNCATED"
#define NAME_MSGKEY_NEXTMARKER         "NEXT_MARKER"
#define NAME_MSGKEY_BASENAME           "BASE_NAME"
#define NAME_MSGKEY_BASETYPE           "BASE_TYPE"
#define NAME_MSGKEY_SRC                "SRC"
#define NAME_MSGKEY_DST                "DST"
#define NAME_MSGKEY_COUNT              "COUNT"
#define NAME_MSGKEY_DISTANCE           "DISTANCE"
#define NAME_MSGKEY_NOTIN              "NOT-IN"
#define NAME_MSGKEY_BROKEN             "BROKEN"
#define NAME_MSGKEY_ALLOWUPDATE        "ALLOW_UPDATE"

#endif /*OIO_SDS__metautils__lib__metautils_macros_h*/
