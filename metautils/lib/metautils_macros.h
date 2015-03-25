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

/* Some well known service types */
# define NAME_SRVTYPE_META0 "meta0"
# define NAME_SRVTYPE_META1 "meta1"
# define NAME_SRVTYPE_META2 "meta2"
# define NAME_SRVTYPE_RAWX  "rawx"

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

#define NAME_MSGNAME_METAREPLY "REPLY"
#define NAME_MSGKEY_STATUS "STATUS"
#define NAME_MSGKEY_MESSAGE "MSG"
#define NAME_MSGKEY_FLAG "FLAG"
#define NAME_MSGKEY_PREFIX "PREFIX"
#define NAME_MSGKEY_WARNING "WARNING"
#define NAME_MSGKEY_TIMESTAMP "TIMESTAMP"
#define NAME_MSGKEY_CONTAINERID "CONTAINER_ID"
#define NAME_MSGKEY_VIRTUALNAMESPACE "VIRTUAL_NAMESPACE"
#define NAME_MSGKEY_NAMESPACE "NAMESPACE"
#define NAME_MSGKEY_SRVTYPE "SRVTYPE"
#define NAME_MSGKEY_CONTAINERNAME "CONTAINER_NAME"
#define NAME_MSGKEY_CONTENTPATH "CONTENT_PATH"
#define NAME_MSGKEY_CONTENTLENGTH "CONTENT_LENGTH"
#define NAME_MSGKEY_CHUNKID "CHUNKID"
#define NAME_MSGKEY_STGPOLICY "STORAGE_POLICY"
#define NAME_MSGKEY_M1_MASTER "M1_MASTER"

#endif /*OIO_SDS__metautils__lib__metautils_macros_h*/
