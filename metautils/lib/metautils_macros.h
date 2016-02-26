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

/* Some well known service tags macro names */
# define NAME_MACRO_SPACE_NAME "stat.space"
# define NAME_MACRO_CPU_NAME "stat.cpu"
# define NAME_MACRO_IOIDLE_NAME "stat.io"

# define NAME_TAGNAME_RAWX_VOL "tag.vol"
# define NAME_TAGNAME_RAWX_UP "tag.up"
# define NAME_TAGNAME_RAWX_FIRST "tag.1"
# define NAME_TAGNAME_RAWX_LOC "tag.loc"
# define NAME_TAGNAME_RAWX_STGCLASS "tag.stgclass"

# define NAME_TAGNAME_AGENT_CHECK "tag.agent_check"

# define NAME_TAGNAME_USER_IS_SERVICE "user_is_a_service"

/* A flag usable in metacnx_ctx_s.flags to keep the connection alive */
#define METACNX_FLAGMASK_KEEPALIVE 0x00000001

#define REPSEQ_FINAL         0x00000001
#define REPSEQ_ERROR         0X00000002
#define REPSEQ_BODYMANDATORY 0x00000004

#define NAME_MSGNAME_METAREPLY         "RP"

#define NAME_MSGKEY_ACCOUNT            "ACCT"
#define NAME_MSGKEY_ACTION             "ACTION"
#define NAME_MSGKEY_ALLOWUPDATE        "ALLOW_UPDATE"
#define NAME_MSGKEY_APPEND             "APPEND"
#define NAME_MSGKEY_AUTOCREATE         "AUTOCREATE"
#define NAME_MSGKEY_BASENAME           "BNAME"
#define NAME_MSGKEY_BASETYPE           "BTYPE"
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
#define NAME_MSGKEY_DISTANCE           "DIST"
#define NAME_MSGKEY_DRYRUN             "DRYRUN"
#define NAME_MSGKEY_DST                "DST"
#define NAME_MSGKEY_EVENT              "E"
#define NAME_MSGKEY_FLAGS              "FLAGS"
#define NAME_MSGKEY_FLUSH              "FLUSH"
#define NAME_MSGKEY_FORCE              "FORCE"
#define NAME_MSGKEY_FULL               "FULL"
#define NAME_MSGKEY_KEY                "K"
#define NAME_MSGKEY_LOCAL              "LOCAL"
#define NAME_MSGKEY_LOCK               "LOCK"
#define NAME_MSGKEY_MARKER             "MRK"
#define NAME_MSGKEY_MARKER_END         "MRK_END"
#define NAME_MSGKEY_MAX_KEYS           "MAX_KEYS"
#define NAME_MSGKEY_M1_MASTER          "M1_MASTER"
#define NAME_MSGKEY_MESSAGE            "MSG"
#define NAME_MSGKEY_METAURL            "METAURL"
#define NAME_MSGKEY_NAMESPACE          "NS"
#define NAME_MSGKEY_NEXTMARKER         "MRK_NXT"
#define NAME_MSGKEY_NEW                "NEW"
#define NAME_MSGKEY_NOCHECK            "NOCHECK"
#define NAME_MSGKEY_NODIST             "NODIST"
#define NAME_MSGKEY_NOREAL             "NOREAL"
#define NAME_MSGKEY_NOTIN              "!IN"
#define NAME_MSGKEY_OLD                "OLD"
#define NAME_MSGKEY_OVERWRITE          "OVERWRITE"
#define NAME_MSGKEY_PREFIX             "PREFIX"
#define NAME_MSGKEY_POSITIONPREFIX     "POSITION_PREFIX"
#define NAME_MSGKEY_PURGE              "PURGE"
#define NAME_MSGKEY_QUERY              "Q"
#define NAME_MSGKEY_REPLICAS           "REPLICAS"
#define NAME_MSGKEY_SPARE              "SPARE"
#define NAME_MSGKEY_SRC                "SRC"
#define NAME_MSGKEY_STATUS             "S"
#define NAME_MSGKEY_SIZE               "SZ"
#define NAME_MSGKEY_STGPOLICY          "SP"
#define NAME_MSGKEY_TRUNCATED          "TRUNC"
#define NAME_MSGKEY_TYPENAME           "T"
#define NAME_MSGKEY_URL                "URL"
#define NAME_MSGKEY_USER               "USR"
#define NAME_MSGKEY_VALUE              "V"
#define NAME_MSGKEY_VERPOLICY          "VP"
#define NAME_MSGKEY_VERSION            "VER"

#define NAME_MSGKEY_PREFIX_PROPERTY    "P:"

enum {
	SCORE_UNSET = -2,
	SCORE_UNLOCK = -1,
	SCORE_DOWN = 0,
	SCORE_MAX = 100
};

#endif /*OIO_SDS__metautils__lib__metautils_macros_h*/
