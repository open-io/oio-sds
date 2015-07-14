/*
OpenIO SDS meta2v2
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

#ifndef OIO_SDS__meta2v2__meta2_macros_h
# define OIO_SDS__meta2v2__meta2_macros_h 1

# ifndef M2V2_ADMIN_PREFIX_SYS
# define M2V2_ADMIN_PREFIX_SYS SQLX_ADMIN_PREFIX_SYS "m2."
# endif

# ifndef M2V2_ADMIN_PREFIX_USER
# define M2V2_ADMIN_PREFIX_USER SQLX_ADMIN_PREFIX_USER
# endif

# ifndef M2V2_ADMIN_VERSION
# define M2V2_ADMIN_VERSION M2V2_ADMIN_PREFIX_SYS "version"
# endif

# ifndef M2V2_ADMIN_QUOTA
# define M2V2_ADMIN_QUOTA M2V2_ADMIN_PREFIX_SYS "quota"
# endif

# ifndef M2V2_ADMIN_SIZE
# define M2V2_ADMIN_SIZE M2V2_ADMIN_PREFIX_SYS "usage"
# endif

# ifndef M2V2_ADMIN_CTIME
# define M2V2_ADMIN_CTIME M2V2_ADMIN_PREFIX_SYS "ctime"
# endif

# ifndef M2V2_ADMIN_VERSIONING_POLICY
# define M2V2_ADMIN_VERSIONING_POLICY M2V2_ADMIN_PREFIX_SYS "policy.version"
# endif

# ifndef M2V2_ADMIN_STORAGE_POLICY
# define M2V2_ADMIN_STORAGE_POLICY M2V2_ADMIN_PREFIX_SYS "policy.storage"
# endif

# ifndef M2V2_ADMIN_KEEP_DELETED_DELAY
# define M2V2_ADMIN_KEEP_DELETED_DELAY M2V2_ADMIN_PREFIX_SYS "keep_deleted_delay"
# endif

# ifndef META2_INIT_FLAG
# define META2_INIT_FLAG M2V2_ADMIN_PREFIX_SYS "init"
# endif

/* -------------------------------------------------------------------------- */

# define NAME_MSGNAME_M2V2_CREATE  "M2V2_CREATE"
# define NAME_MSGNAME_M2V2_DESTROY "M2V2_DESTROY"
# define NAME_MSGNAME_M2V2_HAS     "M2V2_HAS"
# define NAME_MSGNAME_M2V2_PURGE   "M2V2_PURGE"
# define NAME_MSGNAME_M2V2_DEDUP   "M2V2_DEDUP"

# define NAME_MSGNAME_M2V2_PUT    "M2V2_PUT"
# define NAME_MSGNAME_M2V2_BEANS  "M2V2_BEANS"
# define NAME_MSGNAME_M2V2_APPEND "M2V2_APPEND"
# define NAME_MSGNAME_M2V2_GET    "M2V2_GET"
# define NAME_MSGNAME_M2V2_DEL    "M2V2_DEL"

/* list all aliases */
# define NAME_MSGNAME_M2V2_LIST    "M2V2_LIST"

/* list but filter by chunk */
# define NAME_MSGNAME_M2V2_LCHUNK  "M2V2_LCHUNK"

/* list but filter by header */
# define NAME_MSGNAME_M2V2_LHEADER "M2V2_LHEADER"

# define NAME_MSGNAME_M2V2_PROP_SET "M2V2_PROP_SET"
# define NAME_MSGNAME_M2V2_PROP_GET "M2V2_PROP_GET"
# define NAME_MSGNAME_M2V2_PROP_DEL "M2V2_PROP_DEL"

# define NAME_MSGNAME_M2V2_SNAP_TAKE    "M2V2_SNAP_TAKE"
# define NAME_MSGNAME_M2V2_SNAP_LIST    "M2V2_SNAP_LIST"
# define NAME_MSGNAME_M2V2_SNAP_RESTORE "M2V2_SNAP_RESTORE"
# define NAME_MSGNAME_M2V2_SNAP_DEL     "M2V2_SNAP_DEL"

# define NAME_MSGNAME_M2V2_RAW_DEL   "M2V2_RAW_DEL"
# define NAME_MSGNAME_M2V2_RAW_ADD   "M2V2_RAW_ADD"
# define NAME_MSGNAME_M2V2_RAW_SUBST "M2V2_RAW_SUBST"

# define NAME_MSGNAME_M2V2_HDR_FOLLOW "M2V2_HDR_FOLLOW"

# define NAME_MSGNAME_M2V2_EXITELECTION "M2V2_EXIT_ELECTION"

# define NAME_MSGNAME_M2V2_STGPOL  "M2V2_STGPOL"

# define NAME_MSGNAME_M2V1_TOUCH_CONTENT   "REQ_M2RAW_TOUCH_CONTENT"
# define NAME_MSGNAME_M2V1_TOUCH_CONTAINER "REQ_M2RAW_TOUCH_CONTAINER"

/* ------------------------------------------------------------------------- */

#define NAME_MSGNAME_M2_CREATE               "REQ_M2_CREATE"
#define NAME_MSGNAME_M2_CONTENTSPARE         "REQ_M2_CONTENTSPARE"
#define NAME_MSGNAME_M2_CONTENTADD           "REQ_M2_CONTENTADD"
#define NAME_MSGNAME_M2_CONTENTAPPEND        "REQ_M2_CONTENTAPPEND"
#define NAME_MSGNAME_M2RAW_SETCONTENT        "REQ_M2RAW_CONTENT_SET"
#define NAME_MSGNAME_M2RAW_GETCHUNKS         "REQ_M2RAW_CHUNKS_GET"
#define NAME_MSGNAME_M2RAW_SETCHUNKS         "REQ_M2RAW_CHUNKS_SET"
#define NAME_MSGNAME_M2RAW_DELCHUNKS         "REQ_M2RAW_CHUNKS_DEL"
#define NAME_MSGNAME_M2RAW_SETMDSYS          "META2_SERVICES_MODIFY_METADATASYS"

/* -------------------------------------------------------------------------- */

# ifndef META2_URL_LOCAL_BASE
#  define META2_URL_LOCAL_BASE "__M2V2_LOCAL_BASE__"
# endif

/* LEGACY CONSTANTS --------------------------------------------------------- */

# ifndef MDUSR_PROPERTY_KEY
#  define MDUSR_PROPERTY_KEY M2V2_ADMIN_PREFIX_SYS "v1.mdusr"
# endif

#endif /*OIO_SDS__meta2v2__meta2_macros_h*/
