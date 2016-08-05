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

# ifndef META2_EVENTS_PREFIX
# define META2_EVENTS_PREFIX "storage"
# endif

/* -------------------------------------------------------------------------- */

# define NAME_MSGNAME_M2V2_CREATE          "M2_CREATE"
# define NAME_MSGNAME_M2V2_DESTROY         "M2_DESTROY"
# define NAME_MSGNAME_M2V2_HAS             "M2_HAS"
# define NAME_MSGNAME_M2V2_FLUSH           "M2_FLUSH"
# define NAME_MSGNAME_M2V2_PURGE           "M2_PURGE"
# define NAME_MSGNAME_M2V2_DEDUP           "M2_DEDUP"
# define NAME_MSGNAME_M2V2_PUT             "M2_PUT"
# define NAME_MSGNAME_M2V2_BEANS           "M2_PREP"
# define NAME_MSGNAME_M2V2_APPEND          "M2_APPEND"
# define NAME_MSGNAME_M2V2_GET             "M2_GET"
# define NAME_MSGNAME_M2V2_DEL             "M2_DEL"
# define NAME_MSGNAME_M2V2_TRUNC           "M2_TRUNC"
# define NAME_MSGNAME_M2V2_LIST            "M2_LST"
# define NAME_MSGNAME_M2V2_LCHUNK          "M2_LCHUNK"
# define NAME_MSGNAME_M2V2_LHID            "M2_LHID"
# define NAME_MSGNAME_M2V2_LHHASH          "M2_LHHASH"
# define NAME_MSGNAME_M2V2_LINK            "M2_LINK"
# define NAME_MSGNAME_M2V2_ISEMPTY         "M2_EMPTY"
# define NAME_MSGNAME_M2V2_PROP_SET        "M2_PSET"
# define NAME_MSGNAME_M2V2_PROP_GET        "M2_PGET"
# define NAME_MSGNAME_M2V2_PROP_DEL        "M2_PDEL"
# define NAME_MSGNAME_M2V2_RAW_DEL         "M2_RAWDEL"
# define NAME_MSGNAME_M2V2_RAW_ADD         "M2_RAWADD"
# define NAME_MSGNAME_M2V2_RAW_SUBST       "M2_RAWSUBST"
# define NAME_MSGNAME_M2V2_EXITELECTION    "M2_LEAVE"
# define NAME_MSGNAME_M2V1_TOUCH_CONTENT   "M2_CTOUCH"
# define NAME_MSGNAME_M2V1_TOUCH_CONTAINER "M2_BTOUCH"

#endif /*OIO_SDS__meta2v2__meta2_macros_h*/
