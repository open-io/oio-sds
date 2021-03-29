/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

# ifndef M2V2_ADMIN_OBJ_COUNT
# define M2V2_ADMIN_OBJ_COUNT M2V2_ADMIN_PREFIX_SYS "objects"
# endif

# ifndef M2V2_ADMIN_SHARD_COUNT
# define M2V2_ADMIN_SHARD_COUNT M2V2_ADMIN_PREFIX_SYS "shards"
# endif

# ifndef M2V2_ADMIN_DAMAGED_OBJECTS
# define M2V2_ADMIN_DAMAGED_OBJECTS M2V2_ADMIN_PREFIX_SYS "objects.damaged"
# endif

# ifndef M2V2_ADMIN_MISSING_CHUNKS
# define M2V2_ADMIN_MISSING_CHUNKS M2V2_ADMIN_PREFIX_SYS "chunks.missing"
# endif

# ifndef M2V2_ADMIN_CTIME
# define M2V2_ADMIN_CTIME M2V2_ADMIN_PREFIX_SYS "ctime"
# endif

# ifndef M2V2_ADMIN_BUCKET_NAME
# define M2V2_ADMIN_BUCKET_NAME M2V2_ADMIN_PREFIX_SYS "bucket.name"
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

# ifndef M2V2_ADMIN_DELETE_EXCEEDING_VERSIONS
# define M2V2_ADMIN_DELETE_EXCEEDING_VERSIONS M2V2_ADMIN_VERSIONING_POLICY ".delete_exceeding"
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
# define NAME_MSGNAME_M2V2_PURGE_CONTENT   "M2_CPURGE"
# define NAME_MSGNAME_M2V2_PURGE_CONTAINER "M2_BPURGE"
# define NAME_MSGNAME_M2V2_DEDUP           "M2_DEDUP"
# define NAME_MSGNAME_M2V2_PUT             "M2_PUT"
# define NAME_MSGNAME_M2V2_BEANS           "M2_PREP"
# define NAME_MSGNAME_M2V2_APPEND          "M2_APPEND"
# define NAME_MSGNAME_M2V2_GET             "M2_GET"
# define NAME_MSGNAME_M2V2_DRAIN           "M2_DRAIN"
# define NAME_MSGNAME_M2V2_DEL             "M2_DEL"
# define NAME_MSGNAME_M2V2_TRUNC           "M2_TRUNC"
# define NAME_MSGNAME_M2V2_LIST            "M2_LST"
# define NAME_MSGNAME_M2V2_LCHUNK          "M2_LCHUNK"
# define NAME_MSGNAME_M2V2_LHID            "M2_LHID"
# define NAME_MSGNAME_M2V2_LHHASH          "M2_LHHASH"
# define NAME_MSGNAME_M2V2_ISEMPTY         "M2_EMPTY"
# define NAME_MSGNAME_M2V2_PROP_SET        "M2_PSET"
# define NAME_MSGNAME_M2V2_PROP_GET        "M2_PGET"
# define NAME_MSGNAME_M2V2_PROP_DEL        "M2_PDEL"
# define NAME_MSGNAME_M2V2_RAW_DEL         "M2_RAWDEL"
# define NAME_MSGNAME_M2V2_RAW_ADD         "M2_RAWADD"
# define NAME_MSGNAME_M2V2_RAW_SUBST       "M2_RAWSUBST"
# define NAME_MSGNAME_M2V1_TOUCH_CONTENT   "M2_CTOUCH"
# define NAME_MSGNAME_M2V1_TOUCH_CONTAINER "M2_BTOUCH"

/* -------------------------------------------------------------------------- */

#define M2V2_FLAG_NODELETED        0x00000001
#define M2V2_FLAG_ALLVERSION       0x00000002
#define M2V2_FLAG_NOPROPS          0x00000004
#define M2V2_FLAG_ALLPROPS         0x00000010

/* when listing */
#define M2V2_FLAG_HEADERS          0x00000020

/* when getting an alias, do not follow the foreign keys toward
 * headers, contents and chunks. */
#define M2V2_FLAG_NORECURSION      0x00000080

/* when getting an alias, ignores the version in the URL and
 * return the latest alias only. */
#define M2V2_FLAG_LATEST           0x00000100

/* flush the properties */
#define M2V2_FLAG_FLUSH            0x00000200

/* Ask the meta2 to redirect if not MASTER, even if the request is Read-Only */
#define M2V2_FLAG_MASTER           0x00000400

/* Ask the meta2 to open the database locally */
#define M2V2_FLAG_LOCAL            0x00000800

/* Request N spare chunks which should not be on provided blacklist */
#define M2V2_SPARE_BY_BLACKLIST "SPARE_BLACKLIST"

struct m2v2_create_params_s
{
	const char *storage_policy; /**< Will override the (maybe present) stgpol property. */
	const char *version_policy; /**< idem for the verpol property. */
	const char *peers; /**< Peers to replicate the database to. */

	/** A NULL-terminated sequence of strings where:
	 * properties[i*2] is the i-th key and
	 * properties[(i*2)+1] is the i-th value */
	gchar **properties;
	gboolean local; /**< Do not try to replicate, do not call get_peers() */
};

enum m2v2_destroy_flag_e
{
	/* send a destruction event */
	M2V2_DESTROY_EVENT = 0x01,
	M2V2_DESTROY_FLUSH = 0x02,
	M2V2_DESTROY_FORCE = 0x04,
};

#endif /*OIO_SDS__meta2v2__meta2_macros_h*/
