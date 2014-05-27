#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include <sqlite3.h>

#include <sqliterepo/sqlite_utils.h>
#include <metautils/lib/metautils.h>

#include <meta2v2/meta2_backend_dbconvert.h>
#include <meta2v2/generic.h>
#include <meta2v2/meta2_macros.h>

#include <glib.h>

/** Available types for table fields. */
#define M2V2_TABLE_FIELD_TYPE_BLOB		"BLOB"
#define M2V2_TABLE_FIELD_TYPE_BOOL		"BOOL"
#define M2V2_TABLE_FIELD_TYPE_INTEGER	"INTEGER"
#define M2V2_TABLE_FIELD_TYPE_TEXT		"TEXT"

/** Available extra params to be added to field types. */
#define M2V2_TABLE_EXTRA_PARAM_PK		"PRIMARY KEY"
#define M2V2_TABLE_EXTRA_PARAM_UNIQUE	"UNIQUE"
#define M2V2_TABLE_EXTRA_PARAM_NOTNULL	"NOT NULL"

/** Names of tables. */
#define M2V2_TABLE_NAME_CHUNK			"chunk"
#define M2V2_TABLE_NAME_CONTENT			"content"
#define M2V2_TABLE_NAME_CONTENT_PROPERTY	"content_property"
#define M2V2_TABLE_NAME_ADMIN			"admin"
#define M2V2_TABLE_NAME_ALIASV2			"alias_v2"
#define M2V2_TABLE_NAME_CHUNKV2			"chunk_v2"
#define M2V2_TABLE_NAME_CONTENTV2		"content_v2"
#define M2V2_TABLE_NAME_CONTENTHEADERV2		"content_header_v2"
#define M2V2_TABLE_NAME_PROPERTIESV2		"properties_v2"
#define M2V2_TABLE_NAME_SNAPSHOTV2		"snapshot_v2"

/** Fields for old tables. */
#define M2V2_TABLE_FIELD_OLD_CHUNK_HASH		"chunk_hash"
#define M2V2_TABLE_FIELD_OLD_CHUNK_ID		"chunk_id"
#define M2V2_TABLE_FIELD_OLD_CHUNK_LENGTH	"chunk_length"
#define M2V2_TABLE_FIELD_OLD_CHUNK_NB		"chunk_nb"
#define M2V2_TABLE_FIELD_OLD_CHUNK_POS		"chunk_pos"
#define M2V2_TABLE_FIELD_OLD_CONTENT_LENGTH	"content_length"
#define M2V2_TABLE_FIELD_OLD_CONTENT_PATH	"content_path"
#define M2V2_TABLE_FIELD_OLD_CONTENT_VERSION	"content_version"
#define M2V2_TABLE_FIELD_OLD_FLAGS		"flags"
#define M2V2_TABLE_FIELD_OLD_METADATA		"metadata"
#define M2V2_TABLE_FIELD_OLD_SYS_METADATA	"system_metadata"
#define M2V2_TABLE_FIELD_OLD_PROPERTY		"property"
#define M2V2_TABLE_FIELD_OLD_VALUE		"value"

/** Fields for new tables. */
#define M2V2_TABLE_FIELD_ALIAS				"alias"
#define M2V2_TABLE_FIELD_ALIASVERSION		"alias_version"
#define M2V2_TABLE_FIELD_CHUNKID			"chunk_id"
#define M2V2_TABLE_FIELD_CONTAINERVERSION	"container_version"
#define M2V2_TABLE_FIELD_CONTENTID			"content_id"
#define M2V2_TABLE_FIELD_CONTENTHASH		"content_hash"
#define M2V2_TABLE_FIELD_CTIME				"ctime"
#define M2V2_TABLE_FIELD_DELETED			"deleted"
#define M2V2_TABLE_FIELD_HASH				"hash"
#define M2V2_TABLE_FIELD_ID					"id"
#define M2V2_TABLE_FIELD_KEY				"key"
#define M2V2_TABLE_FIELD_MDSYS				"mdsys"
#define M2V2_TABLE_FIELD_NAME				"name"
#define M2V2_TABLE_FIELD_POLICY				"policy"
#define M2V2_TABLE_FIELD_POSITION			"position"
#define M2V2_TABLE_FIELD_SIZE				"size"
#define M2V2_TABLE_FIELD_VALUE				"value"
#define M2V2_TABLE_FIELD_VERSION			"version"

/** Storage policy must be retrieved from system metadata. */
#define DB_ADMIN_KEY_CSTGPOLICY "storage-policy"

/** Maximum request length. */
#define M2V2_MAX_REQ_SIZE 1<<10

/** This structures allows to describe a table. */
typedef struct s_m2v2_table_info {
	gchar *name;
	GSList *field_names;
	GHashTable *field_types;
	GHashTable *field_extra;
	GSList *constraints;
	GSList *primary_keys;
} t_m2v2_table_info;

/** Type of sqlite3 select result. */
typedef struct s_m2v2_sqlite3_result {
	gint type;
	gint refcount;
	gboolean converted;
	GByteArray *value;
} t_m2v2_sqlite3_result;

/** ctime result to be inserted in new rows. */
t_m2v2_sqlite3_result *ctime_result = NULL;

/** Meta2v2 tables. */
t_m2v2_table_info *chunk_table = NULL;
t_m2v2_table_info *content_table = NULL;
t_m2v2_table_info *content_header_table = NULL;
t_m2v2_table_info *alias_table = NULL;
t_m2v2_table_info *properties_table = NULL;
t_m2v2_table_info *snapshot_table = NULL;

/** Meta2v1 tables. */
t_m2v2_table_info *old_admin_table = NULL;
t_m2v2_table_info *old_chunk_table = NULL;
t_m2v2_table_info *old_content_table = NULL;
t_m2v2_table_info *old_properties_table = NULL;

/**
 * Frees a table description.
 * @param table The table description to be freed.
 */
static void _free_table(t_m2v2_table_info *table)
{
	if (table) {
		if (table->name)
			g_free(table->name);
		if (table->field_names)
			g_slist_free(table->field_names);
		if (table->field_types)
			g_hash_table_destroy(table->field_types);
		if (table->field_extra)
			g_hash_table_destroy(table->field_extra);
		if (table->constraints)
			g_slist_free(table->constraints);
		if (table->primary_keys)
			g_slist_free(table->primary_keys);
		g_free(table);
	}
}

/**
 * Creates a newly allocated table_info.
 * The returned table_info must be freed using _free_table.
 * @return a newly allocated table info
 */
static t_m2v2_table_info* _create_table()
{
	t_m2v2_table_info *table = g_malloc(sizeof(t_m2v2_table_info)); \
	table->name = NULL;
	table->field_names = NULL;
	table->field_types = g_hash_table_new(g_str_hash, g_str_equal);
	table->field_extra = g_hash_table_new(g_str_hash, g_str_equal);
	table->constraints = NULL;
	table->primary_keys = NULL;
	return table;
}

/**
 * Sets table name.
 * @param table The table info to be completed.
 * @param name The name of the table.
 */
static void _set_table_name(t_m2v2_table_info *table, const gchar *name)
{
	table->name = g_strdup(name);
}

/**
 * Adds a field to a table_info.
 * @param table The table info to be completed.
 * @param field_name The name of the new field.
 * @param field_type The type of the new field.
 * @param field_extra Extra information about the new field.
 */
static inline void _add_field(t_m2v2_table_info *table, gchar *field_name, gchar *field_type, gchar *field_extra)
{
	table->field_names = g_slist_append(table->field_names, field_name);
	g_hash_table_insert(table->field_types, field_name, field_type);
	if (field_extra)
		g_hash_table_insert(table->field_extra, field_name, field_extra);
}

/**
 * Adds the field <code>field_name</code> to the primary keys of the
 * table <code>table</code>.
 * @param table The table to be completed.
 * @param field_name The field name to be added to primary keys.
 */
static inline void _add_primary_key(t_m2v2_table_info *table, gchar *field_name)
{
	table->primary_keys = g_slist_append(table->primary_keys, field_name);
}

/**
 * Adds the constraint <code>constraint</code> to the table <code>table</code>.
 * @param table The table to be completed.
 * @param constraint The constraint to be added.
 */
static inline void _add_constraint(t_m2v2_table_info *table, gchar *constraint)
{
	table->constraints = g_slist_append(table->constraints, constraint);
}

/**
 * Creation and initialization of v1 chunk table description.
 */
static void _init_old_chunk_db()
{
	old_chunk_table = _create_table();
	_set_table_name(old_chunk_table, M2V2_TABLE_NAME_CHUNK);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_ID,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_FLAGS,			M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_LENGTH,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_POS,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_HASH,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_METADATA,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
}

/**
 * Creation and initialization of v1 chunk table description.
 */
static void _init_old_properties_db()
{
	old_properties_table = _create_table();
	_set_table_name(old_properties_table, M2V2_TABLE_NAME_CONTENT_PROPERTY);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_CONTENT_VERSION,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_PROPERTY,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_chunk_table, M2V2_TABLE_FIELD_OLD_VALUE,			M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
}

/**
 * Creation and initialization of v1 content table description.
 */
static void _init_old_admin_db()
{
	old_admin_table = _create_table();
	_set_table_name(old_admin_table, M2V2_TABLE_NAME_ADMIN);
	_add_field(old_admin_table, "k", M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_admin_table, "v", M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_primary_key(old_admin_table, "k");
}

/**
 * Creation and initialization of v1 content table description.
 */
static void _init_old_content_db()
{
	old_content_table = _create_table();
	_set_table_name(old_content_table, M2V2_TABLE_NAME_CONTENT);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_FLAGS,			M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_CONTENT_LENGTH,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_CHUNK_NB,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_SYS_METADATA,	M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
	_add_field(old_content_table, M2V2_TABLE_FIELD_OLD_METADATA,		M2V2_TABLE_FIELD_TYPE_BLOB, NULL);
}

/**
 * Creation and initialization of v2 chunk table description.
 */
static void _init_chunk_db()
{
	chunk_table = _create_table();
	_set_table_name(chunk_table, M2V2_TABLE_NAME_CHUNKV2);
	_add_field(chunk_table, M2V2_TABLE_FIELD_ID,	M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(chunk_table, M2V2_TABLE_FIELD_HASH,	M2V2_TABLE_FIELD_TYPE_BLOB,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(chunk_table, M2V2_TABLE_FIELD_SIZE,	M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(chunk_table, M2V2_TABLE_FIELD_CTIME,	M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_primary_key(chunk_table, M2V2_TABLE_FIELD_ID);
}

/**
 * Creation and initialization of v2 content table description.
 */
static void _init_content_db()
{
	content_table = _create_table();
	_set_table_name(content_table, M2V2_TABLE_NAME_CONTENTV2);

	_add_field(content_table, M2V2_TABLE_FIELD_CONTENTID,	M2V2_TABLE_FIELD_TYPE_BLOB,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(content_table, M2V2_TABLE_FIELD_CHUNKID,		M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(content_table, M2V2_TABLE_FIELD_POSITION,	M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);

	_add_constraint(content_table, "fk_CONTENTS_CONTENTS_HEADERS_2"
			" FOREIGN KEY (" M2V2_TABLE_FIELD_CONTENTID ")"
			" REFERENCES " M2V2_TABLE_NAME_CONTENTHEADERV2 "(" M2V2_TABLE_FIELD_ID ")"
			" ON UPDATE CASCADE ON DELETE CASCADE");
	_add_constraint(content_table, "fk_CONTENTS_CHUNKS_3"
				" FOREIGN KEY (" M2V2_TABLE_FIELD_CHUNKID ")"
				" REFERENCES " M2V2_TABLE_NAME_CHUNKV2 "(" M2V2_TABLE_FIELD_ID ")"
				" ON UPDATE CASCADE ON DELETE CASCADE");

	_add_primary_key(content_table, M2V2_TABLE_FIELD_CONTENTID);
	_add_primary_key(content_table, M2V2_TABLE_FIELD_CHUNKID);
	_add_primary_key(content_table, M2V2_TABLE_FIELD_POSITION);
}

/**
 * Creation and initialization of v2 content header table description.
 */
static void _init_content_header_db()
{
	content_header_table = _create_table();
	_set_table_name(content_header_table, M2V2_TABLE_NAME_CONTENTHEADERV2);
	_add_field(content_header_table, M2V2_TABLE_FIELD_ID,		M2V2_TABLE_FIELD_TYPE_BLOB,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(content_header_table, M2V2_TABLE_FIELD_POLICY,	M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(content_header_table, M2V2_TABLE_FIELD_HASH,		M2V2_TABLE_FIELD_TYPE_BLOB,		NULL);
	_add_field(content_header_table, M2V2_TABLE_FIELD_SIZE,		M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_primary_key(content_header_table, M2V2_TABLE_FIELD_ID);
	_add_primary_key(content_header_table, M2V2_TABLE_FIELD_POLICY);
}

/**
 * Creation and initialization of v2 alias table description.
 */
static void _init_alias_db()
{
	alias_table = _create_table();
	_set_table_name(alias_table, M2V2_TABLE_NAME_ALIASV2);

	_add_field(alias_table, M2V2_TABLE_FIELD_ALIAS,				M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_VERSION,			M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_CONTAINERVERSION,	M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_CONTENTID,			M2V2_TABLE_FIELD_TYPE_BLOB,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_MDSYS,				M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_CTIME,				M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(alias_table, M2V2_TABLE_FIELD_DELETED,			M2V2_TABLE_FIELD_TYPE_BOOL,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);

	_add_constraint(alias_table, "fk_ALIASES_CONTENTS_HEADERS_1"
				" FOREIGN KEY (" M2V2_TABLE_FIELD_CONTENTID ")"
				" REFERENCES " M2V2_TABLE_NAME_CONTENTHEADERV2 "(" M2V2_TABLE_FIELD_ID ")"
				" ON UPDATE CASCADE ON DELETE CASCADE");

	_add_primary_key(alias_table, M2V2_TABLE_FIELD_ALIAS);
	_add_primary_key(alias_table, M2V2_TABLE_FIELD_VERSION);
	_add_primary_key(alias_table, M2V2_TABLE_FIELD_CONTAINERVERSION);
}

/**
 * Creation and initialization of v2 metadata table description.
 */
static void _init_properties_db()
{
	properties_table = _create_table();
	_set_table_name(properties_table, M2V2_TABLE_NAME_PROPERTIESV2);
	_add_field(properties_table, M2V2_TABLE_FIELD_ALIAS,			M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(properties_table, M2V2_TABLE_FIELD_ALIASVERSION,	M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(properties_table, M2V2_TABLE_FIELD_KEY,			M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(properties_table, M2V2_TABLE_FIELD_VALUE,			M2V2_TABLE_FIELD_TYPE_BLOB,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(properties_table, M2V2_TABLE_FIELD_DELETED,			M2V2_TABLE_FIELD_TYPE_BOOL,		M2V2_TABLE_EXTRA_PARAM_NOTNULL);

	_add_constraint(properties_table, "fk_PROPERTIES_ALIASES_0"
				" FOREIGN KEY (" M2V2_TABLE_FIELD_ALIAS "," M2V2_TABLE_FIELD_ALIASVERSION ")"
				" REFERENCES " M2V2_TABLE_NAME_ALIASV2 "(" M2V2_TABLE_FIELD_ALIAS "," M2V2_TABLE_FIELD_VERSION ")"
				" ON UPDATE CASCADE ON DELETE CASCADE");

	_add_primary_key(properties_table, M2V2_TABLE_FIELD_ALIAS);
	_add_primary_key(properties_table, M2V2_TABLE_FIELD_ALIASVERSION);
	_add_primary_key(properties_table, M2V2_TABLE_FIELD_KEY);
}

/**
 * Creation and initialization of v2 snapshot table description.
 */
static void _init_snapshot_db()
{
	snapshot_table = _create_table();
	_set_table_name(snapshot_table, M2V2_TABLE_NAME_SNAPSHOTV2);
	_add_field(snapshot_table, M2V2_TABLE_FIELD_VERSION,	M2V2_TABLE_FIELD_TYPE_INTEGER,	M2V2_TABLE_EXTRA_PARAM_NOTNULL);
	_add_field(snapshot_table, M2V2_TABLE_FIELD_NAME,		M2V2_TABLE_FIELD_TYPE_TEXT,		M2V2_TABLE_EXTRA_PARAM_UNIQUE);
	_add_primary_key(snapshot_table, M2V2_TABLE_FIELD_VERSION);
}


//---------------------------------------------------------------------
//
// FIELD TESTS (Type, format)
//
//---------------------------------------------------------------------

/**
 * Returns whether the field is in text format.
 * Useful when the field type is BLOB but the data is actual TEXT.
 * @param field_name The field to test.
 * @return TRUE if the field is in text format.
 */
static gboolean _is_text_in_db(const gchar *field_name)
{
	return	0 == g_strcmp0(field_name, M2V2_TABLE_FIELD_MDSYS) ||
			0 == g_strcmp0(field_name, M2V2_TABLE_FIELD_POLICY)||
			0 == g_strcmp0(field_name, M2V2_TABLE_FIELD_ALIAS) ||
			0 == g_strcmp0(field_name, M2V2_TABLE_FIELD_OLD_SYS_METADATA) ||
			0 == g_strcmp0(field_name, M2V2_TABLE_FIELD_OLD_CONTENT_PATH);
}

/**
 * Returns whether the field is of type TEXT.
 * @param field_type The field type to test.
 * @return TRUE if the field is of type TEXT.
 */
static gboolean _is_field_text(const gchar *field_type)
{
	return 0 == g_strcmp0(field_type, M2V2_TABLE_FIELD_TYPE_TEXT);
}

/**
 * Returns whether the field is of type INTEGER.
 * @param field_type The field type to test.
 * @return TRUE if the field is of type INTEGER.
 */
static gboolean _is_field_integer(const gchar *field_type)
{
	return	0 == g_strcmp0(field_type, M2V2_TABLE_FIELD_TYPE_INTEGER) ||
			0 == g_strcmp0(field_type, M2V2_TABLE_FIELD_TYPE_BOOL);
}


//---------------------------------------------------------------------
//
// CONVERSION FUNCTIONS
//
//---------------------------------------------------------------------

/**
 * Converts a BLOB to text.
 * @param req The char array to hold the result.
 * @param blob The BLOB to convert.
 * @param blen The length of the BLOB.
 */
static inline gchar* _req_blob_to_text(gchar *req, const guint8 *blob, const gint blen)
{
	// Some fields in v1 table (e.g. metadata_system) are in text format but do not include
	// a trailing '\0'. Some fields (e.g. content_path) do include a trailing '\0'.
	// So we need to copy the blob until first '\0' or at most blen bytes.
	gchar *iter_req = memccpy(req, blob, 0, blen);
	return iter_req ? iter_req - 1 : req + blen;
}

/**
 * Converts a BLOB to hex char array.
 * Every byte of the blob encodes 2 hex characters.
 * @param req The char array to hold the result.
 * @param blob The BLOB to convert.
 * @param blen The length of the BLOB.
 */
static inline gchar* _req_blob_to_hex(gchar *req, const guint8 *blob, const gint blen)
{
	gint i;
	gchar *iter_req = req;
	for (i = 0; i < blen; ++i, iter_req += 2)
		g_snprintf(iter_req, 2, "%02X", blob[i]);
	*iter_req = '\0';

	return iter_req;
}

/**
 * Converts a BLOB to integer.
 * @param req The char array to hold the result.
 * @param blob The BLOB to convert.
 */
static inline gchar* _req_blob_to_int(gchar *req, const guint8 *blob)
{
	gchar *iter_req = req;
	const void *vblob = blob;
	const guint64 *val = vblob;

	iter_req += g_snprintf(iter_req, 32, "%lu", val ? *val : 0UL);

	return iter_req;
}

/**
 * Converts a BLOB to hex char array.
 * Every byte of the blob encodes 2 hex characters.
 * @param blob The BLOB to convert.
 * @param blen The length of the BLOB.
 * @return A newly allocated hex char array which contains the blob data.
 */
static inline guint8* _blob_to_hex(const guint8 *blob, guint blen)
{
	const gsize reslen = 2 * blen + 1;
	guint8 *res = g_malloc0(reslen);
	gchar *iter_res = (gchar*) res;
	guint i;
	g_assert(res);
	if (blob) {
		for (i = 0; i < blen; ++i, iter_res += 2)
			g_snprintf(iter_res, 2, "%02X", blob[i]);
	}
	res[reslen - 1] = '\0';
	return res;
}

/**
 * Converts a hex char into its integer value according to ascii encoding.
 * @param hexchar The hex char to be converted.
 * @return The integer value of the given hex char, or 0 if a non-hex char is given.
 */
static inline guint8 _get_int(const gchar hexchar)
{
	if (hexchar >= 'A' && hexchar <= 'F')
		return 10U + hexchar - 'A';
	if (hexchar >= 'a' && hexchar <= 'f')
		return 10U + hexchar - 'a';
	if (hexchar >= '0' && hexchar <= '9')
		return hexchar - '0';
	return '\0';
}

/**
 * Converts a hex char array to BLOB.
 * Every byte of the blob encodes 2 hex characters.
 * @param hex The string to convert.
 * @param hexlen The length of the string.
 * @return A newly allocated array which contains the blob data, NULL if hexlen == 0.
 */
static inline guint8* _hex_to_blob(const gchar *hex, const guint hexlen)
{
	guint i, j;
	guint8 *res = g_malloc0(hexlen / 2);
	guint8 u;
	g_assert(res && hexlen < G_MAXUINT-1U);
	if (hexlen == 0 || !res)
		return NULL;
	for (i = 0U, j = 0U; j < hexlen / 2; i += 2U, j++) {
		u = _get_int(hex[i]) << 4;
		u |= _get_int(hex[i + 1]);
		res[j] = u;
	}
	return res;
}


//---------------------------------------------------------------------
//
// REQUEST CREATION
//
//---------------------------------------------------------------------

/**
 * Generates the <code>CREATE TABLE</code> request for the given table info.
 * @param crreq The array in which the request will be generated, must be
 * 				large enough to hold the request.
 * @param ti The table info describing the table for which the request is asked.
 * @return TRUE if generation succeeded, FALSE otherwise.
 */
static gboolean _generate_create_request(gchar *crreq, const t_m2v2_table_info *ti)
{
	gchar *req = crreq;
	g_assert(crreq);

	*req = '\0';
	req = g_stpcpy(req, "CREATE TABLE IF NOT EXISTS ");
	req = g_stpcpy(req, ti->name);
	req = g_stpcpy(req, "(");

	void _make_create_code(gpointer _field_name, gpointer unused)
	{
		gchar * const field_name = _field_name;
		gchar * const field_type = g_hash_table_lookup(ti->field_types, field_name);
		gchar * const field_extra = g_hash_table_lookup(ti->field_extra, field_name);

		(void) unused;

		req = g_stpcpy(req, field_name);
		req = g_stpcpy(req, " ");
		req = g_stpcpy(req, field_type);
		if (field_extra) {
			req = g_stpcpy(req, " ");
			req = g_stpcpy(req, field_extra);
		}
		req = g_stpcpy(req, ",");
	}

	g_slist_foreach(ti->field_names, _make_create_code, NULL);

	void _add_field_and_comma(gpointer _field_name, gpointer _begining)
	{
		gchar * const field_name = _field_name;
		gchar * const begining = _begining;
		if (begining)
			req = g_stpcpy(req, begining);
		req = g_stpcpy(req, field_name);
		req = g_stpcpy(req, ",");
	}

	if (ti->constraints) {
		g_slist_foreach(ti->constraints, _add_field_and_comma, " CONSTRAINT ");
	}

	if (ti->primary_keys) {
		req = g_stpcpy(req, " PRIMARY KEY(");
		g_slist_foreach(ti->primary_keys, _add_field_and_comma, NULL);
		req = g_stpcpy(req - 1, "))");
	} else {
		*(req - 1) = ')';
	}
	req = g_stpcpy(req, ";");

	return TRUE;
}

#ifdef M2V2_NEED_UPDATE_REQ
/**
 * Generates an <code>UPDATE TABLE</code> request for the given table info.
 * @param crreq The array in which the request will be generated, must be
 * 				large enough to hold the request.
 * @param ti The table info describing the table for which the request is asked.
 * @param values The new values, in the order of the table fields.
 * @return TRUE if generation succeeded, FALSE otherwise.
 */
static gboolean _generate_update_request(gchar *upreq, t_m2v2_table_info *ti, GSList *values)
{
	gchar *req = upreq;
	g_assert(upreq);

	*req = '\0';
	req = g_stpcpy(req, "UPDATE TABLE ");
	req = g_stpcpy(req, ti->name);
	req = g_stpcpy(req, " SET ");

	void _make_update_code(gpointer _field_name, gpointer unused)
	{
		gchar *field_name = _field_name;
		(void) unused;

		req = g_stpcpy(req, field_name);
		req = g_stpcpy(req, "=");
		req = g_stpcpy(req, values->data);
		req = g_stpcpy(req, ",");
		values = values->next;
	}

	g_slist_foreach(ti->field_names, _make_update_code, NULL);
	*req = ';';

	return TRUE;
}
#endif

/**
 * Generates an <code>INSERT TABLE</code> request for the given table info.
 * @param inreq The array in which the request will be generated, must be
 * 				large enough to hold the request.
 * @param ti The table info describing the table for which the request is asked.
 * @param values The new values, in the order of the table fields.
 * @return TRUE if generation succeeded, FALSE otherwise.
 */
static gboolean _generate_insert_request(gchar *insert_req, const t_m2v2_table_info *ti, GSList *values)
{
	GSList *field_name_list = ti->field_names;
	gchar *req = insert_req;
	gboolean ret = TRUE;
	gboolean use_sql_bind = TRUE;
	g_assert(insert_req);

	*req = '\0';
	req = g_stpcpy(req, "INSERT OR REPLACE INTO ");
	req = g_stpcpy(req, ti->name);
	req = g_stpcpy(req, " VALUES(");

	void _make_insert_code(gpointer _value, gpointer _use_bind)
	{
		const gboolean * const use_bind = _use_bind;
		t_m2v2_sqlite3_result * const res_value = _value;
		GByteArray * const value = res_value->value;
		gchar *current_field_name = NULL;
		gchar *current_field_type = NULL;

		if (ret == FALSE)
			return;

		if (!field_name_list) {
			GRID_ERROR("Too many values in insert request for table [%s]", ti->name);
			ret = FALSE;
			return;
		}

		current_field_name = field_name_list->data;
		field_name_list = field_name_list->next;
		current_field_type = g_hash_table_lookup(ti->field_types, current_field_name);
		if (current_field_type == NULL) {
			GRID_ERROR("Unknown type for field [%s] in table [%s]", current_field_name, ti->name);
			ret = FALSE;
			return;
		}

		if (*use_bind) {
			// Use sql bind functions rather than specifying the text-formatted values
			// in the request.
			req = g_stpcpy(req, "?");
		} else {
			if (_is_field_text(current_field_type)) {
				req = g_stpcpy(req, "'");
				if (_is_text_in_db(current_field_name)) {
					req = _req_blob_to_text(req, value->data, value->len);
				} else {
					req = _req_blob_to_hex(req, value->data, value->len);
				}
				req = g_stpcpy(req, "'");
			} else if (_is_field_integer(current_field_type)) {
				req = _req_blob_to_int(req, value->data);
			} else {
				req = g_stpcpy(req, "X'");
				req = _req_blob_to_hex(req, value->data, value->len);
				req = g_stpcpy(req, "'");
			}
		}
		req = g_stpcpy(req, ",");
	}

	g_slist_foreach(values, _make_insert_code, &use_sql_bind);
	*(req - 1) = ')';
	req = g_stpcpy(req, ";");

	return ret;
}

/**
 * Generates a <code>SELECT</code> request for the given table info.
 * @param sereq The array in which the request will be generated, must be
 * 				large enough to hold the request.
 * @param ti The table info describing the table for which the request is asked.
 * @param fields The fields to be added to the request. If NULL, the request will
 * 				 read <code>"SELECT *"</code>.
 * @return TRUE if generation succeeded, FALSE otherwise.
 */
static gboolean _generate_select_request(gchar *select_req, const t_m2v2_table_info *ti, GSList *fields)
{
	g_assert(select_req);
	gchar *sereq = select_req;

	*sereq = '\0';
	sereq = g_stpcpy(sereq, "SELECT ");

	void _make_select_code(gpointer _value, gpointer unused)
	{
		gchar * const value = _value;
		(void) unused;

		sereq = g_stpcpy(sereq, value);
		sereq = g_stpcpy(sereq, ",");
	}

	if (fields == NULL) {
		sereq = g_stpcpy(sereq, "* ");
	} else {
		g_slist_foreach(fields, _make_select_code, NULL);
		sereq[strlen(sereq) - 1] = ' ';
	}

	sereq = g_stpcpy(sereq, "FROM ");
	sereq = g_stpcpy(sereq, ti->name);
	sereq = g_stpcpy(sereq, ";");

	return TRUE;
}


//---------------------------------------------------------------------
//
// RESULT CREATION, COMPARISON & DESTRUCTION
//
//---------------------------------------------------------------------

/**
 * Creates a new t_m2v2_sqlite3_result filled with 0s, with a reference count of 1.
 * @return A newly allocated t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _sqlite3_result_new()
{
	t_m2v2_sqlite3_result * const ret = g_malloc0(sizeof(t_m2v2_sqlite3_result));
	g_assert(ret);
	ret->refcount = 1;
	return ret;
}

/**
 * Increments the reference count of the given t_m2v2_sqlite3_result.
 * @param res The t_m2v2_sqlite3_result to reference.
 */
static void _sqlite3_result_ref(t_m2v2_sqlite3_result *res)
{
	if (res) {
		res->refcount++;
	}
}

/**
 * Callback function to be called in g_slist_free_full: frees the
 * list elements, casted to GByteArrays.
 * @param _gba The GByteArray to be freed.
 */
static void _free_gbytearray(gpointer _gba)
{
	GByteArray *gba = _gba;
	if (!gba)
		return;
	if (gba->data)
		g_byte_array_free(gba, TRUE);
	else
		g_byte_array_free(gba, FALSE);
}

/**
 * Decrements the reference count of the given t_m2v2_sqlite3_result.
 * If the reference count drops to 0, the t_m2v2_sqlite3_result and all
 * its data is freed.
 * @param res The t_m2v2_sqlite3_result to unreference.
 */
static void _sqlite3_result_unref(t_m2v2_sqlite3_result *res)
{
	if (res) {
		res->refcount--;
		if (res->refcount == 0) {
			_free_gbytearray(res->value);
			g_free(res);
		}
	}
}

/**
 * Callback method used to free a t_m2v2_sqlite3_result.
 * Directly calls _sqlite3_result_unref.
 * @param _res t_m2v2_sqlite3_result* to be freed.
 */
static void _sqlite3_result_free(gpointer _res)
{
	t_m2v2_sqlite3_result * const res = _res;
	_sqlite3_result_unref(res);
}

/**
 * Callback function to be called in g_slist_free_full: frees the
 * result lists, in which each element is a list of t_m2v2_sqlite3_result*.
 * @param _slist Result list to be freed.
 */
static void _free_result(gpointer _slist)
{
	GSList *slist = _slist;
	if (slist) {
		g_slist_free_full(slist, _sqlite3_result_free);
	}
}

/**
 * This function computes a hash value for a t_m2v2_sqlite3_result.
 * The returned hash is the str_hash of the data converted to hex string.
 * @param _res t_m2v2_sqlite3_result for which the hash is needed.
 * @return The hash needed.
 */
static guint _sqlite3_result_hash(gconstpointer _res)
{
	const t_m2v2_sqlite3_result * const res = _res;
	guint8 * const hexdata = _blob_to_hex(res->value->data, res->value->len);
	const guint hash = g_str_hash(hexdata);
	g_free(hexdata);
	return hash;
}

/**
 * This function compares two t_m2v2_sqlite3_result.
 * Returns TRUE if both t_m2v2_sqlite3_result are equals, ie both have
 * the same type, same data length and data.
 * Neither reference count nor converted fields are tested.
 * @param _res1 t_m2v2_sqlite3_result to be compared.
 * @param _res2 t_m2v2_sqlite3_result to be compared.
 * @return TRUE if _res1 and _res2 are equal, FALSE otherwise.
 */
static gboolean _sqlite3_result_equal(gconstpointer _res1, gconstpointer _res2)
{
	const t_m2v2_sqlite3_result * const res1 = _res1;
	const t_m2v2_sqlite3_result * const res2 = _res2;

	if (res1->type != res2->type)
		return FALSE;

	if (res1->value->len != res2->value->len)
		return FALSE;

	return 0 == memcmp(res1->value->data, res2->value->data, res1->value->len);
}


//---------------------------------------------------------------------
//
// REQUEST EXECUTION
//
//---------------------------------------------------------------------


static void
_exec_adm(sqlite3 *db, const char *k, const char *v) {

	GRID_TRACE2("%s", __FUNCTION__);

	char req[1024];
	memset(req, '\0', 1024);
	g_snprintf(req, 1024, "INSERT INTO admin(k,v) VALUES (\"%s\", \"%s\");", k, v);
	GRID_DEBUG("Executing %s", req);
	sqlite3_exec(db, req, NULL, NULL, NULL);
}

/**
 * Executes the given request and put the result into <code>result</code>
 * (set to NULL if not needed).
 * @param request The request to be executed.
 * @param db The sqlite3 database.
 * @param insert_values A list of t_m2v2_sqlite3_result* to be used in INSERT request,
 * 						when sqlite3_bind_* functions are needed. Use _free_result to free
 * 						the lists elements.
 * @param result The list of result: a list of rows whose elements are also lists of t_m2v2_sqlite3_result*
 * 				 representing the data of each column.
 * @param err A pointer to a GError which will be filled upon execution errors.
 * @return TRUE if execution succeeded, FALSE otherwise.
 */
static gboolean _execute_request(const gchar *request, sqlite3 *db, GSList *insert_values, GSList **result, GError **err)
{
	sqlite3_stmt *stmt = NULL;
	int rc, i, status, errcode, len;
	GSList *fields;
	t_m2v2_sqlite3_result *row_result;
	GSList *res = NULL;
	const guint8 *blob;
	const unsigned char *text;
	int value_count;
	sqlite3_int64 integer;
	const void* data;
	gboolean ret = FALSE;
	g_assert(request);

	void _bind_blobs(gpointer _insert_result, gpointer _vcount)
	{
		t_m2v2_sqlite3_result *insert_result = _insert_result;
		int *vcount = _vcount;
		if (NULL == insert_result->value || NULL == insert_result->value->data) {
			sqlite3_bind_null(stmt, *vcount);
		} else {
			switch(insert_result->type) {
			case SQLITE_TEXT:
				sqlite3_bind_text(stmt, *vcount, (const gchar*) insert_result->value->data, insert_result->value->len, NULL);
				break;
			case SQLITE_INTEGER:
				sqlite3_bind_int64(stmt, *vcount, 
						g_ascii_strtoll((const char*) insert_result->value->data, NULL, 10));
				break;
			case SQLITE_NULL:
				sqlite3_bind_null(stmt, *vcount);
				break;
			case SQLITE_BLOB:
			default:
				sqlite3_bind_blob(stmt, *vcount, insert_result->value->data, insert_result->value->len, NULL);
				break;
			}
		}
		(*vcount)++;
	}

	GRID_DEBUG("Request to prepare : %s", request);
	sqlite3_prepare_debug(rc, db, request, M2V2_MAX_REQ_SIZE, &stmt, NULL);
	if (SQLITE_OK == rc) {
		GRID_TRACE("request prepared successfully [%s]", request);
	} else {
		GSETERROR(err, "error preparing request: %s", sqlite3_errmsg(db));
		goto sql_prepare_error;
	}

	if (insert_values) {
		value_count = 1;
		g_slist_foreach(insert_values, _bind_blobs, &value_count);
	}

	while (SQLITE_ROW == (status = sqlite3_step(stmt))) {
		if (!result)
			continue;
		fields = NULL;
		for (i = 0; i < sqlite3_column_count(stmt); ++i) {
			row_result = _sqlite3_result_new();
			switch (row_result->type = sqlite3_column_type(stmt, i)) {
			case SQLITE_BLOB:
				blob = sqlite3_column_blob(stmt, i);
				data = blob;
				break;
			case SQLITE_INTEGER:
				integer = sqlite3_column_int64(stmt, i);
				data = &integer;
				break;
			case SQLITE_TEXT:
				text = sqlite3_column_text(stmt, i);
				data = text;
				break;
			case SQLITE_FLOAT: // should never happen
			case SQLITE_NULL:
				data = NULL;
				break;
			default:
				data = NULL;
				GSETERROR(err, "Unknown type in sqlite3 result: %i", row_result->type);
				break;
			}
			len = sqlite3_column_bytes(stmt, i);
			row_result->value = g_byte_array_new();
			row_result->value->len = len;
			if (len > 0 && data) {
				row_result->value->data = g_malloc0(len);
				memcpy(row_result->value->data, data, len);
			} else {
				row_result->value->data = NULL;
			}
			fields = g_slist_append(fields, row_result);
		}
		res = g_slist_append(res, fields);
	}

	ret = (status == SQLITE_DONE);

sql_prepare_error:
	if (SQLITE_OK != (errcode = sqlite3_finalize(stmt))) {
		GSETERROR(err, "error finalizing request: %s (code %i)", sqlite3_errmsg(db), errcode);
		if (SQLITE_CANTOPEN == errcode)
			GSETERROR(err, "check permissions on db file AND its parent directory");
	}

	if (result)
		*result = res;

	return ret;
}

/**
 * Destroys the ctime result.
 */
static void _destroy_ctime_result()
{
	if (ctime_result) {
		_free_gbytearray(ctime_result->value);
		g_free(ctime_result);
		ctime_result = NULL;
	}
}

/**
 * Inits the ctime result.
 */
static void _init_ctime_result()
{
	if (ctime_result)
		_destroy_ctime_result(ctime_result);

	ctime_result = _sqlite3_result_new();
	const time_t time_sec = time(NULL);
	GByteArray * const time_gba = g_byte_array_new();

	time_gba->data = g_malloc0(sizeof(time_t));
	memcpy(time_gba->data, &time_sec, sizeof(time_t));
	time_gba->len = sizeof(time_t);

	ctime_result->type = SQLITE_INTEGER;
	ctime_result->value = time_gba;
}

/**
 * Creates a new t_m2v2_sqlite3_result containing the given time.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param time_sec Wanted time.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_ctime_result(gpointer _unused, gpointer _unused2)
{
	(void) _unused;
	(void) _unused2;
	_sqlite3_result_ref(ctime_result);
	return ctime_result;
}

/**
 * Generates chunkid as blob to be used in meta2v1 tables, from new-style text
 * used in meta2v2.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_old_chunkid(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const curid = g_slist_nth_data((GSList*)_cur_val, 2);
	t_m2v2_sqlite3_result * const res = _sqlite3_result_new();
	gchar * const textid = g_strndup((gchar*)curid->value->data, curid->value->len);
	gchar *strid, *cpath;
	guint8 *blobid;
	short unsigned int ip1, ip2, ip3, ip4, port, rtpo;
	(void) _unused;

	res->value = g_byte_array_new();
	res->value->len = 312;
	res->value->data = g_malloc0(res->value->len);

	strid = strrchr(textid, '/');
	blobid = _hex_to_blob(strid + 1, 64);
	memcpy(res->value->data, blobid, 32);

	cpath = strchr(textid + strlen("http://") + 1, '/');
	memcpy(res->value->data + 56, cpath, strid - cpath);

	sscanf(textid + strlen("http://"), "%hu.%hu.%hu.%hu:%hu",
			&ip1, &ip2, &ip3, &ip4, &port);

	rtpo = 0;
	rtpo |= port << 8;
	rtpo |= (port & 0xFF00) >> 8;

	memcpy(res->value->data + 36, &ip1, 1);
	memcpy(res->value->data + 37, &ip2, 1);
	memcpy(res->value->data + 38, &ip3, 1);
	memcpy(res->value->data + 39, &ip4, 1);
	memcpy(res->value->data + 52, &rtpo, 2);

	res->type = SQLITE_BLOB;
	g_free(textid);
	g_free(blobid);
	return res;
}

/**
 * Generates chunkid as text to be used in meta2v2 tables, from old-style blob
 * used in meta2v1.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_chunkid(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const rawid = g_slist_nth_data((GSList*)_cur_val, 0);
	t_m2v2_sqlite3_result * const res = _sqlite3_result_new();
	gchar *strdata, *hexid;
	guint16 port = 0U;
	(void) _unused;

	port  = *(rawid->value->data + 52) << 8;
	port |= *(rawid->value->data + 53);

	hexid =	(gchar*)_blob_to_hex(rawid->value->data, 32);

	// example of output:
	// http://192.168.0.1:6031/DATA/TESTNS/machine/vol01/106FAC779BDA48A3740F8B14A1F20B3024AB15F231E845BE8CC8607E6C9A766B
	strdata = g_strdup_printf("http://%hu.%hu.%hu.%hu:%hu%s/%s",
			*(guint8*)(rawid->value->data + 36),
			*(guint8*)(rawid->value->data + 37),
			*(guint8*)(rawid->value->data + 38),
			*(guint8*)(rawid->value->data + 39),
			port,
			(gchar*)(rawid->value->data + 56),
			hexid
			);

	g_free(hexid);

	res->value = g_byte_array_new();
	res->value->data = (guint8*)strdata;
	res->value->len = strlen(strdata);
	res->type = SQLITE_TEXT;
	return res;
}

/**
 * Callback function aiming to create chunk hash. This function simply returns
 * the chunk hash found as second value in _cur_val, incrementing its reference
 * count by 1.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_hash(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const hashres = g_slist_nth_data((GSList*)_cur_val, 1);
	(void) _unused;

	_sqlite3_result_ref(hashres);
	return hashres;
}

/**
 * Callback function aiming to create chunk size. This function simply returns
 * the chunk size found as third value in _cur_val, incrementing its reference
 * count by 1.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_size(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const sizeres = g_slist_nth_data((GSList*)_cur_val, 2);
	(void) _unused;

	if (!sizeres->converted) {
		sizeres->type = SQLITE_INTEGER;
		sizeres->converted = TRUE;
	}

	_sqlite3_result_ref(sizeres);
	return sizeres;
}

/**
 * Callback function aiming to create chunk size. This function simply returns
 * the chunk size found as second value in _cur_val, incrementing its reference
 * count by 1.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_size2(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const sizeres = g_slist_nth_data((GSList*)_cur_val, 1);
	(void) _unused;

	if (!sizeres->converted) {
		sizeres->type = SQLITE_INTEGER;
		sizeres->converted = TRUE;
	}

	_sqlite3_result_ref(sizeres);
	return sizeres;
}

/**
 * Callback function aiming to create chunk position.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_chunk_pos2(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const posres = g_slist_nth_data((GSList*)_cur_val, 1);
	guint32 intval32 = 0U;
	(void) _unused;

	if (!posres->converted) {
		if (posres->value->data) {
			memcpy(&intval32, posres->value->data, sizeof(intval32));
			memset(posres->value->data, 0, posres->value->len);
			posres->value->len = g_snprintf((gchar*)posres->value->data, 16, "%u", intval32);
		} else {
			GRID_ERROR("Error: _cb_make_chunk_pos2: empty position");
		}
		posres->type = SQLITE_TEXT;
		posres->converted = TRUE;
	}

	_sqlite3_result_ref(posres);
	return posres;
}

/**
 * Callback function aiming to create alias.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_alias(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const aliasres = g_slist_nth_data((GSList*)_cur_val, 0);
	(void) _unused;

	if (!aliasres->converted) {
		aliasres->value->len = strnlen((gchar*) aliasres->value->data, aliasres->value->len);
		aliasres->type = SQLITE_TEXT;
		aliasres->converted = TRUE;
	}

	_sqlite3_result_ref(aliasres);
	return aliasres;
}

/**
 * Callback function aiming to create system metadata.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_mdsys2(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const mdsysres = g_slist_nth_data((GSList*)_cur_val, 1);
	(void) _unused;

	if (!mdsysres->converted) {
		mdsysres->value->len = strnlen((gchar*) mdsysres->value->data, mdsysres->value->len);
		mdsysres->type = SQLITE_TEXT;
		mdsysres->converted = TRUE;
	}

	_sqlite3_result_ref(mdsysres);
	return mdsysres;
}

/**
 * Callback function aiming to create mdusr.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_prop_key(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const propres = g_slist_nth_data((GSList*)_cur_val, 1);
	(void) _unused;

	if (!propres->converted) {
		propres->value->len = strnlen((gchar*) propres->value->data, propres->value->len);
		propres->type = SQLITE_TEXT;
		propres->converted = TRUE;
	}

	_sqlite3_result_ref(propres);
	return propres;
}

/**
 * Callback function aiming to create mdusr.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_mdusr_prop_key(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const res = _sqlite3_result_new();
	(void) _unused;
	(void) _cur_val;

	res->value = g_byte_array_append(g_byte_array_new(), (const guint8*)MDUSR_PROPERTY_KEY,
			strlen(MDUSR_PROPERTY_KEY));
	res->type = SQLITE_TEXT;
	return res;
}

/**
 * Callback function aiming to create mdusr.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val The current result.
 * @param _unused Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_prop_val(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const mdsysres = g_slist_nth_data((GSList*)_cur_val, 2);
	(void) _unused;

	if (!mdsysres->converted) {
		mdsysres->value->len = strnlen((gchar*) mdsysres->value->data, mdsysres->value->len);
		mdsysres->type = SQLITE_BLOB;
		mdsysres->converted = TRUE;
	}

	_sqlite3_result_ref(mdsysres);
	return mdsysres;
}

/**
 * Creates a new t_m2v2_sqlite3_result with a length of 4 and data set to zeroes.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _make_zero_result()
{
	t_m2v2_sqlite3_result * const zero = _sqlite3_result_new();
	zero->type = SQLITE_BLOB;
	zero->value = g_byte_array_new();
	zero->value->len = 4U;
	zero->value->data = g_malloc0(zero->value->len);
	return zero;
}

/**
 * Callback function to create a new t_m2v2_sqlite3_result with a length
 * of 4 and data set to zeroes.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _unused Unused.
 * @param _unused2 Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_zero_result(gpointer _unused, gpointer _unused2)
{
	(void) _unused;
	(void) _unused2;
	t_m2v2_sqlite3_result * const zero = _sqlite3_result_new();
	zero->type = SQLITE_INTEGER;
	zero->value = g_byte_array_append(g_byte_array_new(), (const guint8*)"0\0", 2);
	return zero;
}

/**
 * Callback function to create a new t_m2v2_sqlite3_result with a length
 * of 4 and data set to the unsigned integer value 1.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _unused Unused.
 * @param _unused2 Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_one_result(gpointer _unused, gpointer _unused2)
{
	(void) _unused;
	(void) _unused2;
	t_m2v2_sqlite3_result * const one = _sqlite3_result_new();
	one->type = SQLITE_INTEGER;
	one->value = g_byte_array_append(g_byte_array_new(), (const guint8*)"1\0", 2);
	return one;
}

/**
 * Callback function to create a new t_m2v2_sqlite3_result with a length
 * of 0 and data set to NULL.
 * @param _unused Unused.
 * @param _unused2 Unused.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_null_result(gpointer _unused, gpointer _unused2)
{
	(void) _unused;
	(void) _unused2;
	t_m2v2_sqlite3_result * const resnull = _sqlite3_result_new();
	resnull->type = SQLITE_NULL;
	resnull->value = NULL;
	return resnull;
}

/**
 * Creates a new t_m2v2_sqlite3_result of type TEXT, filled with a copy of
 * the char array str.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param str The char array for which a t_m2v2_sqlite3_result is needed.
 * @return The new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _make_result_from_string(const gchar *str)
{
	t_m2v2_sqlite3_result *res;
	GByteArray *gba;

	if (!str)
		return _make_zero_result();

	gba = g_byte_array_new();
	gba->len = strlen(str);
	gba->data = g_malloc0(gba->len);
	memcpy(gba->data, str, gba->len);

	res = _sqlite3_result_new();
	res->type = SQLITE_TEXT;
	res->value = gba;

	return res;
}

/**
 * Returns the value of a field from system metadata retrieved from v1 db.
 * The returned value is a copy which should be freed using  g_free.
 * @param mdsys_res System metadata as returned by a SELECT request.
 * @param mdsys_key The key of the wanted system metadata entry.
 * @return A new string containing the wanted value, NULL if not found.
 */
static const gchar* _get_field_from_mdsys(const t_m2v2_sqlite3_result *mdsys_res, const gchar *mdsys_key)
{
	gchar *mdsys, *value, *ret = NULL;
	GHashTable *mdsys_ht;
	GError *err = NULL;

	mdsys = g_strndup((const gchar*) mdsys_res->value->data, mdsys_res->value->len);
	if (NULL != mdsys) {
		if (NULL != (mdsys_ht = metadata_unpack_string(mdsys, &err))) {
			if (NULL != (value = g_hash_table_lookup(mdsys_ht, mdsys_key)))
				ret = g_strdup(value);
			g_hash_table_destroy(mdsys_ht);
		}
		g_free(mdsys);
	}
	return ret;
}

/**
 * Callback to extract the storage-policy from system metadata,
 * to be inserted into content_header_v2 table.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_storage_pol(gpointer _cur_val, gpointer _cbarg)
{
	GSList * const cur_val = _cur_val;
	GSList * const values = g_slist_nth_data((GSList*)_cbarg, 1);
	GSList *found_list, *found_value;
	const gchar *storage_policy;
	t_m2v2_sqlite3_result *ret = NULL;

	gint _find_content_path (gconstpointer _old_values, gconstpointer _new_value)
	{
		t_m2v2_sqlite3_result * const cpath = g_slist_nth_data((GSList*)_new_value, 0);
		t_m2v2_sqlite3_result * const cpath2 = g_slist_nth_data((GSList*)_old_values, 0);

		if (cpath && cpath->value && cpath2 && cpath2->value)
			return memcmp(cpath->value->data, cpath2->value->data, cpath->value->len);
		return -1;
	}

	// look for content path to find out the correct result row.
	found_list = g_slist_find_custom(values, cur_val, _find_content_path);
	if (found_list) {
		if (NULL != (found_value = g_slist_nth_data(found_list, 0))) {
			if (NULL != (storage_policy = _get_field_from_mdsys(g_slist_nth_data(found_value, 1), DB_ADMIN_KEY_CSTGPOLICY))) {
				ret = _make_result_from_string(storage_policy);
				g_free((void*)storage_policy);
			}
		}
	}

	if (!ret)
		ret = _make_zero_result();

	return ret;
}

/**
 * Get contentid from given contentids hashtable, or create a new one if not
 * found and store it in the hashtable. The returned id should be freed with
 * {@link _sqlite3_result_unref}.
 * @param contentpathres the result containing the contentpath for which an id is needed
 * @param contentids the content ids hash table
 * @return the contentid for the given content path
 */
static t_m2v2_sqlite3_result* _get_contentid(t_m2v2_sqlite3_result *contentpathres, GHashTable *contentids)
{
	const gsize idsize = 32U;
	guint8 *buf;
	t_m2v2_sqlite3_result *res;
	gchar *content_path;

	g_assert(contentpathres && contentpathres->value);
	g_assert(contentids);

	content_path = (gchar*) contentpathres->value->data;

	if (content_path) {
		if (NULL == (res = g_hash_table_lookup(contentids, content_path))) {
			buf = g_malloc0(idsize);
			res = _sqlite3_result_new();
			res->type = SQLITE_BLOB;
			res->value = g_byte_array_new();
			res->value->len = idsize;
			SHA256_randomized_buffer(buf, idsize);
			res->value->data = buf;
			g_hash_table_insert(contentids, g_strndup(content_path, contentpathres->value->len), res);
		}
	} else {
		GRID_ERROR("Error: _get_contentid: Empty content path");
		res = _sqlite3_result_new();
		res->type = SQLITE_NULL;
		res->value = NULL;
	}

	// Always increment ref count as we need to keep the content id for every row.
	_sqlite3_result_ref(res);

	return res;
}

/**
 * Callback to retrieve the correct contentid as first element of resulting row.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the contentid hash table.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_contentid(gpointer _cur_val, gpointer _cbarg)
{
	GHashTable * const contentids = g_slist_nth_data((GSList*)_cbarg, 0); // first cbarg value is the contentids hashtable
	t_m2v2_sqlite3_result * const contentpathres = g_slist_nth_data((GSList*)_cur_val, 0);

	return _get_contentid(contentpathres, contentids);
}

/**
 * Callback to retrieve the correct contentid as second element of resulting row.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the contentid hash table.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_contentid2(gpointer _cur_val, gpointer _cbarg)
{
	GHashTable * const contentids = g_slist_nth_data((GSList*)_cbarg, 0); // first cbarg value is the contentids hashtable
	t_m2v2_sqlite3_result * const contentpathres = g_slist_nth_data((GSList*)_cur_val, 2);

	return _get_contentid(contentpathres, contentids);
}

/**
 * Returns a new list which contains the fields to be inserted in
 * a new table. The returned list is a merge of values retrieved
 * from old table and new values computed using callbacks.
 * @param values Old values retrieved using a SELECT request.
 * @param cb_new_fields List of callbacks which return the new values.
 * @param cbarg Argument passed to the callbacks listed in cb_new_fields.
 * @return the merged list (to be freed with g_slist_free).
 */
static GSList* _merge_lists(GSList *values, GSList *cb_new_fields, gpointer cbarg)
{
	GSList *merged_list = NULL;
	GSList *cursor_values = values;

	// If a callback is defined, call it and use its return value as the new value to be
	// inserted. Otherwise use the value retrieved from old table.
	void _choose_value(gpointer _new_field, gpointer _cbarg)
	{
		t_m2v2_sqlite3_result* (*new_field) (gpointer, gpointer) = _new_field;
		t_m2v2_sqlite3_result *field_value = NULL;

		if (new_field) {
			field_value = new_field(values, _cbarg);
		} else {
			if (cursor_values) {
				field_value = g_slist_nth_data(cursor_values, 0);
				cursor_values = g_slist_nth(cursor_values, 1);
				_sqlite3_result_ref(field_value);
			} else {
				GRID_ERROR("Error: merge_lists: list length mismatch.");
			}
		}
		if (field_value)
			merged_list = g_slist_append(merged_list, field_value);
	}

	g_slist_foreach(cb_new_fields, _choose_value, cbarg);

	return merged_list;
}

/**
 * Retrieves values from a table.
 * @param db The sqlite3 database.
 * @param table_info The corresponding table info.
 * @param fields_names Names of fields to be retrieved.
 * @param p_retrieved_values A pointer to the table of results.
 * @param err GError, holds any error which may occur.
 * @return TRUE if no error occurred, FALSE otherwise.
 */
static gboolean _retrieve_values(
		sqlite3 *db,
		const t_m2v2_table_info *table_info,
		GSList *fields_names,
		GSList **p_retrieved_values,
		GError **err)
{
	gchar req[M2V2_MAX_REQ_SIZE];
	gboolean ret = FALSE;

	g_assert(p_retrieved_values);
	memset(req, 0, M2V2_MAX_REQ_SIZE);

	// SELECT request generation
	if (_generate_select_request(req, table_info, fields_names)) {
		GRID_TRACE("request generated successfully: [%s]", req);
	} else {
		GRID_TRACE("error generating request [%s]", req);
		goto error;
	}

	// SELECT request execution
	g_clear_error(err);
	if (_execute_request(req, db, NULL, p_retrieved_values, err)) {
		GRID_TRACE("request executed successfully: [%s]", req);
	} else {
		GRID_TRACE("error executing request [%s]: [%s]", req, (*err)->message);
		goto error;
	}

	ret = TRUE;

error:
	return ret;
}

/**
 * Insert values into a table.
 * @param db The sqlite3 database.
 * @param table_info The destination table.
 * @param new_values The new values to be inserted: one GSList per row,
 * 					 this argument is a GSList* of GSList*.
 * @param new_fields_cb The list of callbacks for new fields (all NULL fields
 * 						in new_values).
 * @param cbarg Generic argument for callbacks.
 * @param err GError, holds any error which may occur.
 * @return TRUE if no error occurred, FALSE otherwise.
 */
static gboolean _insert_values(
		sqlite3 *db,
		const t_m2v2_table_info *table_info,
		GSList *new_values,
		GSList *new_fields_cb,
		gpointer cbarg,
		GError **err)
{
	gchar req[M2V2_MAX_REQ_SIZE];
	gboolean ret = TRUE;

	g_assert(new_values);
	memset(req, 0, M2V2_MAX_REQ_SIZE);

	void _make_db_row(gpointer _values, gpointer _unused)
	{
		(void) _unused;
		GSList *values = _values;
		GSList *final_list = _merge_lists(values, new_fields_cb, cbarg);

		*req = '\0';
		g_clear_error(err);
		if (_generate_insert_request(req, table_info, final_list)) {
			GRID_TRACE("request generated successfully: [%s]", req);
		} else {
			GRID_TRACE("error generating insert request: [%s]", (*err)->message);
			g_slist_free_full(final_list, _sqlite3_result_free);
			ret = FALSE;
			return;
		}

		g_clear_error(err);
		if (_execute_request(req, db, final_list, NULL, err)) {
			GRID_TRACE("request executed successfully: [%s]", req);
		} else {
			GRID_TRACE("error executing request [%s]: [%s]", req, (*err)->message);
			g_slist_free_full(final_list, _sqlite3_result_free);
			ret = FALSE;
			return;
		}
		g_slist_free_full(final_list, _sqlite3_result_free);
		final_list = NULL;
	}

	g_slist_foreach(new_values, _make_db_row, NULL);

	return ret;
}

#define CVDB_FREE_LISTS \
	do { \
		if (fields_names) { \
			g_slist_free(fields_names); \
			fields_names = NULL; \
		} \
		if (new_fields_cb) { \
			g_slist_free(new_fields_cb); \
			new_fields_cb = NULL; \
		} \
	} while (0)

#define CVDB_FREE_RETR_VAL(p_retr_val) \
	do { \
		if (p_retr_val) { \
			g_slist_free_full(*p_retr_val, _free_result); \
			g_free(p_retr_val); \
			p_retr_val = NULL; \
		} \
	} while (0)

#define CVDB_CREATE_TABLE(tablename) \
	do { \
		if (_generate_create_request(req, tablename)) { \
			GRID_TRACE("request generated successfully: [%s]", req); \
		} else { \
			err = NEWERROR(500, "error generating request [%s]", req); \
			goto error; \
		} \
		if (_execute_request(req, db, NULL, NULL, &err)) { \
			GRID_TRACE("request executed successfully: [%s]", req); \
		} else { \
			g_prefix_error(&err, "error executing request [%s]: ", req); \
			goto error; \
		} \
	} while (0)

static void
_create_indexes(sqlite3 *db)
{
	/* create all indexes */
	sqlite3_exec(db, "CREATE INDEX snapshot_index_by_name on snapshot_v2(name);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE INDEX properties_index_by_header on properties_v2(alias);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE INDEX contents_index_by_header on content_v2(content_id)", NULL, NULL, NULL);
}

/**
 * Converts a database from v1 schema to v2 schema.
 * @param dbpath Path to the database.
 * @return TRUE if the conversion finished successfully, FALSE otherwise.
 */
GError*
m2_convert_db(sqlite3 *db)
{
	GRID_DEBUG("%s", __FUNCTION__);
	GSList *fields_names = NULL, *new_fields_cb = NULL, *cbarg = NULL;
	GSList **p_retrieved_values = NULL, **p_retrieved_values2 = NULL;
	gboolean ret = FALSE;
	gchar req[M2V2_MAX_REQ_SIZE];
	GHashTable *contentids = NULL;
	GError *err = NULL;

	g_assert(db != NULL);

	if (chunk_table == NULL)
		m2v2_init_db();

	memset(req, 0, M2V2_MAX_REQ_SIZE);

	/* PREPARE ADM */
	p_retrieved_values = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, "k");
	fields_names = g_slist_append(fields_names, "v");

	// Convert table
	GRID_TRACE("Going to retrieve admin values");
	ret = _retrieve_values(db, old_admin_table, fields_names, p_retrieved_values, &err);

	/* */
	strcpy(req, "DELETE from admin;");
	if (!_execute_request(req, db, NULL, NULL, &err)) {
		GRID_TRACE("error on del req : %s", err->message);
		g_prefix_error(&err, "error executing request [%s]: ", req);
		goto error;
	}

	CVDB_CREATE_TABLE(chunk_table);
	CVDB_CREATE_TABLE(content_table);
	CVDB_CREATE_TABLE(content_header_table);
	CVDB_CREATE_TABLE(alias_table);
	CVDB_CREATE_TABLE(properties_table);
	CVDB_CREATE_TABLE(snapshot_table);

	_create_indexes(db);

	_init_ctime_result();

	//----------------------------------------------------------------
	/* Build a list with entries we need */
	GSList * l = NULL;
	for(l = *p_retrieved_values; l; l=l->next) {
		if(!l->data)
			continue;
		t_m2v2_sqlite3_result *r = g_slist_nth_data(l->data, 0);
		if(0 == g_ascii_strncasecmp((const char *)r->value->data, "storage_policy", r->value->len)) {
			t_m2v2_sqlite3_result *v = g_slist_nth_data(l->data, 1);
			char tmp[256];
			memset(tmp, '\0', 256);
			memcpy(tmp, v->value->data, v->value->len);
			_exec_adm(db, "sys.storage_policy", tmp);
		} else if (0 == g_ascii_strncasecmp((const char *)r->value->data, "container_size", r->value->len)) {
			t_m2v2_sqlite3_result *v = g_slist_nth_data(l->data, 1);
			char tmp[256];
			memset(tmp, '\0', 256);
			memcpy(tmp, v->value->data, v->value->len);
			if(0 == strlen(tmp))
				tmp[0] = '0';
			_exec_adm(db, "sys.container_size", tmp);
		}
	}

	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values);
	if (!ret)
		goto error;


	//-----------------------------------------------------------------
	// CHUNK
	p_retrieved_values = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CHUNK_ID); // used in _cb_make_chunkid
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CHUNK_HASH); // first NULL CB
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CHUNK_LENGTH); // second NULL CB

	// Values for new table
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunkid); // id
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_hash); // hash
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_size); // size
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_ctime_result); // ctime

	// Convert table
	if ((ret = _retrieve_values(db, old_chunk_table, fields_names, p_retrieved_values, &err))
			&& 0 < g_slist_length(*p_retrieved_values)) {
		ret = _insert_values(db, chunk_table, *p_retrieved_values, new_fields_cb, NULL, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values);
	if (!ret)
		goto error;

	//-----------------------------------------------------------------

	//-----------------------------------------------------------------
	// CONTENT
	// Add contentids hashtable as the first element of cbarg
	contentids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, _sqlite3_result_free);
	cbarg = g_slist_append(cbarg, contentids);

	p_retrieved_values = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CHUNK_ID); // used in _cb_make_chunkid
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CHUNK_POS); // first NULL CB
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CONTENT_PATH); // used in make_contentid CB

	// Make contentid field
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_contentid2); // contentid
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunkid); // chunkid
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunk_pos2); // position
 
	// Convert table
	if ((ret = _retrieve_values(db, old_chunk_table, fields_names, p_retrieved_values, &err)) 
			&& 0 < g_slist_length(*p_retrieved_values)) {
		ret = _insert_values(db, content_table, *p_retrieved_values, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values);
	if (!ret)
		goto error;
	//-----------------------------------------------------------------

	//-----------------------------------------------------------------
	// ALIAS
	p_retrieved_values = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CONTENT_PATH);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_SYS_METADATA);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_METADATA);

	// Make alias, aliasversion, containerversion, contenthash, ctime, deleted
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_alias); // alias
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_one_result); // version
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_one_result); // containerversion
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_contentid); // contentid
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_mdsys2); // mdsys
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_ctime_result); // ctime
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_zero_result); // deleted

	// Convert table
	if ((ret = _retrieve_values(db, old_content_table, fields_names, p_retrieved_values, &err)) 
			&& 0 < g_slist_length(*p_retrieved_values)) {
		ret = _insert_values(db, alias_table, *p_retrieved_values, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;

	if (!ret)
		goto error;

	//PROPERTIES from MDUSR
	GSList *prop_list = NULL;
	for(l = *p_retrieved_values; l; l = l->next) {
		t_m2v2_sqlite3_result * const mdusr = g_slist_nth_data((GSList*)l->data, 2);
		if(mdusr && mdusr->value && mdusr->value->len > 0) {
			prop_list = g_slist_prepend(prop_list, l->data);
		}
	}

	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_alias); // alias
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_one_result); // version
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_mdusr_prop_key); //key (special mdusr key)
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_prop_val); // value (mdusr)
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_zero_result); // deleted

	if(0 < g_slist_length(prop_list))
		ret = _insert_values(db, properties_table, prop_list, new_fields_cb, cbarg, &err);

	CVDB_FREE_LISTS;
	/* no need to free list elts */
	g_slist_free(prop_list);

	if (!ret)
		goto error;
	//-----------------------------------------------------------------

	//-----------------------------------------------------------------
	// CONTENT_HEADER
	// do not initialize p_retrieved_values
	//p_retrieved_values = g_malloc0(sizeof(GSList*));
	p_retrieved_values2 = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	// We need contentpath in order to be able to link correct mdsys from old content table.
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CONTENT_PATH);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CONTENT_LENGTH);

	// Make hash and policy
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_contentid); // id
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_storage_pol); // policy
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_null_result); // hash
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_size2); // size

	// Convert table
	cbarg = g_slist_append(cbarg, *p_retrieved_values);
	if ((ret = _retrieve_values(db, old_content_table, fields_names, p_retrieved_values2, &err))
			&& 0 < g_slist_length(*p_retrieved_values2)) {
		ret = _insert_values(db, content_header_table, *p_retrieved_values2, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values);
	CVDB_FREE_RETR_VAL(p_retrieved_values2);
	if (!ret)
		goto error;
	//-----------------------------------------------------------------

	//-----------------------------------------------------------------
	// CONTENT_PROPERTIES
	// do not initialize p_retrieved_values
	p_retrieved_values = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	// We need contentpath in order to be able to link correct mdsys from old content table.
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_CONTENT_PATH);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_PROPERTY);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_OLD_VALUE);

	// Builder for V2 prop
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_alias); // id
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_one_result); // version
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_prop_key); //key 
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_prop_val); // value 
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_zero_result); // deleted

	if ((ret = _retrieve_values(db, old_properties_table, fields_names, p_retrieved_values, &err))
			&& 0 < g_slist_length(*p_retrieved_values)) {
		GRID_TRACE("Found %d properties in old table", g_slist_length(*p_retrieved_values));
		ret = _insert_values(db, properties_table, *p_retrieved_values, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values);

error:
	_destroy_ctime_result();
	if (contentids)
		g_hash_table_destroy(contentids);
	g_slist_free(cbarg);
	return err;
}

/**
 * Callback to retrieve the correct system metadata.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_mdsys(gpointer _cur_val, gpointer _values)
{
	GSList * const first_list_of_values = g_slist_nth_data((GSList*)_values, 0);
	GSList *found_list, *found_value;
	t_m2v2_sqlite3_result *ret = NULL;

	gint _find_content_id (gconstpointer _old_values, gconstpointer _cval)
	{
		t_m2v2_sqlite3_result * const cid = g_slist_nth_data((GSList*)_cval, 1);
		t_m2v2_sqlite3_result * const cid2 = g_slist_nth_data((GSList*)_old_values, 2);

		if (cid && cid->value && cid2 && cid2->value)
			return memcmp(cid->value->data, cid2->value->data, cid->value->len);
		return -1;
	}

	found_list = g_slist_find_custom(first_list_of_values, _cur_val, _find_content_id);
	if (found_list) {
		if (NULL != (found_value = g_slist_nth_data(found_list, 0))) {
			ret = g_slist_nth_data(found_value, 1);
			if (!ret->converted) {
				ret->type = SQLITE_BLOB;
				ret->converted = TRUE;
			}
			_sqlite3_result_ref(ret);
		}
	}

	if (!ret)
		ret = _make_zero_result();

	return ret;
}

/**
 * Callback to retrieve the correct content path.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_content_path(gpointer _cur_val, gpointer _values)
{
	GSList *found_list, *found_value;
	GSList * const first_list_of_values = g_slist_nth_data((GSList*)_values, 0);
	t_m2v2_sqlite3_result *ret = NULL;

	gint _find_content_id (gconstpointer _old_values, gconstpointer _cval)
	{
		t_m2v2_sqlite3_result * const cid = g_slist_nth_data((GSList*)_cval, 1);
		t_m2v2_sqlite3_result * const cid2 = g_slist_nth_data((GSList*)_old_values, 2);

		if (cid && cid->value && cid2 && cid2->value)
			return memcmp(cid->value->data, cid2->value->data, cid->value->len);
		return -1;
	}

	found_list = g_slist_find_custom(first_list_of_values, _cur_val, _find_content_id);
	if (found_list) {
		if (NULL != (found_value = g_slist_nth_data(found_list, 0))) {
			ret = g_slist_nth_data(found_value, 0);
			_sqlite3_result_ref(ret);
		}
	}

	if (!ret)
		ret = _make_zero_result();

	return ret;
}

/**
 * Callback to retrieve the correct content path.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_content_path_from_previous(gpointer _cur_val, gpointer _values)
{
	GSList *tmp_list, *found_list, *found_value, *found_list2;
	GSList * const first_list_of_values = g_slist_nth_data((GSList*)_values, 0);
	GSList * const second_list_of_values = g_slist_nth_data((GSList*)_values, 1);
	t_m2v2_sqlite3_result *ret = NULL;

	gint _find_content_path (gconstpointer _old_values, gconstpointer _new_value)
	{
		t_m2v2_sqlite3_result * const chunkid = g_slist_nth_data((GSList*)_new_value, 2);
		t_m2v2_sqlite3_result * const chunkid2 = g_slist_nth_data((GSList*)_old_values, 0);

		if (chunkid && chunkid->value && chunkid2 && chunkid2->value)
			return memcmp(chunkid->value->data, chunkid2->value->data, chunkid->value->len);
		return -1;
	}

	gint _find_content_id (gconstpointer _old_values, gconstpointer _cid)
	{
		const t_m2v2_sqlite3_result * const cid = _cid;
		t_m2v2_sqlite3_result * const cid2 = g_slist_nth_data((GSList*)_old_values, 2);

		if (cid && cid->value && cid2 && cid2->value)
			return memcmp(cid->value->data, cid2->value->data, cid->value->len);
		return -1;
	}

	tmp_list = g_slist_find_custom(second_list_of_values, _cur_val, _find_content_path);
	if (tmp_list && (found_list = g_slist_nth_data(tmp_list, 0))) {
		if (NULL != (found_value = g_slist_nth_data(found_list, 2))) {
			if (NULL != (found_list2 = g_slist_find_custom(first_list_of_values, found_value, _find_content_id))) {
				if (NULL != (found_value = g_slist_nth_data(found_list2, 0))) {
					ret = g_slist_nth_data(found_value, 0);
					if (!ret->converted) {
						// increment size to add null byte at the end
						ret->value->data = g_realloc(ret->value->data, ret->value->len + 1);
						memset(ret->value->data + ret->value->len, 0, 1);
						ret->value->len++;
						ret->converted = TRUE;
						ret->type = SQLITE_BLOB;
					}
					_sqlite3_result_ref(ret);
				}
			}
		}
	}

	if (!ret)
		ret = _make_zero_result();

	return ret;
}

/**
 * Callback to retrieve the correct chunk position.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_chunk_pos(gpointer _cur_val, gpointer _values)
{
	GSList * const cur_val = _cur_val;
	GSList *found_list, *found_value;
	GSList * const second_list_of_values = g_slist_nth_data((GSList*)_values, 1);
	t_m2v2_sqlite3_result *ret = NULL;
	guint32 intval32;
	const gchar *textdata;

	gint _find_content_path (gconstpointer _old_values, gconstpointer _new_value)
	{
		t_m2v2_sqlite3_result * const chunkid = g_slist_nth_data((GSList*)_new_value, 2);
		t_m2v2_sqlite3_result * const chunkid2 = g_slist_nth_data((GSList*)_old_values, 0);

		if (chunkid && chunkid->value && chunkid2 && chunkid2->value)
			return memcmp(chunkid->value->data, chunkid2->value->data, chunkid->value->len);
		return -1;
	}

	found_list = g_slist_find_custom(second_list_of_values, cur_val, _find_content_path);
	if (found_list) {
		if (NULL != (found_value = g_slist_nth_data(found_list, 0))) {
			ret = g_slist_nth_data(found_value, 1);
			if (!ret->converted) {
				textdata = g_strndup((const gchar*) ret->value->data, ret->value->len);
				intval32 = strtoul(textdata, NULL, 10);
				g_free((gpointer)textdata);
				g_free(ret->value->data);
				ret->value->len = sizeof(intval32);
				ret->value->data = g_malloc0(ret->value->len);
				memcpy(ret->value->data, &intval32, ret->value->len);
				ret->type = SQLITE_BLOB;
				ret->converted = TRUE;
			}
			_sqlite3_result_ref(ret);
		}
	}

	if (!ret)
		ret = _make_zero_result();

	return ret;
}

/**
 * Callback to retrieve the correct chunk length.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it is unused.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_chunk_length(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const lenres = g_slist_nth_data((GSList*)_cur_val, 0);
	guint64 intval64;
	(void) _unused;

	if (!lenres->converted) {
		intval64 = 0UL;
		if (lenres->value->len < sizeof(intval64)) {
			lenres->value->data = g_realloc(lenres->value->data, sizeof(intval64));
			memset(lenres->value->data + lenres->value->len, 0, sizeof(intval64) - lenres->value->len);
			lenres->value->len = sizeof(intval64);
		}
		lenres->type = SQLITE_BLOB;
		lenres->converted = TRUE;
	}

	_sqlite3_result_ref(lenres);
	return lenres;
}

/**
 * Callback to retrieve the correct content length.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it is unused.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_content_length(gpointer _cur_val, gpointer _unused)
{
	t_m2v2_sqlite3_result * const lenres = g_slist_nth_data((GSList*)_cur_val, 0);
	guint64 intval64;
	(void) _unused;

	if (!lenres->converted) {
		intval64 = 0UL;
		if (lenres->value->len < sizeof(intval64)) {
			lenres->value->data = g_realloc(lenres->value->data, sizeof(intval64));
			memset(lenres->value->data + lenres->value->len, 0, sizeof(intval64) - lenres->value->len);
			lenres->value->len = sizeof(intval64);
		}
		lenres->type = SQLITE_BLOB;
		lenres->converted = TRUE;
	}

	_sqlite3_result_ref(lenres);
	return lenres;
}

/**
 * Callback to retrieve the correct chunk number.
 * The result should be freed using {@link _sqlite3_result_unref}.
 * @param _cur_val Current row values (GSList*).
 * @param _cbarg Generic callback argument, here it holds the result of previous requests.
 * @return A new t_m2v2_sqlite3_result.
 */
static t_m2v2_sqlite3_result* _cb_make_chunknb(gpointer _cur_val, gpointer _values)
{
	GHashTable * const nbchunkht = g_slist_nth_data((GSList*)_values, 2);
	t_m2v2_sqlite3_result * const res_cid = g_slist_nth_data((GSList*)_cur_val, 1);
	t_m2v2_sqlite3_result * const ret = _sqlite3_result_new();
	const guint32 * const nbchunks = g_hash_table_lookup(nbchunkht, res_cid);
	ret->value = g_byte_array_new();
	ret->value->len = sizeof(*nbchunks);
	ret->value->data = g_malloc(ret->value->len);
	memcpy(ret->value->data, nbchunks, ret->value->len);
	ret->type = SQLITE_BLOB;
	return ret;
}

/**
 * Converts a database from v2 schema to v1 schema.
 * @param dbpath Path to the database.
 * @return TRUE if the conversion finished successfully, FALSE otherwise.
 */
GError* m2_unconvert_db(sqlite3 *db)
{
	GError *err = NULL;
	GSList *fields_names = NULL, *new_fields_cb = NULL, *cbarg = NULL;
	GSList **p_retrieved_values = NULL, **p_retrieved_values2 = NULL, **p_retrieved_values3 = NULL;
	gboolean ret = FALSE;
	gchar req[M2V2_MAX_REQ_SIZE];
	GHashTable *chunk_nbs = NULL;

	g_assert(db != NULL);

	if (chunk_table == NULL)
		m2v2_init_db();

	memset(req, 0, M2V2_MAX_REQ_SIZE);

	// If content was created in meta2v2, no content_property table will
	// be found in db. This table is required in meta2v1, so we need to
	// create an empty table.
	strcpy(req, "CREATE TABLE IF NOT EXISTS content_property(content_path BLOB, content_version BLOB, property BLOB, value BLOB);");
	if (_execute_request(req, db, NULL, NULL, &err)) {
		GRID_TRACE("request executed successfully: [%s]", req);
	} else {
		g_prefix_error(&err, "error executing request [%s]", req);
		goto error;
	}

	*req = '\0';
	CVDB_CREATE_TABLE(old_chunk_table);
	CVDB_CREATE_TABLE(old_content_table);

	p_retrieved_values = g_malloc0(sizeof(GSList*));
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_ALIAS);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_MDSYS);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_CONTENTID);
	ret = _retrieve_values(db, alias_table, fields_names, p_retrieved_values, &err);
	cbarg = g_slist_append(cbarg, *p_retrieved_values);
	CVDB_FREE_LISTS;
	// do not clear retrieved values
	if (!ret)
		goto error;

	p_retrieved_values2 = g_malloc0(sizeof(GSList*));
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_CHUNKID);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_POSITION);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_CONTENTID);
	ret = _retrieve_values(db, content_table, fields_names, p_retrieved_values2, &err);
	cbarg = g_slist_append(cbarg, *p_retrieved_values2);
	CVDB_FREE_LISTS;
	// do not clear retrieved values
	if (!ret)
		goto error;

	// compute chunk number for every content id
	// chunk_nb = max(chunk_pos) + 1
	void _process_chunk_nb(gpointer _value, gpointer unused)
	{
		t_m2v2_sqlite3_result * const res_chunkpos = g_slist_nth_data((GSList*)_value, 1);
		t_m2v2_sqlite3_result * const res_contentid = g_slist_nth_data((GSList*)_value, 2);
		const gchar* const textdata = g_strndup((gchar*)res_chunkpos->value->data, res_chunkpos->value->len);
		const guint32 chunkpos = strtoul(textdata, NULL, 10);
		guint32 *chunknb;
		(void) unused;

		if (NULL == (chunknb = g_hash_table_lookup(chunk_nbs, res_contentid))) {
			chunknb = g_malloc0(sizeof(*chunknb));
		}
		if (*chunknb < chunkpos + 1UL) {
			*chunknb = chunkpos + 1UL;
			g_hash_table_insert(chunk_nbs, res_contentid, chunknb);
		}

		g_free((gpointer)textdata);
	}
	chunk_nbs = g_hash_table_new_full(_sqlite3_result_hash, _sqlite3_result_equal, NULL, g_free);
	g_slist_foreach(*p_retrieved_values2, _process_chunk_nb, NULL);
	cbarg = g_slist_append(cbarg, chunk_nbs);

	/*********/
	/* CHUNK */
	/*********/

	p_retrieved_values3 = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_SIZE);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_HASH);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_ID);

	// Values for new table
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_old_chunkid); // chunk_id
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_content_path_from_previous); // content_path
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_zero_result); // flags
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunk_length); // chunk_length
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunk_pos); // chunk_pos
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_hash); // chunk_hash
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_null_result); // metadata

	// Convert table
	if ((ret = _retrieve_values(db, chunk_table, fields_names, p_retrieved_values3, &err))) {
		ret = _insert_values(db, old_chunk_table, *p_retrieved_values3, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values3);
	if (!ret)
		goto error;

	/***********/
	/* CONTENT */
	/***********/

	p_retrieved_values3 = g_malloc0(sizeof(GSList*));

	// Build fields to be retrieved from old table
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_SIZE);
	fields_names = g_slist_append(fields_names, M2V2_TABLE_FIELD_ID);

	// Make contenthash field
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_content_path); // content_path
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_zero_result); // flags
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_content_length); // content_length
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_chunknb); // chunk_nb
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_mdsys); // system_metadata
	new_fields_cb = g_slist_append(new_fields_cb, _cb_make_null_result); // metadata

   	// Convert table
	if ((ret = _retrieve_values(db, content_header_table, fields_names, p_retrieved_values3, &err))) {
		ret = _insert_values(db, old_content_table, *p_retrieved_values3, new_fields_cb, cbarg, &err);
	}
	CVDB_FREE_LISTS;
	CVDB_FREE_RETR_VAL(p_retrieved_values3);
	if (!ret)
		goto error;

error:
	CVDB_FREE_RETR_VAL(p_retrieved_values);
	CVDB_FREE_RETR_VAL(p_retrieved_values2);

	if (cbarg)
		g_slist_free(cbarg);

	if (chunk_nbs)
		g_hash_table_destroy(chunk_nbs);

	return err;
}

/**
 * Initializes descriptions of tables.
 * Must be called once, before use of m2_convert_* functions.
 */
void m2v2_init_db(void)
{
	// New tables
	_init_chunk_db();
	_init_content_db();
	_init_content_header_db();
	_init_alias_db();
	_init_properties_db();
	_init_snapshot_db();

	// Old tables
	_init_old_chunk_db();
	_init_old_properties_db();
	_init_old_content_db();
	_init_old_admin_db();

#ifdef M2V2_TEST_CONVERT
	// Converters
	_init_converters();
#endif
}

/**
 * Cleans the descriptions of tables.
 * Must be called once, when program terminates.
 */
void m2v2_clean_db(void)
{
	// New tables
	_free_table(chunk_table);
	_free_table(content_table);
	_free_table(content_header_table);
	_free_table(alias_table);
	_free_table(properties_table);
	_free_table(snapshot_table);

	// Old tables
	_free_table(old_chunk_table);
	_free_table(old_content_table);
	_free_table(old_properties_table);
	_free_table(old_admin_table);

#ifdef M2V2_TEST_CONVERT
	// Converters
	_free_converters();
#endif
}

#ifdef M2V2_TEST_CONVERT
/** This structure allows to describe how to convert from one field in a given table
 * to another field in another table. */
typedef struct s_m2v2_convert {
	t_m2v2_table_info *table_from;
	gchar *field_from;
	t_m2v2_table_info *table_to;
	gchar *field_to;
	gpointer (*cb_convert) (gpointer, gpointer);
	gpointer (*cb_reverse) (gpointer, gpointer);
} t_m2v2_convert;

/** Converters. */
GSList *converters = NULL;

gpointer _verbatim_converter(gpointer _value, gpointer _unused)
{
	(void) _unused;
	return _value;
}

gpointer _mdsys_to_policy_converter(gpointer value, gpointer arg)
{

}

static void _add_converter(
		t_m2v2_table_info *table_from, gchar *field_from,
		t_m2v2_table_info *table_to, gchar *field_to,
		gpointer (*cv) (gpointer, gpointer), gpointer (*rv) (gpointer, gpointer))
{
	t_m2v2_convert *c = g_malloc(sizeof(t_m2v2_convert));
	c->table_from = table_from;
	c->field_from = field_from;
	c->table_to = table_to;
	c->field_to = field_to;
	c->cb_convert = cv;
	c->cb_reverse = rv;
	converters = g_slist_append(converters, cv);
}

static void _init_converters()
{
	// chunk.chunk_id -> chunk_v2.id
	_add_converter(
			old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_ID,
			chunk_table, M2V2_TABLE_FIELD_ID,
			_verbatim_converter, _verbatim_converter);

	// chunk.content_path -> alias_v2.alias
	_add_converter(
				old_chunk_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,
				alias_table, M2V2_TABLE_FIELD_ALIAS,
				_verbatim_converter, _verbatim_converter);

	// chunk.flags -> NONE

	// chunk.chunk_length -> chunk_v2.size
	_add_converter(
					old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_LENGTH,
					chunk_table, M2V2_TABLE_FIELD_SIZE,
					_verbatim_converter, _verbatim_converter);

	// chunk.chunk_pos -> content_v2.position
	_add_converter(
					old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_POS,
					content_table, M2V2_TABLE_FIELD_POSITION,
					_verbatim_converter, _verbatim_converter);

	// chunk.chunk_hash -> content_v2.hash
	_add_converter(
					old_chunk_table, M2V2_TABLE_FIELD_OLD_CHUNK_HASH,
					content_table, M2V2_TABLE_FIELD_HASH,
					_verbatim_converter, _verbatim_converter);

	// chunk.metadata -> NONE

	// content.content_path -> alias_v2.alias
	_add_converter(
					old_content_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,
					alias_table, M2V2_TABLE_FIELD_ALIAS,
					_verbatim_converter, _verbatim_converter);

	// content.flags -> NONE

	// content.content_length -> content_header_v2.size
	_add_converter(
					old_content_table, M2V2_TABLE_FIELD_OLD_CONTENT_PATH,
					content_header_table, M2V2_TABLE_FIELD_SIZE,
					_verbatim_converter, _verbatim_converter);

	// content.chunk_nb -> NONE

	// content.system_metadata -> alias_v2.mdsys
	_add_converter(
					old_content_table, M2V2_TABLE_FIELD_OLD_SYS_METADATA,
					alias_table, M2V2_TABLE_FIELD_MDSYS,
					_verbatim_converter, _verbatim_converter);

	// content.metadata -> NONE

	// content.system_metadata (only policy) -> content_headers_v2.policy
	_add_converter(
					old_content_table, M2V2_TABLE_FIELD_OLD_SYS_METADATA,
					alias_table, M2V2_TABLE_FIELD_POLICY,
					_mdsys_to_policy_converter, NULL);
}
#endif

#ifdef M2V2_TEST

#include <grid_client.h>
#include <gs_internals.h>

// Test program
int main(int argc, char **argv)
{
	m2v2_init_db();
	GError *err = NULL;
	gchar **tokens;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar container_name[LIMIT_LENGTH_CONTAINERNAME];

	memset(ns_name, 0, LIMIT_LENGTH_NSNAME);
	memset(container_name, 0, LIMIT_LENGTH_CONTAINERNAME);

	if (argc > 1) {
		if (!(tokens = g_strsplit(argv[1], "/", 0)))
			goto error;
		if (g_strv_length(tokens) != 2) {
			fprintf(stderr, "Expected GridUrl NS/CONTAINER as argument\n");
			g_strfreev(tokens);
			goto error;
		}

		g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
		g_strlcpy(container_name, tokens[1], sizeof(container_name)-1);
		g_strfreev(tokens);
		
		container_id_t cid;
		memset(cid, 0, sizeof(cid));
		meta1_name2hash(cid, ns_name, container_name);
		gchar cid_str[65];
		memset(cid_str, 0, 65);
		buffer2str(cid, sizeof(cid), cid_str, sizeof(cid_str));
		gchar *dbpath = g_malloc0(100);

		gchar *cursor = dbpath;
		*cursor = '\0';
		cursor = g_stpcpy(cursor, "/DATA/AMONS/devamo/meta2-1/");
		strncpy(cursor, cid_str, 2);
		cursor = g_stpcpy(cursor + 2, "/");
		strncpy(cursor, cid_str + 2, 2);
		cursor = g_stpcpy(cursor + 2, "/");
		strncpy(cursor, cid_str, 65);

		if (dbpath[0] != '\0') {
			g_clear_error(&err);
			GTimer *timer = g_timer_new();
			if (m2_convert_db(dbpath, &err))
				fprintf(stdout, "Database [%s] converted successfully.\n", dbpath);
			else
				fprintf(stderr, "Error converting database [%s]: [%s]\n", dbpath, err ? err->message : "<no error set>");
			fprintf(stdout, "Conversion took %f seconds.\n", g_timer_elapsed(timer, NULL));
			g_timer_destroy(timer);
		} else {
			fprintf(stderr, "Could not find container [%s] in namespace [%s]\n", container_name, ns_name);
		}
		g_free(dbpath);
	}
error:
	if (err)
		g_error_free(err);
	m2v2_clean_db();
	return 0;
}
#endif /* M2V2_TEST */
