#ifndef SQLX__INTERNALS_H
# define SQLX__INTERNALS_H 1

/**
 * @defgroup sqliterepo_misc Misc. features
 * @ingroup sqliterepo
 * @{
 */

# include <sqlite3.h>

# include <metautils/lib/metautils.h>
# include <RowName.h>
# include <RowField.h>
# include <Row.h>
# include <Table.h>
# include <TableSequence.h>


# ifndef SQLX_MAX_COND
#  define SQLX_MAX_COND 64
# endif

# ifndef SQLX_MAX_BASES
#  define SQLX_MAX_BASES 2048
# endif

# ifndef SQLX_GRACE_DELAY_COOL
#  define SQLX_GRACE_DELAY_COOL 30L
# endif

# ifndef SQLX_GRACE_DELAY_HOT
#  define SQLX_GRACE_DELAY_HOT 300L
# endif

# ifndef SQLX_DELAY_ELECTION_REPLAY
#  define SQLX_DELAY_ELECTION_REPLAY 5L
# endif

// Size of buffer for reading dump file
#define SQLX_DUMP_BUFFER_SIZE 32768
// Size of chunks sent to client when doing chunked SQLX_DUMP
#define SQLX_DUMP_CHUNK_SIZE (8*1024*1024)

#define MALLOC_TRIM_SIZE (16*1024*1024)

#define MEMBER(D)   ((struct election_member_s*)(D))
#define MMANAGER(D) MEMBER(D)->manager
#define MKEY(D)     MEMBER(D)->key
#define MCFG(D)     MMANAGER(D)->config
#define MKEY_S(D)   hashstr_str(MEMBER(D)->key)

/**
 * @param C
 */
#define CONFIG_CHECK(C) do {\
	EXTRA_ASSERT((C) != NULL);\
	EXTRA_ASSERT((C)->get_local_url != NULL); \
	EXTRA_ASSERT((C)->get_peers != NULL); \
	EXTRA_ASSERT((C)->get_version != NULL); \
	EXTRA_ASSERT((C)->mode <= ELECTION_MODE_GROUP); \
} while (0)

/**
 * @param M
 */
#define MANAGER_CHECK(M) do {\
	EXTRA_ASSERT((M) != NULL);\
	EXTRA_ASSERT((M)->lock != NULL);\
	EXTRA_ASSERT((M)->lrutree_members != NULL);\
	CONFIG_CHECK((M)->config); \
} while (0)

/**
 * @param M
 */
#define MEMBER_CHECK(M) do {\
	EXTRA_ASSERT(MEMBER(M) != NULL);\
	EXTRA_ASSERT(MEMBER(M)->name != NULL);\
	EXTRA_ASSERT(MEMBER(M)->type != NULL);\
	EXTRA_ASSERT(MEMBER(M)->key != NULL);\
	MANAGER_CHECK(MMANAGER(M));\
} while (0)

struct sqlx_cache_s;

struct sqlx_repository_s
{
	gchar basedir[512];

	GHashTable *schemas;

	// Not owned
	struct sqlx_cache_s *cache;

	// Not owned
	struct election_manager_s *election_manager;

	// Hooks
	sqlx_file_locator_f locator;
	gpointer locator_data;

	sqlx_repo_close_hook close_callback;
	gpointer close_callback_data;

	sqlx_repo_open_hook open_callback;
	gpointer open_callback_data;

	sqlx_repo_change_hook change_callback;
	gpointer change_callback_data;

	// hash for the directory structure
	guint hash_width;
	guint hash_depth;

	// Limits for the base's holder
	guint bases_count;
	guint bases_max;

	enum sqlx_sync_mode_e sync_mode_solo;
	enum sqlx_sync_mode_e sync_mode_repli;

	gboolean flag_autocreate : 1;
	gboolean flag_autovacuum : 1;
	gboolean flag_delete_on : 1;

	gboolean running : 1;
};


/**
 * @param t0
 * @param t1
 * @return
 */
static inline gboolean
gtv_bigger(const GTimeVal *t0, const GTimeVal *t1)
{
	if (t0->tv_sec > t1->tv_sec)
		return TRUE;
	if (t0->tv_sec == t1->tv_sec && t0->tv_usec > t1->tv_usec)
		return TRUE;
	return FALSE;
}

/**
 * @param i1
 * @param i2
 * @return
 */
static inline int
gint64_cmp(gint64 i1, gint64 i2)
{
	return (i1==i2) ? 0 : (i1<i2 ? -1 : 1);
}

/**
 * @param p1
 * @param p2
 * @return
 */
static inline int
gint64_sort(gconstpointer p1, gconstpointer p2)
{
	return gint64_cmp(*(gint64*)p1, *(gint64*)p2);
}

/**
 * @param b
 * @param bs
 * @param u
 * @return
 */
static inline int
write_to_gba(const void *b, size_t bs, void *u)
{
	if (b && bs && u)
		g_byte_array_append((GByteArray*)u, b, bs);
	return 1;
}

/**
 * @param stmt
 * @param r
 * @param t
 */
void load_statement(sqlite3_stmt *stmt, Row_t *r, Table_t *t,
		gboolean noreal);

/**
 * @param op
 * @return
 */
const gchar * sqlite_op2str(int op);

/** @} */

#endif
