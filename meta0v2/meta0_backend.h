/**
 * @file meta0_backend.h
 */

#ifndef HC__META0_V2_BACKEND__H
# define HC__META0_V2_BACKEND__H 1

/**
 * @addtogroup meta0v2_backend
 * @{
 */

# ifndef META0_TYPE_NAME
#  define META0_TYPE_NAME "meta0"
# endif

# define META0_SCHEMA \
	"CREATE TABLE IF NOT EXISTS meta1 ( " \
		"prefix BLOB NOT NULL," \
		"addr TEXT NOT NULL," \
		"PRIMARY KEY(prefix,addr));" \
	"CREATE TABLE IF NOT EXISTS meta1_ref ( " \
		"addr TEXT NOT NULL," \
		"state TEXT NOT NULL," \
		"prefixes TEXT NOT NULL," \
		"PRIMARY KEY (addr));" \
	"INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"schema_version\",\"1.8\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.admin\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.meta1\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.meta1_ref\",\"1:0\");" \
	"VACUUM"

struct meta0_backend_s;
struct sqlx_repository_s;

enum m0v2_open_type_e
{
	M0V2_OPENBASE_LOCAL        = 0x000,
	M0V2_OPENBASE_MASTERONLY   = 0x001,
	M0V2_OPENBASE_SLAVEONLY    = 0x002,
	M0V2_OPENBASE_MASTERSLAVE  = 0x003,
};


/**
 * @param ns
 * @param id
 * @param repo
 * @return
 */
struct meta0_backend_s * meta0_backend_init(const gchar *ns, const gchar *id,
		struct sqlx_repository_s *repo);


void
meta0_backend_migrate(struct meta0_backend_s *m0);

/**
 * @param m0
 */
void meta0_backend_clean(struct meta0_backend_s *m0);


/**
 * @param m0
 * @return
 */
GError* meta0_backend_check(struct meta0_backend_s *m0);


/**
 * @param m0
 * @return
 */
struct sqlx_repository_s* meta0_backend_get_repository(
		struct meta0_backend_s *m0);


void meta0_backend_reload_requested(struct meta0_backend_s *m0);

/**
 * @param m0
 * @param replicas
 * @param urls
 * @return
 */
GError* meta0_backend_fill(struct meta0_backend_s *m0, guint replicas,
		gchar **urls);


/** Reloads the internal cache of the META0 backend
 * @param m0
 * @return
 */
GError * meta0_backend_reload(struct meta0_backend_s *m0);


/**
 * @param m0
 * @param result
 * @return
 */
GError* meta0_backend_get_all(struct meta0_backend_s *m0,
		GPtrArray **result);


/**
 * @param m0
 * @param prefix
 * @param urls
 * @return
 */
GError* meta0_backend_get_one(struct meta0_backend_s *m0,
		const guint8 *prefix, gchar ***urls);


/**
 * @param m0
 * @new_assign_prefixes
 * @return
 */
GError* meta0_backend_assign(struct meta0_backend_s *m0, 
	const GPtrArray *new_assign_prefixes, const GPtrArray *new_assign_meta1ref, const gboolean init);

/**
 * @param m0
 * @param result
 * @return
 */
GError* meta0_backend_get_all_meta1_ref(struct meta0_backend_s *m0, GPtrArray **result);

/**
 * @param m0
 * @param meta1_ref
 * @return
 */
GError* meta0_backend_destroy_meta1_ref(struct meta0_backend_s *m0, gchar *meta1);

/** @} */

#endif /* HC__META0_V2_BACKEND__H */
