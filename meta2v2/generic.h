#ifndef GENERIC_H
# define GENERIC_H 1
# include <glib.h>
# include <sqlite3.h>

# define BEAN_FLAG_DIRTY     0x01
# define BEAN_FLAG_TRANSIENT 0x02

#ifndef M2_SQLITE_GERROR
# define M2_SQLITE_GERROR(db, RC) g_error_new(GQ(), (RC), "(%d) %s", (RC), db?sqlite3_errmsg(db):"-")
#endif

#define HDR(B)            ((struct bean_header_s*)(B))
#define DESCR(B)          (HDR(B)->descr)
#define DESCR_FIELD(B,i)  (DESCR(B)->fields + i)
#define FIELD(B,i)        (((guint8*)(B)) + DESCR(B)->offset_fields + DESCR_FIELD(B,i)->offset)
#define GSTR(pf)          (*((GString**)pf))
#define GBA(pf)           (*((GByteArray**)pf))

struct field_descriptor_s;
struct bean_decriptor_s;
struct fk_descriptor_s;

typedef void (*on_bean_f) (gpointer u, gpointer bean);

/** PRIVATE, DON'T TOUCH UNLESS YOU KNOW WHAT YOU ARE DOING */
struct bean_header_s
{
	guint32 flags;
	guint64 fields; /*!< the bit at position i means that the fields at
					  position i is set (and thus not NULL) */
	const struct bean_descriptor_s *descr;
};

struct field_descriptor_s
{
	const gchar *name;
	const guint position;
	const long offset;
	const gboolean mandatory;
	const enum {FT_BOOL, FT_INT, FT_REAL, FT_TEXT, FT_BLOB} type;
	const gboolean pk;
};

struct bean_descriptor_s
{
	const gchar *name;
	const gchar *c_name;
	const gchar *sql_name;
	const gchar *sql_select;
	const gchar *sql_count;
	const gchar *sql_replace;
	const gchar *sql_update;
	const long offset_fields;
	const long struct_size;
	const guint count_fields;
	const struct field_descriptor_s *fields;
	const struct fk_descriptor_s *fk;
	gchar **fk_names;
	const gint order;
};

struct fk_field_s
{
	gint i;
	const gchar *name;
};

struct fk_descriptor_s
{
	/* the name making sense for the  */
	const gchar *logical_name;

	/* a unique name as registered in the DB */
	const gchar *name;

	const struct bean_descriptor_s *src;
	struct fk_field_s *src_fields;

	const struct bean_descriptor_s *dst;
	struct fk_field_s *dst_fields;
};

/**
 * @param bean
 */
void _bean_clean(gpointer bean);

/**
 * @param beans
 */
void _bean_cleanv(gpointer *beanv);

/**
 * @param v
 */
void _bean_cleanv2(GPtrArray *v);

/**
 * @param v
 */
void _bean_cleanl2(GSList *v);

/**
 * @param descr
 * @param db
 * @param bean
 * @return
 */
GError* _db_save_bean(sqlite3 *db, gpointer bean);

/**
 * @param db
 * @param list
 * @return
 */
GError* _db_save_beans_list(sqlite3 *db, GSList *list);

/**
 * @param db
 * @param array
 * @return
 */
GError* _db_save_beans_array(sqlite3 *db, GPtrArray *array);

/**
 * @param db
 * @param bean
 * @return
 */
GError* _db_delete_bean(sqlite3 *db, gpointer bean);

GError* _db_delete(const struct bean_descriptor_s *descr, sqlite3 *db,
		const gchar *clause, GVariant **params);

/**
 * Fills 'result' with beans described by 'descr', filtered with
 * the 'clause' and its parameters.
 */
GError* _db_get_bean(const struct bean_descriptor_s *descr,
		sqlite3 *db, const gchar *clause, GVariant **params,
		on_bean_f cb, gpointer u);

GError* _db_count_bean(const struct bean_descriptor_s *descr,
		sqlite3 *db, const gchar *clause, GVariant **params,
		gint64 *pcount);

/**
 * Finds the FK descriptor, then calls _db_get_FK()
 * @param bean
 * @param name
 * @param db
 * @param cb
 * @param u
 * @return
 */
GError* _db_get_FK_by_name(gpointer bean, const gchar *name,
		sqlite3 *db, on_bean_f cb, gpointer u);

GError* _db_count_FK_by_name(gpointer bean, const gchar *name,
		sqlite3 *db, gint64 *pcount);

/**
 * @param bean
 * @param name
 * @param db
 * @param result
 * @return
 */
GError* _db_get_FK_by_name_buffered(gpointer bean, const gchar *name,
		sqlite3 *db, GPtrArray *result);

/**
 * @param gstr can be NULL
 * @param bean
 * @return
 */
GString* _bean_debug(GString *gstr, gpointer bean);

/**
 * @param bean
 * @param avoid_pk
 */
void _bean_randomize(gpointer bean, gboolean avoid_pk);

/**
 * Returns a newly allocated blank bean of the goven type
 * @param descr
 * @return
 */
gpointer _bean_create(const struct bean_descriptor_s *descr);

/**
 * @param bean
 * @return
 */
const gchar * _bean_get_typename(gpointer bean);

/**
 * @param bean
 * @return
 */
gchar ** _bean_get_FK_names(gpointer bean);

/**
 * @param bean
 * @param fkname
 * @return
 */
gpointer _bean_create_child(gpointer bean, const gchar *fkname);

/**
 * Duplicates 'bean' and returns it
 *
 * @param bean
 * @return
 */
gpointer _bean_dup(gpointer bean);

/**
 * @param bean
 * @param pos
 * @param pv
 */
void _bean_set_field_value(gpointer bean, guint pos, gpointer pv);

/**
 * Appends the bean into 'gpa'.
 * @param gpa a pointer to a GPtrArray
 * @param bean a valid bean to be managed
 */
void _bean_buffer_cb(gpointer gpa, gpointer bean);

#define _bean_has_field(bean,pos) (HDR(bean)->fields & (1<<(pos)))
#define _bean_set_field(bean,pos) (HDR(bean)->fields |= (1<<(pos)))
#define _bean_del_field(bean,pos) (HDR(bean)->fields &= ~(1<<(pos)))

gsize SHA256_randomized_buffer(guint8 *d, gsize dlen);

gsize SHA256_randomized_string(gchar *d, gsize dlen);

GVariant* _gba_to_gvariant(GByteArray *gba);

#endif /* GENERIC_H */
