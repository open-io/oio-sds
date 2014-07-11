#ifndef __BROKEN_HOLDER_H__
# define __BROKEN_HOLDER_H__ 1

/**
 * @addtogroup gridcluster_backend
 * @{
 */

# ifndef BRKM1_PREFIX
#  define BRKM1_PREFIX "META1:"
# endif
# ifndef BRKM1_PATTERN
#  define BRKM1_PATTERN "META1:([^:]+):([^:]+)"
# endif
# ifndef BRKM2_PATTERN
#  define BRKM2_PATTERN "([^:]*):([^:]*):::"
# endif
# ifndef BRKCONTAINER_PATTERN_RM
#  define BRKCONTAINER_PATTERN_RM "([^:]*):([^:]*):([^:]*)"
# endif
# ifndef BRKCONTAINER_PATTERN_PUT
#  define BRKCONTAINER_PATTERN_PUT "([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)"
# endif
# ifndef BRKCONTAINER_PATTERN_FIX
#  define BRKCONTAINER_PATTERN_FIX "([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)"
# endif
# include <metautils/lib/metautils.h>
# include <cluster/conscience/conscience.h>

/**
 *
 */
struct broken_holder_s {
	struct conscience_s *conscience;
	GHashTable *ht_meta2;/**< Maps (addr_info_t*) to (broken_meta2_t*)*/
	GHashTable *ht_meta1;/**< Maps (addr_info_t*) to (broken_meta1_t*)*/
};

/**
 *
 */
typedef struct broken_content_s {
	time_t date_insertion;
	gint   counter;
	gchar  container_id[STRLEN_CONTAINERID];
	gchar  content_path[LIMIT_LENGTH_CONTENTPATH+1];
	gchar  cause[128+1];
} broken_content_t;

/**
 *
 */
typedef struct broken_meta2_s {
	time_t       date_insertion;
	gint         counter;
	addr_info_t  addr;
	gboolean     totally_broken;
	time_t       last_alert_stamp;
	GHashTable  *broken_containers;/**<Maps (gchar*) to (broken_content_t*)*/
} broken_meta2_t;

/**
 *
 */
typedef struct broken_meta1_s {
	time_t       date_insertion;
	gint64       counter;
	addr_info_t  addr;
	gchar        string [ sizeof(BRKM1_PREFIX) + STRLEN_ADDRINFO + 1 ];
} broken_meta1_t;

/* ------------------------------------------------------------------------- */

/**
 * @param conscience
 * @return
 */
struct broken_holder_s* conscience_create_broken_holder ( struct conscience_s *conscience );

/**
 * @param bh
 */
void conscience_destroy_broken_holder( struct broken_holder_s *bh );

/**
 * @param bh
 * @param err
 * @param element
 * @return
 */
void broken_holder_remove_element( struct broken_holder_s *bh,
	const gchar *element );

/**
 * @param bh
 * @param err
 * @param element
 * @return
 */
void broken_holder_add_element( struct broken_holder_s *bh,
	const gchar *element );

/**
 * @param bh
 */
void broken_holder_flush( struct broken_holder_s *bh );

/**
 * @param u
 * @param bm1
 */
typedef gboolean (*on_brk_meta1_f) (gpointer u, struct broken_meta1_s *bm1);

/**
 * @param u
 * @param bm2
 * @param bc
 */
typedef gboolean (*on_brk_content_f) (gpointer u, struct broken_meta2_s *bm2,
	struct broken_content_s *bc);

/**
 * @param bh
 * @param oldest
 * @param udata
 * @param m1
 * @param c
 * @return
 */
gboolean broken_holder_run_elements( struct broken_holder_s *bh, time_t oldest,
	gpointer udata, on_brk_meta1_f m1, on_brk_content_f c);

/**
 * @param m1
 * @return 
 */
gchar* broken_holder_write_meta1( struct broken_meta1_s *m1 );

/**
 * @param m22
 * @return 
 */
gchar* broken_holder_write_meta2( struct broken_meta2_s *m2 );

/**
 * @param m2
 * @param c
 * @return 
 */
gchar* broken_holder_write_content( struct broken_meta2_s *m2, struct broken_content_s *c );

/**
 * @param bh
 * @param element
 */
void broken_holder_fix_element(struct broken_holder_s *bh, const gchar *element);

/**
 * @param bh
 * @param element
 * @return
 */
gboolean broken_holder_check_element_format( struct broken_holder_s *bh, const gchar *element );

/** @} */

#endif /*__BROKEN_HOLDER_H__*/
