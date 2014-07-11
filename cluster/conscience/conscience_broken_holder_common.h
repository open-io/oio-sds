#ifndef __BROKEN_HOLDER_COMMON_H__
# define __BROKEN_HOLDER_COMMON_H__
# include <glib.h>

/**
 * @addtogroup gridcluster_backend
 * @{
 */

/**
 */
struct broken_fields_s
{
	const gchar *packed;
	const gchar *ns;
	gchar *ip;
	gint port;
	gchar *cid;
	gchar *content;
	gchar *cause;
};

/**
 * @param bh
 * @param bf
 */
void broken_holder_add_meta1(struct broken_holder_s * bh, struct broken_fields_s * bf);

/**
 * @param bh
 * @param bf
 */
void broken_holder_add_in_meta2(struct broken_holder_s * bh, struct broken_fields_s * bf);

/*removers*/

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_meta2( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_meta1( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_content( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_container( struct broken_holder_s *bh, struct broken_fields_s *bf );

/*fixers*/


/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_meta1(struct broken_holder_s * bh, struct broken_fields_s *bf);

/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf);

/**
 * @param bh
 * @param bf
 * @param brk_m2
 */
void broken_holder_fix_content(struct broken_holder_s *bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2);

/**
 * @param bh
 * @param bf
 * @param brk_m2
 */
void broken_holder_fix_container(struct broken_holder_s *bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2);

/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_in_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf);

/*destructors*/

/**
 * @param p
 */
void free_broken_m2(gpointer p);

/** @} */

#endif
