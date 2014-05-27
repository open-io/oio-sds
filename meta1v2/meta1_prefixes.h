/**
 * @file meta1_prefixes.h
 */

#ifndef GRID__META1_PREFIXES__H
# define GRID__META1_PREFIXES__H 1

/**
 * @addtogroup meta1v2_prefixes 
 * @{
 */

struct sqlx_repository_s;

struct meta1_prefixes_set_s;

/** Constructor
 * @return
 */
struct meta1_prefixes_set_s* meta1_prefixes_init(void);

/** Load / Reload function.
 * @param m1ps
 * @param ns_name
 * @param local_url
 * @return NULL in case of success or the error that occured
 */
GError* meta1_prefixes_load(struct meta1_prefixes_set_s *m1ps,
		const gchar *ns_name,
		const gchar *local_url,
		GArray **updated_prefixes);

/**
 * @param m1ps
 * @param local_url
 * @return NULL in case of success or the error that occured
 */
GError* meta1_prefixes_manage_all(struct meta1_prefixes_set_s *m1ps,
		const gchar *local_url);

/** Destructor
 * @param m1ps destructor
 */
void meta1_prefixes_clean(struct meta1_prefixes_set_s *m1ps);

/**
 * Thread-safe / reentrant
 *
 * @param m1ps
 * @param bytes
 * @return
 */
gboolean meta1_prefixes_is_managed(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);

/**
 * Thread-safe / reentrant
 *
 * @param m1ps
 * @param bytes
 * @return
 */
gchar ** meta1_prefixes_get_peers(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes);


/**
 * @param m1ps
 * @return
 */
gchar** meta1_prefixes_get_all(struct meta1_prefixes_set_s *m1ps);

guint8* meta1_prefixes_get_cache(struct meta1_prefixes_set_s *m1ps);

/** @} */

#endif
