/**
 * @file hc_url.h
 * Client URL library
 */

#ifndef __HC_URL__H__
# define __HC_URL__H__ 1

/**
 * @defgroup client_url
 * @ingroup client
 */

enum hc_url_field_e
{
	HCURL_NS=1,
	HCURL_NSPHYS,
	HCURL_NSVIRT,
	HCURL_REFERENCE,
	HCURL_PATH,
	HCURL_OPTIONS,
	HCURL_VERSION,
	HCURL_SNAPSHOT,

	HCURL_WHOLE,
	HCURL_HEXID,
	HCURL_SNAPORVERS, /**< Snapshot or version */
};

#define HCURL_LATEST_VERSION "LAST"
/**
 * Forward declaration
 */
struct hc_url_s;

/**
 * @param url
 * @return
 */
struct hc_url_s * hc_url_init(const char *url);

/**
 * Builds an empty URL
 * @return
 */
struct hc_url_s * hc_url_empty(void);

/**
 * @param u
 */
void hc_url_clean(struct hc_url_s *u);

/**
 * @param u
 * @return
 */
struct hc_url_s* hc_url_dup(struct hc_url_s *u);

/**
 * @param u
 * @param ignored
 */
void hc_url_gclean(gpointer u, gpointer ignored);

/**
 * @param u
 * @param f
 * @param v
 * @return u
 */
struct hc_url_s* hc_url_set(struct hc_url_s *u,
		enum hc_url_field_e f, const char *v);

/**
 * @param u
 * @param f
 * @return
 */
const char * hc_url_get(struct hc_url_s *u, enum hc_url_field_e f);

/**
 * @param u
 * @param f
 * @return
 */
int hc_url_has(struct hc_url_s *u, enum hc_url_field_e f);

/**
 * @param u
 * @return
 */
const guint8* hc_url_get_id(struct hc_url_s *u);

/**
 * Returns the options hash table.
 * @param u The url struct.
 * @return The options hash table.
 */
const GHashTable* hc_url_get_options(struct hc_url_s *u);

/**
 * Returns the value of the given option.
 * @param u The url struct.
 * @param option_name The name of the option.
 * @return The value of the given option.
 */
const gchar* hc_url_get_option_value(struct hc_url_s *u, const gchar *option_name);

/**
 * @param u
 * @return
 */
size_t hc_url_get_id_size(struct hc_url_s *u);

/**
 * @param u
 */
void hc_url_dump(struct hc_url_s *u);

/** @} */

#endif /* __HC_URL__H__ */
