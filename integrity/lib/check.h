#ifndef CHECK_H
#define CHECK_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <grid_client.h>

#define META1_TIMEOUT 60 * 60 * 1000
#define META2_TIMEOUT 60 * 60 * 1000

typedef struct _check_result {
	gboolean check_ok;
	GString *msg;
	gpointer udata;
} check_result_t;

/**
 * Frees the m2v1 list.
 */
void free_m2v1_list();

/**
 * Returns whether the provided meta2 address is known as m2v1.
 * @param meta2 the address to test
 * @return TRUE if meta2 is a m2v1 address, FALSE otherwise
 */
gboolean is_m2v1(const gchar *meta2);

/**
 * Adds the meta2 address to the list of meta2v1 addresses.
 * Make sure that the address is not already stored in the list by calling
 * {@link is_m2v1} beforehand.
 * @param new_m2v1 the meta2 address to be added to the list
 */
void add_to_m2v1_list(const gchar *new_m2v1);

#define CHECK_ARG_POINTER(P,E) \
	do { \
		if (P == NULL) { \
			GSETERROR(E, "Argument "#P" can't be NULL"); \
			return FALSE; \
		} \
	} while(0);

#define CHECK_ARG_VALID_DIR(D,E) \
	do { \
		struct stat file_stat; \
		memset(&file_stat, 0, sizeof(struct stat)); \
		if (0 != stat(D, &file_stat) || !S_ISDIR(file_stat.st_mode)) { \
			GSETERROR(E, "Argument "#D" is not a valid directory : %s", strerror(errno)); \
			return FALSE; \
		} \
	} while(0);

#define CHECK_ARG_VALID_FILE(F,E) \
	do { \
		struct stat file_stat; \
		memset(&file_stat, 0, sizeof(struct stat)); \
		if (0 != stat(F, &file_stat) || !S_ISREG(file_stat.st_mode)) { \
			GSETERROR(E, "Argument "#F" is not a valid file : %s", strerror(errno)); \
			return FALSE; \
		} \
	} while(0);

// P: pointer  E: GError**  EMSG: error msg
#define CHECK_INFO(P,E,EMSG) \
	do { \
		if (!P) { \
			if (E) \
				*E = NEWERROR(EINVAL, EMSG); \
			return FALSE; \
		} \
	} while (0);

struct meta2_ctx_s {
	gchar *ns;
	gs_grid_storage_t *hc;
	struct gs_container_location_s *loc;
	struct metacnx_ctx_s *m2_cnx;
	struct meta2_raw_content_s *content;
	struct storage_policy_s *sp;
	gboolean check_only;
	gboolean modified;
	gboolean fail;
};

typedef struct _check_info_t {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar rawx_str_addr[STRLEN_ADDRINFO];
	gchar rawx_vol[LIMIT_LENGTH_VOLUMENAME];
	gchar source_path[LIMIT_LENGTH_VOLUMENAME + STRLEN_CHUNKID];
	struct chunk_textinfo_s *ck_info;
	struct content_textinfo_s *ct_info;
	struct chunk_textinfo_extra_s *ck_extra;
	GHashTable *options;
} check_info_t;

struct meta2_ctx_s *get_meta2_ctx(const gchar *ns_name, const gchar *container_hexid,
		const gchar *content_name, gboolean check_only, GError **error);

GError* find_storage_policy_and_friend_chunks_full(const gchar* meta2,
		struct hc_url_s *url, check_info_t *check_info,
		GSList **chunk_ids, struct meta2_raw_content_s **p_raw_content);

GError* find_storage_policy_and_friend_chunks(const gchar* meta2,
		struct hc_url_s *url, check_info_t *check_info,
		GSList **chunk_ids);

GError* generate_raw_chunk(check_info_t *info,
		struct meta2_raw_chunk_s *p_raw_chunk);

/**
 * Creates a new check_result_t.
 * @return a new check_result_t
 */
check_result_t *check_result_new();

/**
 * Clears all memory allocated for res.
 * @param res check result to be freed
 * @param free_udata callback aiming to free res->udata
 */
void check_result_clear(check_result_t **p_res, void (*free_udata(gpointer)));

/**
 * Fills the check_result structure: sets check_ok to TRUE and copies the
 * given message into msg. If res is NULL, does nothing.
 * @param res check result to be completed
 * @param format format string
 */
void check_result_append_msg(check_result_t *res, const gchar *format, ...);

// OPTIONS
#define CHECK_OPTION_DRYRUN "CHECK_OPTION_DRYRUN"

/**
 * Creates a new option hash table.
 * @return a new hash table
 */
GHashTable *check_option_new();

/**
 * Destroys an option hash table.
 * @param options table to be destroyed
 */
void check_option_destroy(GHashTable *options);

/**
 * Return the integer value of an option, or G_MAXINT if no such option can be
 * found.
 * @param info check info
 * @param option_name option name
 * @return integer value of the option or G_MAXINT
 */
gint check_option_get_int(GHashTable *options, const gchar *option_name);

/**
 * Return the boolean value of an option, or FALSE if no such option can be
 * found.
 * @param info check info
 * @param option_name option name
 * @return boolean value of the option, FALSE if option unknown
 */
gboolean check_option_get_bool(GHashTable *options, const gchar *option_name);

/**
 * Return the string value of an option, NULL if the option is unknown.
 * @param info check info
 * @param option_name option name
 * @return string value of the option or NULL
 */
gchar *check_option_get_str(GHashTable *options, const gchar *option_name);

/**
 * Set integer option.
 * @param info check info
 * @param oname option name
 * @param ovalue option value (gint)
 */
void check_option_set_int(GHashTable *options, const gchar *oname, gint ovalue);

/**
 * Set boolean option.
 * @param info check info
 * @param oname option name
 * @param ovalue option value (gboolean)
 */
void check_option_set_bool(GHashTable *options,
		const gchar *oname, gboolean ovalue);

/**
 * Set string option.
 * @param info check info
 * @param oname option name
 * @param ovalue option value (gchar*)
 */
void check_option_set_str(GHashTable *options,
		const gchar *oname, const gchar *ovalue);

#endif /* CHECK_H */
