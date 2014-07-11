#ifndef HONEYCOMB__RULES_ENGINE_H
# define HONEYCOMB__RULES_ENGINE_H 1
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/compression.h>

#ifdef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
#ifdef _POSIX_C_SOURCE
# undef _POSIX_C_SOURCE
#endif
#include <Python.h>

# define ATTR_NAME_MAX_LENGTH 64

# define ATTR_DOMAIN "user.grid"
# define ATTR_NAME_CHUNK_METADATA_COMPRESS "chunk.metadatacompress"
# define ATTR_NAME_CHUNK_COMPRESSED_SIZE "chunk.compressedsize"
# define ATTR_NAME_CHUNK_LAST_SCANNED_TIME "chunk.last_scanned_time"

#define SETERROR(e, m, ...) *(e) = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN), 0, m, ##__VA_ARGS__);
#define SETERRCODE(e, c, m, ...) *(e) = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN), c, m, ##__VA_ARGS__);

#define CHUNK_CRAWLER "chunk_crawler"

#define META2_TYPE_ID 2
#define CHUNK_TYPE_ID 3
#define CONTENT_TYPE_ID 4

extern struct rules_motor_env_s* motor_env;

/**************************************************
 *		C -> Python Part
 **************************************************/

extern gint rules_reload_time_interval;

/* the wrap structure for crawler data block */

struct crawler_sqlx_data_pack_s{
	gchar * sqlx_path;
	gchar * sqlx_seq;
	gchar * sqlx_cid;
	gchar * sqlx_type; 
	gchar * sqlx_url;
};


struct crawler_meta2_data_pack_s{
	gchar * container_path;
	gchar * container_id;
	gchar * meta2_url;
};

struct crawler_chunk_data_pack_s
{
         struct content_textinfo_s *content_info;
	 struct chunk_textinfo_s *chunk_info;
	 struct chunk_textinfo_extra_s *chunk_info_extra;
	 time_t atime;
	 time_t ctime;
	 time_t mtime;
	 const gchar *chunk_path;
};

struct motor_args{
	gpointer data_block;
	gint8 type_id;
	const gchar *ns_name;
	struct rules_motor_env_s** motor_env;
};

struct chunk_textinfo_extra_s{
/*	gchar *last_scanned_time;       !< The chunk last scanned time */
	gchar *compressedsize;          /*!< The size of compressed chunk */
	gchar *metadatacompress;        /*!< The compressed chunk metadata */
};

struct rules_motor_env_s{
	PyObject *py_module;
	PyObject *py_function;
};

/* initialize the motor environment */
void motor_env_init(void);

/* initialize the motor environment (multi-thread version)*/
void motor_env_init_v_multi_thread(void);

/* get and load the rules to python environment */
int
get_and_load_rules(struct rules_motor_env_s** motor_env, const gchar *ns_name);

/* update the rules */
int
update_rules(struct rules_motor_env_s** motor_env, const gchar *ns_name);

/* check reload condition */
gboolean
is_time_to_reload_rules(void);

/* pass the c datas to python for further process */
void
pass_to_motor(gpointer args);

/* pass the c datas to python for further process (multi-threads version) */
gpointer
pass_to_motor_v_multi_thread(gpointer args);


/* fill the sqlx datas from crawler into the wrap structure */
void sqlx_crawler_data_block_init(struct crawler_sqlx_data_pack_s *data_block,
     const gchar *sqlx_path, const gchar *sqlx_seq, const gchar *sqlx_cid,
	      const gchar *sqlx_type, char *sqlx_url);
void sqlx_crawler_data_block_free(struct crawler_sqlx_data_pack_s *data_block);

/* fill the meta2 datas from crawler into the wrap structure */
void meta2_crawler_data_block_init(struct crawler_meta2_data_pack_s *data_block,
		const char *container_path,
		char *meta2_url);
void meta2_crawler_data_block_free(struct crawler_meta2_data_pack_s *data_block);

/* fill the chunk datas from crawler into the wrap structure */
void chunk_crawler_data_block_init(struct crawler_chunk_data_pack_s *data_block,
		struct content_textinfo_s *content,
		struct chunk_textinfo_s *chunk,
		struct chunk_textinfo_extra_s *chunk_info_extra,
		struct stat *chunk_stat,
		const char *chunk_path);


/* initiate arguments for motor */
void
motor_args_init(struct motor_args *args,
		gpointer data_block,
                gint8 type_id,
		struct rules_motor_env_s** motor_env, 
		gchar *ns_name);

/* free the chunk extra textinfo structure */
void
chunk_textinfo_extra_free_content(struct chunk_textinfo_extra_s *ctie);

/* Read extra content info from chunk attributes */
gboolean get_extra_chunk_info(const char *pathname, GError ** error, struct chunk_textinfo_extra_s *chunk_textinfo_extra);

/* specific data convert for chunk_crawler */
void data_2_python(gpointer args, PyObject** pyobj_proxy);

/* free the arguments for each scan */
void free_motor_args(struct rules_motor_env_s* motor_env);

/* destroy the motor environment */
void destroy_motor_env(struct rules_motor_env_s** motor_env);

/* destroy the meta2-crawler datablock */
void destroy_crawler_meta2_data_block(struct crawler_meta2_data_pack_s *data_block);

/* destroy the motor environment (multi-thread version) */
void destroy_motor_env_v_multi_thread(struct rules_motor_env_s** motor_env);



/**************************************************
 *		Python -> C Part
 **************************************************/

/* test functions */

void
content_info_test(struct crawler_chunk_data_pack_s *c_struct);

/* compress a non-compressed chunk */
void
motor_compress_chunk(const char *chunk_path, const char *algo, const int bsize, gboolean preserve);

/* decompress a compressed chunk */
void
motor_decompress_chunk(const char *chunk_path, gboolean preserve);

/* get name space informations */
void
motor_list_namespace_services(const char *ns_name, GError **error);

/*  */
void motor_delete_content(const gchar * ns_name, const gchar * container_id,
		const gchar * content_name);

/*  */
void motor_log(const char *domain, int lvl, const char *msg);

/* move container to another meta2 */
int motor_move_container(const gchar * ns_name, const gchar * xcid);

/* Check content storage policy */
void motor_check_storage_policy(const gchar * ns_name, const gchar * container_id, const gchar * content_name);
/* end of test functions */


#endif /* HONEYCOMB__RULES_ENGINE_H */
