#ifndef _RAINX_REPOSITORY_H_
#define _RAINX_REPOSITORY_H_

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <mod_dav.h>

// TODO FIXME replace this by the APR equivalent
#include <openssl/md5.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>
#include <rawx-lib/src/compression.h>
#include <rainx/rainx_config.h>

#define RAWXLIST_SEPARATOR "|"
#define RAWXLIST_SEPARATOR2 ";"
#define MAX_REPLY_MESSAGE_SIZE 1024
#define INIT_REQ_STATUS -1

#define LOAD_HEADER(Set,Where,Name) __load_one_header(request, conf->headers_scheme, Name, &(resource->info-> Set . Where))

typedef int func0(int, int, int, const char*);
typedef char* func1(char**, char**, int, int, int, const char*);
typedef char** func2(char*, int, int, int, const char*);

struct req_params_store {
	const dav_resource* resource;

	apr_thread_t *thd_arr;
    apr_threadattr_t *thd_attr;

	char* service_address;

	char* data_to_send;
	int data_to_send_size;

	char* header;
	char* req_type;
	char* reply;
	apr_status_t req_status;
	apr_pool_t *pool;
};

/* context needed to identify a resource */
struct dav_resource_private {
	apr_pool_t *pool;        /* memory storage pool associated with request */
	request_rec *request;

	struct content_textinfo_s content;
	struct chunk_textinfo_s chunk;

	char *namespace; /* Namespace name, in case of VNS */

	int k; /* Number of data metachunks (from the policy) */
	int m; /* Number of coding metachunks (from the policy) */
	const char* algo; /* Name of the algorythm to apply (from the policy) */
	int metachunk_size; /* Calculated size of a metachunk */
	char** rawx_list; /* List of rawx services (i.e http://ip:port/DATA/NS/machine/volume/XX/XX/CID|...) must contain k + m addresses */

	int current_rawx; /* Index of the current rawx in the rawx list */
	int current_chunk_remaining; /* Number of bytes until the current chunk buffer is totally filled */

	char* response_chunk_list; /* The list (ip:port/chunk_id|stored_size|md5_digest;...) of actual metachunks stored on the rawx to put in the response header */
};

struct dav_stream {
	const dav_resource *r;
	apr_pool_t *p;
	int original_data_size; /* Size of the original data */
	char* original_data; /* Buffer where the entire received data is stored */
	char* original_data_chunk_start_ptr; /* Pointer to the beginning of the current chunk */
	char* original_data_chunk_end_ptr; /* Pointer to the end of the current chunk */
	int original_data_stored; /* Amount of data currently stored in 'original_data' */

	MD5_CTX md5_ctx;
};

#endif /*  _RAINX_REPOSITORY_H_ */
