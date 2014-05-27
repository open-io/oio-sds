#ifndef _RAWX_BUCKET_H_
#define _RAWX_BUCKET_H_

#include <apr.h>
#include <apr_buckets.h>

struct apr_bucket_type_t chunk_bucket_type;

void chunk_bucket_destroy(void *d);

void chunk_bucket_free_noop(void *d);

apr_status_t chunk_bucket_read(apr_bucket *b, const char **str, apr_size_t *len, apr_read_type_e block);

apr_status_t chunk_bucket_split(apr_bucket *e, apr_size_t point);

apr_status_t chunk_bucket_copy(apr_bucket *e, apr_bucket **c);

#endif /*  _RAWX_BUCKET_H_ */
