#ifndef GRID__META2_REQUEST_CONTEXT__H
# define GRID__META2_REQUEST_CONTEXT__H 1

/* Forward declaration */

struct gridd_filter_input_data_s;
struct gridd_filter_output_data_s;
struct gridd_filter_ctx_s;

/* ------------------------------------------------------------------ */

/*!
 *
 */
struct gridd_filter_ctx_s *meta2_filter_ctx_new(void);

/*!
 *
 */
void meta2_filter_ctx_clean(struct gridd_filter_ctx_s *ctx);

/*!
 *
 */
void meta2_filter_ctx_gclean(gpointer ctx, gpointer ignored);

/*!
 *
 */
struct hc_url_s * meta2_filter_ctx_get_url(const struct gridd_filter_ctx_s *ctx);

/*!
 *
 */
void meta2_filter_ctx_set_url(struct gridd_filter_ctx_s *ctx, struct hc_url_s *url);

/*!
 *
 */
void meta2_filter_ctx_add_param(struct gridd_filter_ctx_s *ctx, const char *k, const char *v);

/*!
 *
 */
const char * meta2_filter_ctx_get_param(const struct gridd_filter_ctx_s *ctx, const char *name);

/*!
 *
 */
struct meta2_backend_s * meta2_filter_ctx_get_backend(const struct gridd_filter_ctx_s *ctx);

/*!
 *
 */
void meta2_filter_ctx_set_backend(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *backend);

/*!
 *
 */
void meta2_filter_ctx_set_error(struct gridd_filter_ctx_s *ctx, GError *e);

/*!
 *
 */
GError * meta2_filter_ctx_get_error(const struct gridd_filter_ctx_s *ctx);

/*!
 *
 */
void meta2_filter_ctx_set_input_udata(const struct gridd_filter_ctx_s * ctx, gpointer udata, GDestroyNotify in_cleaner);

/*!
 *
 */
gpointer meta2_filter_ctx_get_input_udata(const struct gridd_filter_ctx_s * ctx);

#endif
