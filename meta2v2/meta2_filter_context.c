#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.reqctx"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <meta2v2/meta2_filter_context.h>

/* ------------------------------------------------------------------------ */

struct gridd_filter_input_data_s {
	struct hc_url_s *url;
	struct meta2_backend_s *backend;
	GHashTable *params;
	void *udata;
	GDestroyNotify cleaner;
};

struct gridd_filter_output_data_s {
	GError *error;
};


struct gridd_filter_ctx_s {
	struct gridd_filter_input_data_s *input_data;
	struct gridd_filter_output_data_s *output_data;
};

/* ------------------------------------------------------------------------ */

static void
_input_data_clean(struct gridd_filter_input_data_s *input_data)
{
	if(!input_data)
		return;

	if(NULL != input_data->url)
		hc_url_clean(input_data->url);

	if(NULL != input_data->params)
		g_hash_table_destroy(input_data->params);

	if(NULL != input_data->udata)
		input_data->cleaner(input_data->udata);


	g_free(input_data);
}

static void
_output_data_clean(struct gridd_filter_output_data_s *output_data)
{
	if(!output_data)
		return;

	g_free(output_data);
}

static void
_input_data_init(struct gridd_filter_ctx_s *ctx)
{
	if(!ctx)
		return;
	ctx->input_data = g_malloc0(sizeof(struct gridd_filter_input_data_s));
	ctx->input_data->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

}

static void
_output_data_init(struct gridd_filter_ctx_s *ctx)
{
	if(!ctx)
		return;
	ctx->output_data = g_malloc0(sizeof(struct gridd_filter_output_data_s));
	ctx->output_data->error = NULL;
}

/* ------------------------------------------------------------------------ */

struct gridd_filter_ctx_s *
meta2_filter_ctx_new(void)
{
	struct gridd_filter_ctx_s *r = NULL;
	r = g_malloc0(sizeof(struct gridd_filter_ctx_s));
	_input_data_init(r);
	_output_data_init(r);
	return r;
}

void
meta2_filter_ctx_clean(struct gridd_filter_ctx_s *ctx)
{
	if(!ctx)
		return;
	if(NULL != ctx->input_data)
		_input_data_clean(ctx->input_data);
	
	if(NULL != ctx->output_data)
		_output_data_clean(ctx->output_data);
	
	g_free(ctx);
}

void
meta2_filter_ctx_gclean(gpointer ctx, gpointer ignored)
{
	(void) ignored;
	meta2_filter_ctx_clean((struct gridd_filter_ctx_s *) ctx);
}

void
meta2_filter_ctx_set_url(struct gridd_filter_ctx_s *ctx, struct hc_url_s *url)
{
	if(!ctx || !ctx->input_data)
		return;
	ctx->input_data->url = url;
}

struct hc_url_s *
meta2_filter_ctx_get_url(const struct gridd_filter_ctx_s *ctx)
{
	if(!ctx || !ctx->input_data)
		return NULL;
	return ctx->input_data->url;
}

void
meta2_filter_ctx_add_param(struct gridd_filter_ctx_s *ctx, const char *k, const char *v)
{
	if(!ctx || !ctx->input_data || !ctx->input_data->params || !k || !v)
		return;

	g_hash_table_insert(ctx->input_data->params, g_strdup(k), g_strdup(v));
}

const char *
meta2_filter_ctx_get_param(const struct gridd_filter_ctx_s *ctx, const char *name)
{
	if(!ctx || !ctx->input_data || !ctx->input_data->params || !name)
		return NULL;
	return g_hash_table_lookup(ctx->input_data->params, name);
}

void
meta2_filter_ctx_set_backend(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *backend)
{
	if(!ctx || !ctx->input_data)
		return;
	ctx->input_data->backend = backend;
}

struct meta2_backend_s *
meta2_filter_ctx_get_backend(const struct gridd_filter_ctx_s *ctx)
{
	if(!ctx || !ctx->input_data)
		return NULL;
	return ctx->input_data->backend;
}

void
meta2_filter_ctx_set_error(struct gridd_filter_ctx_s *ctx, GError *e)
{
	if(!ctx || !ctx->output_data)
		return;
	if(NULL != ctx->output_data->error)
		g_clear_error(&(ctx->output_data->error));
	ctx->output_data->error = e;
}

GError *
meta2_filter_ctx_get_error(const struct gridd_filter_ctx_s *ctx)
{
	if(!ctx || !ctx->output_data) {
		GRID_DEBUG("uninitialized pointer : %p", ctx);
		return NULL;
	}
	if(NULL != ctx->output_data->error) {
		GRID_DEBUG("ctx error : %d, %s", ctx->output_data->error->code, ctx->output_data->error->message);
	} else {
		GRID_DEBUG("No error found in context");
	}
	return ctx->output_data->error;
}

gpointer
meta2_filter_ctx_get_input_udata(const struct gridd_filter_ctx_s * ctx)
{
	if(!ctx || !ctx->input_data)
		return NULL;
	return ctx->input_data->udata;
}

void
meta2_filter_ctx_set_input_udata(const struct gridd_filter_ctx_s *ctx,
		gpointer udata, GDestroyNotify in_cleaner)
{
	return meta2_filter_ctx_set_input_udata2(ctx, udata, in_cleaner, TRUE);
}

void
meta2_filter_ctx_set_input_udata2(const struct gridd_filter_ctx_s *ctx,
		gpointer udata, GDestroyNotify in_cleaner, gboolean call_cleaner)
{
	if (!ctx || !ctx->input_data || !udata)
		return;
	if (NULL != ctx->input_data->udata && call_cleaner)
		ctx->input_data->cleaner(ctx->input_data->udata);

	ctx->input_data->udata = udata;
	ctx->input_data->cleaner = in_cleaner;
}

