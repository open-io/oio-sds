#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>


static void
_append_bean_to_list(GSList **plist, gpointer bean)
{
	*plist = g_slist_prepend(*plist, bean);
}

struct test_ctx_s
{
	struct hc_url_s *url;
	struct grid_lbpool_s *lbpool;
	struct storage_policy_s *stgpol;
	struct namespace_info_s *nsinfo;
	GSList *beans;
	struct check_args_s check_args;
};

// Mangles the hash of the first CHUNK
static void
pourrify_chunk_hash(struct test_ctx_s *ctx)
{
	ctx->beans = metautils_gslist_shuffle(ctx->beans);
	for (GSList *beans = ctx->beans; beans ;beans=beans->next) {
		gpointer bean = beans->data;
		if (DESCR(bean) == &descr_struct_CHUNKS) {
			GByteArray *hash = CHUNKS_get_hash(bean);
			metautils_gba_randomize(hash);
			return;
		}
	}
}

// Mangles the position of the first CONTENT
static void
pourrify_chunk_position(struct test_ctx_s *ctx)
{
	ctx->beans = metautils_gslist_shuffle(ctx->beans);
	for (GSList *beans = ctx->beans; beans ;beans=beans->next) {
		gpointer bean = beans->data;
		if (DESCR(bean) == &descr_struct_CONTENTS) {
			GString *pos = CONTENTS_get_position(bean);
			g_string_prepend(pos, "1");
			g_string_append(pos, "0");
			return;
		}
	}
}

static void
init_text_context(struct test_ctx_s *ctx, const gchar *polname)
{
	GError *err = NULL;

	memset(ctx, 0, sizeof(struct test_ctx_s));

	ctx->lbpool = grid_lbpool_create("NS");
	g_assert(ctx->lbpool != NULL);

	ctx->nsinfo = get_namespace_info("NS", &err);
	g_assert_no_error(err);
	g_assert(ctx->nsinfo != NULL);

	ctx->stgpol = storage_policy_init(ctx->nsinfo, polname);
	g_assert(ctx->stgpol != NULL);

	ctx->url = hc_url_init("/NS/JFS/content");
	g_assert(ctx->url != NULL);

	grid_lbpool_reconfigure(ctx->lbpool, ctx->nsinfo);

	err = gridcluster_reload_lbpool(ctx->lbpool);
	g_assert_no_error(err);

	err = m2_generate_beans(ctx->url, 65536, 30000, ctx->stgpol,
			grid_lbpool_get_iterator(ctx->lbpool, "rawx"),
			(m2_onbean_cb) _append_bean_to_list, &(ctx->beans));
	g_assert_no_error(err);

	ctx->check_args.lbpool = ctx->lbpool;
	ctx->check_args.ns_info = ctx->nsinfo;
}

static void
clean_test_context(struct test_ctx_s *ctx)
{
	_bean_cleanl2(ctx->beans);
	hc_url_clean(ctx->url);
	storage_policy_clean(ctx->stgpol);
	namespace_info_free(ctx->nsinfo);
	grid_lbpool_destroy(ctx->lbpool);
	memset(ctx, 0, sizeof(struct test_ctx_s));
}

static void
perform_test_on_context(struct test_ctx_s *ctx, gboolean ok)
{
	GError *err = NULL;
	struct m2v2_check_s *check;

	check = m2v2_check_create(ctx->url, &ctx->check_args);
	m2v2_check_feed_with_bean_list(check, ctx->beans);
	err = m2v2_check_consistency(check);
	m2v2_check_destroy(check);

	g_assert_no_error(err);
	if (ok) {
		g_assert(check->flaws->len == 0);
	}
	else {
		g_assert(check->flaws->len != 0);
	}
}

static void
test_valid_dupli(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "FIVECOPIES");
	perform_test_on_context(&ctx, TRUE);
	clean_test_context(&ctx);
}

static void
test_valid_rain(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "RAIN");
	perform_test_on_context(&ctx, TRUE);
	clean_test_context(&ctx);
}

static void
test_invalid_dupli_hash(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "FIVECOPIES");
	pourrify_chunk_hash(&ctx);
	perform_test_on_context(&ctx, FALSE);
	clean_test_context(&ctx);
}

static void
test_invalid_dupli_position(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "FIVECOPIES");
	pourrify_chunk_position(&ctx);
	perform_test_on_context(&ctx, FALSE);
	clean_test_context(&ctx);
}

static void
test_invalid_rain_hash(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "RAIN");
	pourrify_chunk_hash(&ctx);
	// XXX Impossible to check the hash is invalid, just with the beans
	perform_test_on_context(&ctx, TRUE);
	clean_test_context(&ctx);
}

static void
test_invalid_rain_position(void)
{
	struct test_ctx_s ctx;

	g_debug("*** %s ***", __FUNCTION__);
	init_text_context(&ctx, "RAIN");
	pourrify_chunk_position(&ctx);
	perform_test_on_context(&ctx, FALSE);
	clean_test_context(&ctx);
}

int
main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);

	g_test_init (&argc, &argv, NULL);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE2);

	// DUPLI
	g_test_add_func("/meta2v2/utils/check/valid/dupli",
			test_valid_dupli);
	g_test_add_func("/meta2v2/utils/check/invalid/dupli/hash",
			test_invalid_dupli_hash);
	g_test_add_func("/meta2v2/utils/check/invalid/dupli/position",
			test_invalid_dupli_position);

	// RAIN
	g_test_add_func("/meta2v2/utils/check/valid/rain",
			test_valid_rain);
	g_test_add_func("/meta2v2/utils/check/invalid/rain/hash",
			test_invalid_rain_hash);
	g_test_add_func("/meta2v2/utils/check/invalid/rain/position",
			test_invalid_rain_position);

	return g_test_run();
}

