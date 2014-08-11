#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <glib.h>

#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

struct on_bean_ctx_s *
_on_bean_ctx_init(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct on_bean_ctx_s * obc = g_malloc0(sizeof(struct on_bean_ctx_s));
	obc->l = NULL;
	obc->first = TRUE;
	obc->ctx = ctx;
	obc->reply = reply;
	return obc;
}

void
_on_bean_ctx_send_list(struct on_bean_ctx_s *obc, gboolean final)
{
	/* marshall the list, send and clean it */
#ifndef USE_KAFKA
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(obc->ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(obc->ctx);
	struct event_config_s * evt_config = meta2_backend_get_event_config(m2b,
			hc_url_get(url, HCURL_NS));
#endif

	if (NULL != obc->l) {
		obc->reply->add_body(bean_sequence_marshall(obc->l));
#ifdef USE_KAFKA
		if (1) {
#else
		if (event_is_enabled(evt_config)) {
#endif
			/* beans will be clean by context */
			if(obc->first) {
				obc->first = FALSE;
				meta2_filter_ctx_set_input_udata(obc->ctx, obc->l,
						(GDestroyNotify)_bean_cleanl2);
			} else {
				meta2_filter_ctx_set_input_udata2(obc->ctx,
						g_slist_concat(obc->l,
							(GSList*)meta2_filter_ctx_get_input_udata(obc->ctx)),
							(GDestroyNotify) _bean_cleanl2, FALSE);
			}
		} else {
			_bean_cleanl2(obc->l);
		}
	}
	if(final)
		obc->reply->send_reply(200, "OK");
	else
		obc->reply->send_reply(206, "CONTINUE");
	obc->l = NULL;
}

void
_on_bean_ctx_clean(struct on_bean_ctx_s *obc)
{
	if(!obc)
		return;

#ifndef USE_KAFKA
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(obc->ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(obc->ctx);
	struct event_config_s * evt_config = meta2_backend_get_event_config(m2b,
			hc_url_get(url, HCURL_NS));
#endif

	if (obc->l) {
#ifndef USE_KAFKA
		if (!event_is_enabled(evt_config))
#endif
			_bean_cleanl2(obc->l);
		obc->l = NULL;
	}
	obc->reply = NULL;
	obc->ctx = NULL;
	g_free(obc);
}

int
meta2_filter_fill_subject(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct hc_url_s *url;

	TRACE_FILTER();
	url = meta2_filter_ctx_get_url(ctx);
	if (hc_url_has(url, HCURL_REFERENCE))
		reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE),
				hc_url_get(url, HCURL_HEXID));
	else
		reply->subject("%s|%s", hc_url_get(url, HCURL_NS),
				hc_url_get(url, HCURL_HEXID));
	return FILTER_OK;
}

#define FILL_URL_FIELD(K, F) do { \
	tmp = meta2_filter_ctx_get_param(ctx, K); \
	if(NULL != tmp) { \
		hc_url_set(url, F, tmp); \
		tmp = NULL; \
	} \
} while(0)

int
meta2_filter_pack_url(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct hc_url_s *url = NULL;
	const char *tmp = NULL;
	char *hexid = NULL;

	TRACE_FILTER();
	(void) reply;

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		GRID_DEBUG("URL NOT FOUND in CONTEXT, create it");
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}

	GRID_DEBUG("HEXID : %s", hc_url_get(url, HCURL_HEXID));
	if(hc_url_has(url, HCURL_HEXID)) {
		hexid = g_strdup(hc_url_get(url, HCURL_HEXID));
	}

	FILL_URL_FIELD(M2V1_KEY_VIRTUAL_NAMESPACE, HCURL_NS);
	FILL_URL_FIELD(M2V1_KEY_REF, HCURL_REFERENCE);
	FILL_URL_FIELD(M2V1_KEY_REFID, HCURL_HEXID);
	FILL_URL_FIELD(M2V1_KEY_PATH, HCURL_PATH);

	if(!hc_url_has(url, HCURL_NS))  {
		const struct meta2_backend_s *backend = meta2_filter_ctx_get_backend(ctx);
		url = hc_url_set(url, HCURL_NS, backend->ns_name);
	}

	if(NULL != hexid) {
		hc_url_set(url, HCURL_HEXID, hexid);
		g_free(hexid);
	}

	// Hack in case there was "?version=XXX" in M2V1_KEY_PATH
	struct hc_url_s *url2 = hc_url_init(hc_url_get(url, HCURL_WHOLE));
	hc_url_set(url, HCURL_PATH, hc_url_get(url2, HCURL_PATH));
	if (hc_url_has(url2, HCURL_SNAPORVERS)) {
		hc_url_set(url, HCURL_SNAPORVERS, hc_url_get(url2, HCURL_SNAPORVERS));
	}
	hc_url_clean(url2);

	return FILTER_OK;
}

int
meta2_filter_fail_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;

	TRACE_FILTER();
	e = meta2_filter_ctx_get_error(ctx);
	if(NULL != e) {
		GRID_DEBUG("Error defined by KO execution filter, return it");
		reply->send_error(0, e);
	} else {
		GRID_DEBUG("Error not defined by KO execution filter, return 500");
		reply->send_error(0, NEWERROR(500,
					"Request execution failed : No error"));
	}

	return FILTER_OK;
}

int
meta2_filter_success_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	(void) ctx;
	reply->send_reply(200, "OK");
	return FILTER_OK;
}

int
meta2_filter_not_implemented_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	(void) ctx;
	reply->send_reply(501, "NOT IMPLEMENTED");
	return FILTER_OK;
}
