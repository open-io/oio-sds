#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

static gboolean flag_reuse = FALSE;
static gboolean flag_flood = FALSE;
static gint64 max_packets = 0;
static gint nb_threads = 50;
static gchar ns_name[LIMIT_LENGTH_NSNAME];
static GArray *addresses = NULL;

static const gchar*
main_get_usage(void)
{
	return "IP:PORT";
}

static void
main_set_defaults(void)
{
	addresses = g_array_sized_new(TRUE, TRUE, sizeof(addr_info_t), 16);
	memset(ns_name, 0, sizeof(ns_name));
	GRID_DEBUG("Defaults set!");
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ "Flood",   OT_BOOL, {.b=&flag_flood},
			"Only one address is expected but several threads are started, sending requests without any pause."},
		{ "Threads", OT_INT,  {.i=&nb_threads},
			"Number of concurrent PING threads. Ignored when Flood disabled."},
		{ "MaxReq",  OT_INT64, {.i64=&max_packets},
			"How many requests attempts will be made in each thread"},
		{ "CnxReuse", OT_BOOL, {.b=&flag_reuse},
			"If enabled, each connection won't be closed after each request attempt."},
		{ NULL, 0, {.b=0}, NULL }
	};
	return options;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (addresses)
		g_array_free(addresses, TRUE);
	addresses = NULL;
	GRID_DEBUG("Finished!");
}

static gboolean
_config_single_address(const gchar *arg)
{
	addr_info_t ai;
	GError *err = NULL;
	gchar str_addr[STRLEN_ADDRINFO];

	memset(&ai, 0, sizeof(ai));

	if (!l4_address_init_with_url(&ai, arg, &err)) {
		GRID_ERROR("Invalid address '%s' : %s", arg, err->message);
		g_error_free(err);
		return FALSE;
	}

	g_array_append_vals(addresses, &ai, 1);
	addr_info_to_string(&ai, str_addr, sizeof(str_addr));
	GRID_DEBUG("Configured '%s'", str_addr);
	return TRUE;
}

static gboolean
_config_single_service(const gchar *arg)
{
	gchar **strv = g_strsplit(arg, "|", 4);

	if (g_strv_length(strv) < 3) {
		GRID_ERROR("Invalid service description [%s]", arg);
		g_strfreev(strv);
		return FALSE;
	}
	if (!_config_single_address(strv[2])) {
		g_strfreev(strv);
		return FALSE;
	}

	g_free(strv);
	return TRUE;
}

static gboolean
main_configure(int argc, char **args)
{
	int i;

	if (flag_flood) {
		if (nb_threads <= 0) {
			GRID_ERROR("Invalid number of threads [%d]", nb_threads);
			return FALSE;
		}
	}

	if (argc < 1) {
		GRID_ERROR("At least one argument expected");
		return FALSE;
	}
	
	if (flag_flood) {
		
		if (argc != 1) {
			GRID_ERROR("Flood option is not compatible with multiple addresses");
			return FALSE;
		}
		for (i=0; i < nb_threads ; i++) {
			gchar *arg = args[0];

			if (strchr(arg, '|')) {
				if (!_config_single_service(arg))
					return FALSE;
			}
			else {
				if (!_config_single_address(arg))
					return FALSE;
			}
		}
	}
	else {
		for (i=0; i<argc ;i++) {
			gchar *arg = args[i];

			if (strchr(arg, '|')) {
				if (!_config_single_service(arg))
					return FALSE;
			}
			else {
				if (!_config_single_address(arg))
					return FALSE;
			}
		}
	}

	GRID_INFO("Target address(es) configured!");
	return TRUE;
}

/* ------------------------------------------------------------------------- */

struct thread_data_s {
	addr_info_t target;
};

static gboolean
_send_request(struct metacnx_ctx_s *cnx, MESSAGE request, GError **err)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	g_assert(cnx != NULL);
	g_assert(request != NULL);

	if (!metaXClient_reply_sequence_run_context(err, cnx, request, &data)) {
		GSETERROR(err, "request failure");
		metacnx_close(cnx);
		return FALSE;
	}

	if (!flag_reuse)
		metacnx_close(cnx);
	return TRUE;
}

static gpointer
thread_worker(gpointer p)
{
	gint64 packets = 0;
	struct thread_data_s *td = p;
	GError *err = NULL;
	MESSAGE request;
	struct metacnx_ctx_s cnx;
	GTimer *timer;
	gchar str_target[STRLEN_ADDRINFO];

	g_assert(NULL != td);
	addr_info_to_string(&(td->target), str_target, sizeof(str_target));
	GRID_DEBUG("Connecting to [%s]", str_target);

	request = message_create_request(&err, NULL, "PING", NULL, NULL);
	if (!request) {
		GRID_ERROR("Request creation error : %s", err->message);
		goto error_request;
	}

	metacnx_clear(&cnx);
	if (!metacnx_init_with_addr(&cnx, &(td->target), &err)) {
		GRID_ERROR("Connection init failure : %s", err->message);
		goto error_cnx;
	}
	cnx.flags = METACNX_FLAGMASK_KEEPALIVE;
	cnx.timeout.cnx = 120000;
	cnx.timeout.req = 120000;

	timer = g_timer_new();

	do {
		gboolean rc;
		gdouble elapsed;

		err = NULL;
		g_timer_reset(timer);
		rc = _send_request(&cnx, request, &err);
		elapsed = g_timer_elapsed(timer, NULL);

		if (rc)
			g_print("PONG %s %f\n", str_target, elapsed);
		else {
			g_print("ERROR %s %f\n", str_target, elapsed);
			GRID_ERROR("PING request error from %s after %f seconds : %s",
					str_target, elapsed, err->message);
		}

		if (err)
			g_clear_error(&err);

		if (max_packets > 0 && (++packets) >= max_packets)
			break;

		if (!flag_flood)
			usleep(1000000L);

	} while (grid_main_is_running());

	g_timer_destroy(timer);
	metacnx_close(&cnx);
	metacnx_clear(&cnx);
error_cnx:
	message_destroy(request, NULL);
error_request:
	if (err)
		g_clear_error(&err);
	return p;
}

static GSList *
thread_start_N(void)
{
	guint i;
	GThread *th;
	GError *err = NULL;
	GSList *threads = NULL;

	for (i=0; i<addresses->len;i++) {
		struct thread_data_s *p;
		
		p = g_malloc0(sizeof(struct thread_data_s));
		memcpy(&(p->target), &g_array_index(addresses, addr_info_t, i), sizeof(addr_info_t));

		th = g_thread_create(thread_worker, p, TRUE, &err);
		if (th != NULL)
			threads = g_slist_prepend(threads, th);
		else {
			GRID_ERROR("GThread creation failure : %s", err->message);
			g_clear_error(&err);
		}
	}

	return threads;
}

static void
thread_join_all(GSList *threads)
{
	GThread *th;
	gpointer p;
	GSList *l;

	for (l=threads; l ;l=l->next) {
		if (!(th = l->data))
			continue;
		p = g_thread_join(th);
		g_free(p);
	}
}

static void
main_action(void)
{
	GSList *threads = NULL;

	/* Start several worker threads */
	threads = thread_start_N();
	GRID_INFO("Started %u worker threads", g_slist_length(threads));
	
	/* Join the threads started */
	thread_join_all(threads);
	g_slist_free(threads);
	GRID_INFO("Joined all the worker threads");
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

