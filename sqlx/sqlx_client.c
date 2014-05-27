#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.client"
#endif

#include <errno.h>

#include <grid_client.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlx_remote_ex.h>

#include <metautils/lib/RowFieldValue.h>
#include <metautils/lib/RowField.h>
#include <metautils/lib/RowFieldSequence.h>
#include <metautils/lib/Row.h>
#include <metautils/lib/RowSet.h>
#include <metautils/lib/RowName.h>
#include <metautils/lib/TableHeader.h>
#include <metautils/lib/Table.h>
#include <metautils/lib/TableSequence.h>

static gboolean flag_auto_ref = FALSE;
static gboolean flag_auto_link = FALSE;
static gboolean flag_xml = FALSE;
static gboolean flag_json = FALSE;

struct hc_url_s *url = NULL;
static gchar *type = NULL;
static gchar **query = NULL;

static void
_dump_table_text(struct Table *table)
{
	gdouble d = 0;
	gint64 i64 = 0, pos = 0;
	int32_t i, imax, j, jmax;

	g_print("# query = \"%.*s\"\n", table->name.size, table->name.buf);
	g_print("# rows = %u\n", table->rows.list.count);

	if (!table->status)
		g_print("# status = ?");
	else {
		asn_INTEGER_to_int64(table->status, &i64);
		g_print("# status = %"G_GINT64_FORMAT, i64);
	}

	if (!table->statusString)
		g_print("\n");
	else
		g_print(" (%.*s)\n", table->statusString->size, table->statusString->buf);

	if (table->rows.list.count > 0) {

		for (i=0,imax=table->rows.list.count; i<imax ;i++) {
			struct Row *row = table->rows.list.array[i];
			if (!row->fields || row->fields->list.count < 0)
				continue;

			for (j=0,jmax=row->fields->list.count; j<jmax ;j++) {
				struct RowField *field = row->fields->list.array[j];

				asn_INTEGER_to_int64(&(field->pos), &pos);
				if (j)
					g_print("|");
				
				switch (field->value.present) {
					case RowFieldValue_PR_NOTHING:
					case RowFieldValue_PR_n:
						g_print("(nil)");
						break;
					case RowFieldValue_PR_i:
						asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
						g_print("%"G_GINT64_FORMAT, i64);
						break;
					case RowFieldValue_PR_f:
						asn_REAL2double(&(field->value.choice.f), &d);
						g_print("%f", d);
						break;
					case RowFieldValue_PR_b:
						g_print("%.*s", field->value.choice.b.size,
							field->value.choice.b.buf);
						break;
					case RowFieldValue_PR_s:
						g_print("%.*s", field->value.choice.s.size,
									field->value.choice.s.buf);
						break;
				}
			}

			g_print("\n");
		}
	}
}

static void
_dump_table_xml(struct Table *table)
{
	gdouble d = 0;
	gint64 i64 = 0, pos = 0;
	int32_t i, j;

	g_print("<table>\n <name>%.*s</name>\n", table->name.size, table->name.buf);

	i64 = 0;
	if (table->status)
		asn_INTEGER_to_int64(table->status, &i64);

	if (table->statusString)
		g_print(" <status code=\"%"G_GINT64_FORMAT"\"/>\n", i64);
	else
		g_print(" <status code=\"%"G_GINT64_FORMAT"\">%.*s</status>\n", i64,
				table->statusString->size, table->statusString->buf);

	if (table->rows.list.count > 0) {

		g_print(" <rows>\n");

		for (i=0; i<table->rows.list.count ;i++) {
			struct Row *row = table->rows.list.array[i];
			if (!row->fields || row->fields->list.count < 0)
				continue;

			g_print("  <row>\n");

			for (j=0; j<row->fields->list.count ;j++) {
				struct RowField *field = row->fields->list.array[j];

				asn_INTEGER_to_int64(&(field->pos), &pos);
				g_print("   <f pos=%"G_GINT64_FORMAT">", pos);

				switch (field->value.present) {
					case RowFieldValue_PR_NOTHING:
					case RowFieldValue_PR_n:
						g_print("(nil)");
						break;
					case RowFieldValue_PR_i:
						asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
						g_print("%"G_GINT64_FORMAT, i64);
						break;
					case RowFieldValue_PR_f:
						asn_REAL2double(&(field->value.choice.f), &d);
						g_print("%f", d);
						break;
					case RowFieldValue_PR_b:
						g_print("%.*s", field->value.choice.b.size,
								field->value.choice.b.buf);
						break;
					case RowFieldValue_PR_s:
						g_print("%.*s", field->value.choice.s.size,
								field->value.choice.s.buf);
						break;
				}

				g_print("</f>\n");
			}

			g_print("  </row>\n");
		}

		g_print(" </rows>\n");
	}

	g_print("<table>\n");
}

static void
json_dump_string(const guint8 *b, gint32 max)
{
	gint32 i;
	register guint16 u16;
	register guint8 c;

	g_print("\"");
	for (i=0; i<max ;i++) {
		c = b[i];
		if (g_ascii_isprint(c))
			g_print("%c", c);
		else {
			u16 = c;
			g_print("\\u%04x", u16);
		}
	}
	g_print("\"");
}

static void
_dump_table_json(struct Table *table)
{
	gdouble d = 0;
	gint64 i64 = 0, pos = 0;
	int32_t i, j;

	g_print(" {\n \"table\" : \"%.*s\",\n", table->name.size, table->name.buf);
	if (table->status) {
		asn_INTEGER_to_int64(table->status, &i64);
		g_print(" \"status\" : %"G_GINT64_FORMAT",\n", i64);
	}
	g_print("  \"rows\" : [\n");

	if (table->rows.list.count > 0) {

		for (i=0; i<table->rows.list.count ;i++) {
			struct Row *row = table->rows.list.array[i];
			if (!row->fields || row->fields->list.count < 0)
				continue;

			g_print("   {\n");

			for (j=0; j<row->fields->list.count ;j++) {
				struct RowField *field = row->fields->list.array[j];

				asn_INTEGER_to_int64(&(field->pos), &pos);
				g_print("    \"%"G_GINT64_FORMAT"\" : ", pos);

				switch (field->value.present) {
					case RowFieldValue_PR_NOTHING:
					case RowFieldValue_PR_n:
						g_print("null");
						break;
					case RowFieldValue_PR_i:
						asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
						g_print("%"G_GINT64_FORMAT, i64);
						break;
					case RowFieldValue_PR_f:
						asn_REAL2double(&(field->value.choice.f), &d);
						g_print("%f", d);
						break;
					case RowFieldValue_PR_b:
						json_dump_string(field->value.choice.b.buf, field->value.choice.b.size);
						break;
					case RowFieldValue_PR_s:
						json_dump_string(field->value.choice.s.buf, field->value.choice.s.size);
						break;
				}
				g_print(",\n");
			}
			g_print("   },\n");
		}
	}

	g_print("  ]\n },\n");
}

static gboolean
_on_reply(gpointer u, struct message_s *reply)
{
	int i;
	GError *err = NULL;
	void *b = NULL;
	size_t bsize = 0;
	struct TableSequence *ts = NULL;

	(void) u;

	if (0 < message_get_BODY(reply, &b, &bsize, &err)) {
		if (err) {
			g_printerr("Could not get body : (%d) %s\n", err->code, err->message);
			g_clear_error(&err);
			return TRUE;
		}
	}

	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.max_stack_size = 512 * 1024;
	rv = ber_decode(&ctx, &asn_DEF_TableSequence, (void**)&ts, b, bsize);
	if (rv.code != RC_OK) {
		g_printerr("Invalid reply from SQLX: bad body, decoding error\n");
		return FALSE;
	}

	if (flag_json) {
		g_print("{ \"result\" : [\n");
		for (i=0; i < ts->list.count ; i++)
			_dump_table_json(ts->list.array[i]);
		g_print(" ]\n}");
	}
	else if (flag_xml) {
		g_print("<result>\n");
		for (i=0; i < ts->list.count ; i++)
			_dump_table_xml(ts->list.array[i]);
		g_print("</result>");
	}
	else {
		for (i=0; i < ts->list.count ; i++)
			_dump_table_text(ts->list.array[i]);
	}

	if (ts)
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
	return TRUE;
}

static void
strfreev(char ***v)
{
	char **p;
	if (!v || !*v)
		return;
	for (p=*v; *p ;p++)
		free(*p);
	free(*v);
	*v = NULL;
}

static gint
do_query(struct client_s *client, struct meta1_service_url_s *surl,
		const gchar *Q)
{
	gint rc = 0;
	GError *err;
	GByteArray *req;
	struct sqlxsrv_name_s name;

	GRID_DEBUG("Querying [%s]", Q);

	name.seq = surl->seq;
	name.ns = hc_url_get(url, HCURL_NS);
	name.schema = type;
	name.cid = (const container_id_t*)hc_url_get_id(url);

	req = sqlx_pack_QUERY_single(&name, Q, flag_auto_link);
	err = gridd_client_request(client, req, NULL, _on_reply);
	g_byte_array_unref(req);

	if (NULL != err) {
		g_printerr("Local error: (%d) %s\n", err->code, err->message);
		g_clear_error(&err);
	}
	else if (NULL != (err = gridd_client_loop(client))) {
		g_printerr("Local error: (%d) %s\n", err->code, err->message);
		g_clear_error(&err);
	}
	else {
		if (NULL != (err = gridd_client_error(client))) {
			g_printerr("SQLX error: (%d) %s\n", err->code, err->message);
			g_clear_error(&err);
		}
		else {
			GRID_DEBUG("SQLX query succeeded");
			rc = 1;
		}
	}

	return rc;
}

static gint
do_queryv(struct meta1_service_url_s *surl)
{
	gint rc;
	gchar **pq;
	struct client_s *client;

	GRID_DEBUG("Contacting SHARD[%"G_GINT64_FORMAT"] at [%s][%s]",
			surl->seq, surl->host, surl->args);

	client = gridd_client_create_idle(surl->host);
	gridd_client_set_keepalive(client, TRUE);
	gridd_client_start(client);

	rc = 1;
	for (pq=query; *pq ;pq++) {
		if (!do_query(client, surl, *pq)) {
			rc = 0;
			break;
		}
	}

	gridd_client_free(client);
	return rc;
}

static gint
do_destroy2(gs_grid_storage_t *hc, struct meta1_service_url_s *srv_url)
{
	gint rc = 1, seq = 1;
	gchar *target = NULL;
	GError *err = NULL;
	gs_error_t *hc_err = NULL;

	seq = srv_url->seq;
	target = srv_url->host;

	struct sqlxsrv_name_s name = {seq, hc_url_get(url, HCURL_NS),
			(const container_id_t*)hc_url_get_id(url), type};

	err = sqlx_remote_execute_DESTROY(target, NULL, &name, FALSE);

	if (err != NULL) {
		GRID_ERROR("Failed to destroy database: %s", err->message);
		rc = 0;
		goto end_label;
	}
	hc_err = hc_unlink_reference_service(hc,
			hc_url_get(url, HCURL_REFERENCE), type);
	if (hc_err) {
		GRID_ERROR("Failed to unlink service: %s", hc_err->msg);
		rc = 0;
	}

end_label:
	g_clear_error(&err);
	gs_error_free(hc_err);
	return rc;
}

static void
cli_action(void)
{
	gint rc = 0;
	gs_error_t *hc_error = NULL;
	gs_grid_storage_t *hc;
	char **srvurlv = NULL;

	/* Get a grid client */
	hc = gs_grid_storage_init(hc_url_get(url, HCURL_NS), &hc_error);
	if (!hc) {
		g_printerr("NS loading error: (%d) %s\n",
				hc_error->code, hc_error->msg);
		return;
	}

	/* Use the client to get a sqlx service */
	GRID_DEBUG("Locating NS[%s] CNAME[%s] CID[%s]",
			hc_url_get(url, HCURL_NS),
			hc_url_get(url, HCURL_REFERENCE),
			hc_url_get(url, HCURL_HEXID));

retry:
	strfreev(&srvurlv);
	hc_error = hc_list_reference_services(hc,
			hc_url_get(url, HCURL_REFERENCE), type, &srvurlv);
	if (hc_error != NULL) {
		if (hc_error->code != CODE_CONTAINER_NOTFOUND || !flag_auto_ref) {
			g_printerr("Service not located: (%d) %s\n", hc_error->code, hc_error->msg);
			goto exit;
		} else {
			gs_error_free(hc_error);
			hc_error = NULL;
			g_printerr("Reference [%s/%s] does not exists, creating it\n",
					hc_url_get(url, HCURL_NS), hc_url_get(url, HCURL_REFERENCE));
			hc_error = hc_create_reference(hc, hc_url_get(url, HCURL_REFERENCE));
			if (hc_error != NULL) {
				g_printerr("Failed to create reference: (%d) %s\n",
						hc_error->code, hc_error->msg);
				goto exit;
			} else {
				goto retry;
			}
		}
	}

	if (!srvurlv || !*srvurlv) {

		if (!flag_auto_link) {
			g_printerr("No service affected for type [%s], allocation not specified\n", type);
			goto exit;
		}

		hc_error = hc_link_service_to_reference(hc,
				hc_url_get(url, HCURL_REFERENCE), type, &srvurlv);
		if (!hc_error) {
			g_printerr("No service affected for type [%s],"
					" allocated [%s]\n", type, srvurlv[0]);
			goto retry;
		}
		else {
			g_printerr("No service affected for type [%s], allocation "
					"failed: (%d) %s\n", type, hc_error->code, hc_error->msg);
			goto exit;
		}
	}
	else {
		gchar **s;

		for (s=srvurlv; *s ;s++)
			GRID_DEBUG("Located [%s]", *s);

		for (rc=0,s=srvurlv; !rc && *s ;s++) {
			struct meta1_service_url_s *surl;
			if (!(surl = meta1_unpack_url(*s)))
				g_printerr("Invalid service URL from meta1 [%s]\n", *s);
			else {
				if (!g_ascii_strcasecmp("destroy", query[0])) {
					rc = do_destroy2(hc, surl);
				} else {
					rc = do_queryv(surl);
				}
				g_free(surl);
			}
		}
	}

exit:
	strfreev(&srvurlv);
	if (hc_error)
		gs_error_free(hc_error);
	gs_grid_storage_free(hc);
	grid_main_set_status(rc == 0);
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{ "AutoRef", OT_BOOL, {.b = &flag_auto_ref},
			"If the reference does not exist, create it now"},
		{ "AutoLink", OT_BOOL, {.b = &flag_auto_link},
			"If no sqlx base has been linked to the reference, do it now"},
		{ "AutoCreate", OT_BOOL, {.b = &flag_auto_link},
			"Same as AutoLink"},
		{ "OutputXML", OT_BOOL, {.b = &flag_xml},
			"Write XML instead of the default key=value output"},
		{ "OutputJSON", OT_BOOL, {.b = &flag_json},
			"Write JSON instead of the default key=value output or XML output"},
		{NULL, 0, {.i=0}, NULL}
	};

	return cli_options;
}

static void
cli_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	type = NULL;
	query = NULL;
	url = NULL;
}

static void
cli_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	metautils_pfree0(&type, NULL);
	metautils_pfree0(&query, NULL);

	if (url) {
		hc_url_clean(url);
		url = NULL;
	}
}

static void
cli_specific_stop(void)
{
	/* no op */
}

static const gchar *
cli_usage(void)
{
	return "NS/REF TYPE QUERY [QUERY...]\nNS/REF TYPE 'destroy'";
}

static gboolean
cli_configure(int argc, char **argv)
{
	GRID_DEBUG("Configuration");

	if (argc < 3) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	if (!(url = hc_url_init(argv[0]))) {
		g_printerr("Invalid hc URL (%s)\n", strerror(errno));
		return FALSE;
	}

	type = g_strconcat("sqlx.", argv[1], NULL);
	query = g_strdupv(argv+2);
	GRID_DEBUG("Executing %u requests", g_strv_length(query));

	return TRUE;
}

struct grid_main_callbacks cli_callbacks =
{
	.options = cli_get_options,
	.action = cli_action,
	.set_defaults = cli_set_defaults,
	.specific_fini = cli_specific_fini,
	.configure = cli_configure,
	.usage = cli_usage,
	.specific_stop = cli_specific_stop,
};

int
main(int argc, char **args)
{
	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	return grid_main_cli(argc, args, &cli_callbacks);
}

