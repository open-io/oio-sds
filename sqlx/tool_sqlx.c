/*
OpenIO SDS sqlx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlx_remote_ex.h>
#include <resolver/hc_resolver.h>

#include <metautils/lib/RowFieldValue.h>
#include <metautils/lib/RowField.h>
#include <metautils/lib/RowFieldSequence.h>
#include <metautils/lib/Row.h>
#include <metautils/lib/RowSet.h>
#include <metautils/lib/RowName.h>
#include <metautils/lib/TableHeader.h>
#include <metautils/lib/Table.h>
#include <metautils/lib/TableSequence.h>

static struct hc_resolver_s *resolver = NULL;

static gboolean flag_xml = FALSE;
static gboolean flag_json = FALSE;

struct oio_url_s *url = NULL;
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
_on_reply(gpointer u, MESSAGE reply)
{
	(void) u;
	size_t bsize = 0;
	void *b = metautils_message_get_BODY(reply, &bsize);
	if (!b || !bsize)
		return TRUE;

	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.max_stack_size = ASN1C_MAX_STACK;

	struct TableSequence *ts = NULL;
	asn_dec_rval_t rv = ber_decode(&ctx, &asn_DEF_TableSequence, (void**)&ts, b, bsize);
	if (rv.code != RC_OK) {
		g_printerr("Invalid reply from SQLX: bad body, decoding error\n");
		return FALSE;
	}

	if (flag_json) {
		g_print("{ \"result\" : [\n");
		for (int i=0; i < ts->list.count ; i++)
			_dump_table_json(ts->list.array[i]);
		g_print(" ]\n}");
	}
	else if (flag_xml) {
		g_print("<result>\n");
		for (int i=0; i < ts->list.count ; i++)
			_dump_table_xml(ts->list.array[i]);
		g_print("</result>");
	}
	else {
		for (int i=0; i < ts->list.count ; i++)
			_dump_table_text(ts->list.array[i]);
	}

	if (ts)
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
	return TRUE;
}

static gint
do_query(struct gridd_client_s *client, struct meta1_service_url_s *surl,
		const gchar *Q)
{
	gint rc = 0;
	GError *err;
	GByteArray *req;
	struct sqlx_name_mutable_s name;

	GRID_DEBUG("Querying [%s]", Q);

	sqlx_name_fill (&name, url, NAME_SRVTYPE_SQLX, surl->seq);

	req = sqlx_pack_QUERY_single(sqlx_name_mutable_to_const(&name), Q, FALSE);
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

	sqlx_name_clean (&name);
	return rc;
}

static gint
do_queryv(struct meta1_service_url_s *surl)
{
	gint rc;
	gchar **pq;
	struct gridd_client_s *client;

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

/* XXX TODO make a call to the proxy */
static gint
do_destroy2(struct meta1_service_url_s *srvurl)
{
	(void) srvurl;
	g_printerr("SQLX base destruciton not implemented");
	return 1;
}

static void
cli_action(void)
{
	/* Use the client to get a sqlx service */
	GRID_DEBUG("Locating [%s] CID[%s]", oio_url_get(url, OIOURL_WHOLE),
			oio_url_get(url, OIOURL_HEXID));

	gchar **srvurlv = NULL;
	GError *err = hc_resolve_reference_service(resolver, url, type, &srvurlv);
	if (err != NULL) {
		GRID_ERROR("Services resolution error: (%d) %s", err->code, err->message);
		grid_main_set_status(1);
		return;
	}

	if (!srvurlv || !*srvurlv) {
		GRID_ERROR("Services resolution error: (%d) %s", 0, "No service found");
		grid_main_set_status(1);
		return;
	}

	for (gchar **s=srvurlv; *s ;s++)
		GRID_DEBUG("Located [%s]", *s);

	gint rc = 0;
	for (gchar **s=srvurlv; !rc && *s ;s++) {
		struct meta1_service_url_s *surl;
		if (!(surl = meta1_unpack_url(*s)))
			g_printerr("Invalid service URL from meta1 [%s]\n", *s);
		else {
			if (!g_ascii_strcasecmp("destroy", query[0])) {
				rc = do_destroy2(surl);
			} else {
				rc = do_queryv(surl);
			}
			g_free(surl);
		}
	}

	g_strfreev(srvurlv);
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
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
	resolver = NULL;
}

static void
cli_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	metautils_pfree(&type);
	metautils_pfree(&query);
	if (resolver) {
		hc_resolver_destroy (resolver);
		resolver = NULL;
	}
	if (url) {
		oio_url_clean(url);
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

	if (!(url = oio_url_init(argv[0]))) {
		g_printerr("Invalid hc URL (%s)\n", strerror(errno));
		return FALSE;
	}

	resolver = hc_resolver_create1(oio_ext_monotonic_time() / G_TIME_SPAN_SECOND);
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
	return grid_main_cli(argc, args, &cli_callbacks);
}

