/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.client"
#endif

#include <errno.h>
#include <glib.h>

#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/loggers.h"
#include "../metautils/lib/hc_url.h"
#include "../metautils/lib/common_main.h"
#include "../metautils/lib/gridd_client.h"
#include "../client/c/lib/grid_client.h"
#include "../sqliterepo/sqlx_remote.h"

#include <RowFieldValue.h>
#include <RowField.h>
#include <RowFieldSequence.h>
#include <Row.h>
#include <RowSet.h>
#include <RowName.h>
#include <TableHeader.h>
#include <Table.h>
#include <TableSequence.h>

#ifndef FREEP
# define FREEP(F,P) do { if (!(P)) return; F(P); (P) = NULL; } while (0)
#endif

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
	name.cid = hc_url_get_id(url);

	req = sqlx_pack_QUERY_single(&name, Q);
	gridd_client_request(client, req, NULL, _on_reply);
	g_byte_array_unref(req);

	if (NULL != (err = gridd_client_loop(client))) {
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
		}
		rc = 1;
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

static void
cli_action(void)
{
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
		g_printerr("Service not located : (%d) %s\n", hc_error->code, hc_error->msg);
		goto exit;
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
		gint rc;
		gchar **s;

		for (s=srvurlv; *s ;s++)
			GRID_DEBUG("Located [%s]", *s);

		for (rc=0,s=srvurlv; !rc && *s ;s++) {
			struct meta1_service_url_s *surl;
			if (!(surl = meta1_unpack_url(*s)))
				g_printerr("Invalid service URL from meta1 [%s]\n", *s);
			else {
				rc = do_queryv(surl);
				g_free(surl);
			}
		}
	}

exit:
	strfreev(&srvurlv);
	if (hc_error)
		gs_error_free(hc_error);
	gs_grid_storage_free(hc);
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{ "AutoRef", OT_BOOL, {.b = &flag_auto_ref},
			"If the reference does not exist, create it now"},
		{ "AutoLink", OT_BOOL, {.b = &flag_auto_link},
			"If no sqlx base has been linked to the reference, do it now"},
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
	FREEP(g_free, type);
	FREEP(g_free, query);

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
	return "NS/REF TYPE QUERY";
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

