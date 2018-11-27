/*
oio-file, a CLI upload and download tool using the C API of OpenIO
Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>
#include <core/oio_sds.h>

static gboolean is_upload = FALSE;
static gchar *account = NULL;
static gchar *container = NULL;
static gchar *local_file = NULL;
static gchar *remote_object = NULL;
static gchar *ns = NULL;

static GOptionEntry entries[] = {
	{
				"upload",
				'u',
				0,
				G_OPTION_ARG_NONE,
				&is_upload,
				"Upload the specified file to the given container instead of downloading.",
			FALSE},
	{
				"namespace",
				'n',
				0,
				G_OPTION_ARG_STRING,
				&ns,
				"The OpenIO namespace on which we'd like to operate.",
			NULL},
	{
				"account",
				'a',
				0,
				G_OPTION_ARG_STRING,
				&account,
				"The OpenIO account on which we'd like to operate.",
			NULL},
	{
				"container",
				'c',
				0,
				G_OPTION_ARG_STRING,
				&container,
				"The OpenIO container on which we'd like to operate.",
			NULL},
	{
				"local-file",
				'f',
				0,
				G_OPTION_ARG_STRING,
				&local_file,
				"The local file we'll operate on.",
			NULL},
	{
				"remote-object",
				'o',
				0,
				G_OPTION_ARG_STRING,
				&remote_object,
				"The object name we'll operate on.",
			NULL},
	{0}
};

int
main(int argc, char **argv)
{
	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new("- Object upload/download tool using C API");
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("Option parsing failed: %s\n", error->message);
		exit(1);
	}

	if (!ns || !account || !container || !local_file || !remote_object) {
		g_print("One or more arguments are missing !");
		exit(1);
	}


	struct oio_sds_s *client = NULL;
	struct oio_error_s *err = NULL;
	err = oio_sds_init(&client, ns);
	g_assert_no_error((GError *) err);
	struct oio_url_s *url = oio_url_empty();
	g_assert_nonnull(url);
	oio_url_set(url, OIOURL_NS, ns);
	oio_url_set(url, OIOURL_ACCOUNT, account);
	oio_url_set(url, OIOURL_USER, container);
	oio_url_set(url, OIOURL_PATH, remote_object);

	if (is_upload == TRUE) {
		g_print("Performing an upload ...\r\n");
		struct oio_sds_ul_dst_s dst = OIO_SDS_UPLOAD_DST_INIT;
		dst.url = url;
		dst.autocreate = 1;
		dst.out_size = 0;
		dst.append = 0;
		dst.partial = 0;
		err = oio_sds_upload_from_file(client, &dst, local_file, 0, 0);
		oio_url_clean(url);
		g_assert_no_error((GError *) err);
	} else {
		g_print("Performing a download ...\r\n");
		err = oio_sds_download_to_file(client, url, local_file);
		oio_url_clean(url);
		g_assert_no_error((GError *) err);
	}

	g_print("Done !\r\n");

	g_option_context_free(context);
	g_free(ns);
	g_free(account);
	g_free(container);
	g_free(local_file);
	g_free(remote_object);

	return 0;
}
