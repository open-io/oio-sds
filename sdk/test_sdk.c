#include <oio_sds.h>
#include <metautils/lib/common_main.h>
#include <metautils/lib/metautils_loggers.h>
#include <metautils/lib/hc_url.h>
#include <glib.h>

int
main(int argc, char **argv)
{
	logger_lazy_init ();
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level (GRID_LOGLVL_TRACE2);

	if (argc != 3) {
		g_printerr ("Usage: %s HCURL PATH\n", argv[0]);
		return 1;
	}

	const char *str_url = argv[1];
	const char *str_path = argv[2];
	
	struct oio_error_s *err = NULL;
	struct hc_url_s *url;
	struct oio_sds_s *client = NULL;

	url = hc_url_oldinit(str_url);
	if (!url) {
		g_printerr ("Invalid URL [%s]\n", str_url);
		return 2;
	}
	if (!hc_url_has_fq_path(url)) {
		g_printerr ("Partial URL [%s]\n", str_url);
		return 3;
	}
	err = oio_sds_init (&client, hc_url_get(url, HCURL_NS));
	if (err) {
		g_printerr ("Client init error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 4;
	}

	err = oio_sds_upload_from_file (client, url, str_path);
	if (err) {
		g_printerr ("Upload error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 5;
	}

	err = oio_sds_download_to_file (client, url, "/tmp/XXX");
	if (err) {
		g_printerr ("Download error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 6;
	}

	hc_url_pclean (&url);
	oio_sds_pfree (&client);
	oio_error_pfree (&err);
	return 0;
}

