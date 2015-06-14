#include <oio_sds.h>
#include <metautils/lib/metautils.h>
#include <glib.h>

int
main(int argc, char **argv)
{
	if (argc < 2) {
		g_printerr ("Usage: %s HCURL\n", argv[0]);
		return 1;
	}
	
	struct oio_error_s *err = NULL;
	struct hc_url_s *url;
	struct oio_sds_s *client = NULL;

	url = hc_url_oldinit(argv[1]);
	if (!url) {
		g_printerr ("Invalid URL [%s]\n", argv[1]);
		return 2;
	}
	if (!hc_url_has_fq_path(url)) {
		g_printerr ("Partial URL [%s]\n", argv[1]);
		return 3;
	}

	err = oio_sds_init (&client, hc_url_get(url, HCURL_NS));
	if (err) {
		g_printerr ("Client init error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 4;
	}

	err = oio_sds_download_to_file (client, url, "/tmp/XXX");
	if (err) {
		g_printerr ("Download error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 5;
	}

	hc_url_pclean (&url);
	oio_sds_free (client);
	oio_error_pfree (&err);
	return 0;
}

