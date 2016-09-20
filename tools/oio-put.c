#include <stdlib.h>
#include <glib.h>

#include "../core/oiourl.h"
#include "../core/oio_sds.h"

#define GETENV(P,K) do { \
	P = g_getenv(K); \
	if (!P) { \
		g_printerr("Missing environment variable %s\n", K); \
		return 1; \
	} \
} while (0);

int main(int argc, char **argv) {

	int rc = -1;
	const char *ns, *account, *user;
	struct oio_error_s *err = NULL;
	struct oio_sds_s *sds = NULL;
	struct oio_url_s *url = NULL;

	if (argc != 3) {
		g_printerr("Usage: %s PATH_LOCAL PATH_OIO\n", argv[0]);
		return -1;
	}

	const char *local = argv[1];
	const char *name = argv[2];
	GETENV(ns,"OIO_NS");
	GETENV(account,"OIO_ACCOUNT");
	GETENV(user,"OIO_USER");

	/* Build the URL naming the content on OIO-SDS */
	url = oio_url_empty();
	oio_url_set(url, OIOURL_NS, ns);
	oio_url_set(url, OIOURL_ACCOUNT, account);
	oio_url_set(url, OIOURL_USER, user);
	oio_url_set(url, OIOURL_PATH, name);

	/* Initiate a client handle */
	err = oio_sds_init(&sds, oio_url_get(url, OIOURL_NS));
	if (err) {
		g_printerr("Client init error: (%d) %s\n",
				oio_error_code(err), oio_error_message(err));
		goto out;
	}

	/* Prepare the target characteristics of the content */
	const char *props[] = {
		"name.original", name,
		NULL
	};
	struct oio_sds_ul_dst_s dst = {0};
	dst.url = url;
	dst.autocreate = 1;
	dst.properties = (const char * const *) props;

	/* Trigger the upload itself */
	err = oio_sds_upload_from_file(sds, &dst, local, 0, 0);
	if (!err) {
		g_printerr("Uploaded [%s] in [%s]\n", local, oio_url_get(url, OIOURL_WHOLE));
		rc = 0;
	} else {
		g_printerr("Upload error: (%d) %s\n",
				oio_error_code(err), oio_error_message(err));
		rc = 2;
	}

out:
	oio_sds_pfree(&sds);
	oio_error_pfree(&err);
	oio_url_pclean(&url);
	return rc;
}
