#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
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

static int _write (void *u, const unsigned char *b, size_t l) {
	ssize_t rc;
	assert(u != NULL);
	if (l == 0)
		return 0;
retry:
	rc = fwrite(b, 1, l, (FILE*)u);
	if (rc < 0)
		return -1;
	if ((size_t)rc != l) {
		b += rc;
		l -= rc;
		goto retry;
	}
	return l;
}

int main(int argc, char **argv) {

	int rc = -1;
	const char *ns, *account, *user;
	struct oio_error_s *err = NULL;
	struct oio_sds_s *sds = NULL;
	struct oio_url_s *url = NULL;

	if (argc != 2) {
		g_printerr("Usage: %s PATH_OIO\n", argv[0]);
		return -1;
	}

	const char *name = argv[1];
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

	/* Prepare the context to receive the file */
	struct oio_sds_dl_src_s src = {0};
	struct oio_sds_dl_dst_s dst = {0};
	src.url = url;
	dst.type = OIO_DL_DST_HOOK_SEQUENTIAL;
	dst.data.hook.length = (size_t)-1;
	dst.data.hook.ctx = stdout;
	dst.data.hook.cb = _write;

	/* Trigger the download now */
	err = oio_sds_download(sds, &src, &dst);
	if (!err) {
		g_printerr("Downloaded %lu bytes\n", dst.out_size);
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

