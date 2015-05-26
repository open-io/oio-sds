/**
OpenIO SDS oio-grep, a demonstration tool for the C client API.
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <grid_client.h>
#include <glib.h>

static void
_gs_error_clear (gs_error_t **e)
{
	gs_error_free (*e);
	*e = NULL;
}

static int
_download (gs_grid_storage_t *gs, const char *container, const char *content,
		const char *local)
{
	/* XXX */
	gs_error_t *err = NULL;
	gs_status_t gsrc = hc_dl_content_to_file (gs, container, content, local, &err);
	if (gsrc != GS_OK) {
		fprintf(stderr, "OIO download error on [%s]/[%s] : (%d) %s\n",
				container, content, err->code, err->msg);
		_gs_error_clear (&err);
		return 0;
	} else {
		fprintf(stderr, "OIO download done on [%s]/[%s] -> [%s]\n", container, content, local);
		return 1;
	}
}

static ssize_t
_reader (int *pfd, char *b, size_t max)
{
	/* fill <b> with the data available. At most <max> bytes are expected in <b>. */
	return read (*pfd, b, max);
}

static int
_upload (gs_grid_storage_t *gs, const char *container, const char *content,
		const char *local)
{
	struct stat st;
	int fd;

	/* do not play with non-blocking sockets, unless you know what you are doing. */
	if (0 > (fd = open (local, O_RDONLY))) {
		fprintf(stderr, "LOCAL open error on [%s] : (%d) %s\n", local, errno, strerror(errno));
		return 0;
	}
	if (0 > fstat (fd, &st)) {
		fprintf(stderr, "LOCAL stat error on [%s] : (%d) %s\n", local, errno, strerror(errno));
		close (fd);
		return 0;
	}

	gs_status_t rc;
	gs_error_t *err = NULL;
	gs_container_t *c = gs_get_container (gs, container, 1/*autocreate*/, &err);
	if (!c) {
		fprintf (stderr, "OIO container error on [%s]/[%s] : (%d) %s\n",
				container, content, err->code, err->msg);
		_gs_error_clear (&err);
		rc = GS_ERROR;
	} else {
		rc = gs_upload_content_v2 (c,
				content, st.st_size, (gs_input_f)_reader, &fd,
				"", "", &err);
		if (rc != GS_OK) {
			fprintf (stderr, "OIO upload error on [%s]/[%s] : (%d) %s\n",
					container, content, err->code, err->msg);
			_gs_error_clear (&err);
		} else {
			fprintf (stderr, "OIO upload done on [%s]/[%s]\n", container, content);
		}

		gs_container_free (c);
		c = NULL;
	}

	close (fd);
	return rc == GS_OK;
}

static int
_delete (gs_grid_storage_t *gs, const char *container, const char *content)
{
	gs_status_t rc;
	gs_error_t *err = NULL;
	gs_container_t *c = gs_get_container (gs, container, 1/*autocreate*/, &err);
	if (!c) {
		fprintf (stderr, "OIO container error on [%s]/[%s] : (%d) %s\n",
				container, content, err->code, err->msg);
		rc = GS_ERROR;
	} else {
		rc = gs_delete_content_by_name (c, content, &err);
		if (rc != GS_OK) {
			fprintf (stderr, "OIO delete error on [%s]/[%s] : (%d) %s\n",
					container, content, err->code, err->msg);
			_gs_error_clear (&err);
		} else {
			fprintf (stderr, "OIO delete done on [%s]/[%s]\n", container, content);
		}

		gs_container_free (c);
		c = NULL;
	}

	return rc == GS_OK;
}

int
main (int argc, char **args)
{
	if (argc != 5) {
		fprintf (stderr, "Usage: %s NAMESPACE CONTAINER CONTENT PATHLOCAL\n", args[0]);
		return 1;
	}

	const char *ns = args[1], *container = args[2], *content = args[3], *src = args[4];

	int rc = 0;

	/* XXX */
	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = gs_grid_storage_init (ns, &err);
	if (!gs) {
		fprintf(stderr, "OIO init error : (%d) %s\n", err->code, err->msg);
		_gs_error_clear (&err);
		return 2;
	}

	if (!_upload (gs, container, content, src))
		rc = 3;
	else {

		// get a temporary file
		const char *tmpdir = "/tmp";
		if (getenv("TMPDIR"))
			tmpdir = getenv("TMPDIR");
		char tmp[256];
		snprintf (tmp, sizeof(tmp), "%s/plop-XXXXXX", tmpdir);
		int tmpfd = mkstemp (tmp);

		if (tmpfd < 0) {
			fprintf (stderr, "LOCAL mkstemp error [%s] : (%d) %s\n", tmp, errno, strerror(errno));
		} else {
			close (tmpfd);
			unlink (tmp);
			fprintf (stdout, "%s\n%s\n", src, tmp);
			if (!_download (gs, container, content, tmp))
				rc = 4;
		}

		_delete (gs, container, content);
	}
	
	gs_grid_storage_free (gs);
	gs = NULL;
	return rc;
}

