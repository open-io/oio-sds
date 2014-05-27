#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// TODO FIXME replace with GLib equivalent
#include <openssl/md5.h>

#include "../lib/gs_internals.h"

static int input_fd = 0;
static int output_fd = 0;
char *local_path = NULL;

static gs_status_t
dl_nocache(gs_container_t *container, const gchar *name, gs_download_info_t *dlinfo, gs_error_t **err)
{        
	gs_status_t rc = GS_ERROR;
        gs_content_t *content;

        /*find the content*/
        content  = gs_get_content_from_path (container, name, err);
        if (!content) {
                printf("'%s' not found in '%s'\n", name, C0_NAME(container));
                goto error_get;
        }
        printf("content %s found in container %s\n", name, C0_NAME(container));

        /*download the content*/

        if (!gs_download_content (content, dlinfo, err)) {
                printf("grid storage error: cannot download %s from %s (into %s)\n", name, C0_NAME(container), local_path);
                goto error_download;
        }
        printf("download done from %s to %s\n", name, local_path);

        rc = GS_OK;
error_download:
        gs_content_free (content);
error_get:
	return rc;
}

static int
open_destination(void)
{
        if (!g_ascii_strcasecmp(local_path, "-")) {
                output_fd = 1;
        }
        else {
                output_fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (-1 == output_fd) {
                        if (errno == ENOENT) {
                                output_fd = open(local_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
                                if (-1 == output_fd) {
                                        printf("cannot create and open the local file %s (%s)\n", local_path,
                                            strerror(errno));
                                        return 0;
                                }
                                else {
                                        printf("local path %s created\n", local_path);
                                }
                        }
                        else {
                                printf("cannot open the local file %s (%s)\n", local_path, strerror(errno));
                                return 0;
                        }
                }
                else {
                        printf("local path %s opened\n", local_path);
                }
        }
        return 1;
}

static ssize_t
write_to_fd(void *uData, const char *b, const size_t bSize)
{
        ssize_t nbW;

        nbW = write(*((int *) uData), b, bSize);
        return nbW;
}

static ssize_t
feed_from_fd(void *uData, char *b, size_t bSize)
{
        ssize_t nbRead;

        if (!b || !bSize) {
                printf("API : invalid buffer for reading\n");
                return -1;
        }
        nbRead = read(*((int *) uData), b, bSize);
        return nbRead;
}

int main (int argc, char ** args)
{
	int rc = -1;

	gs_error_t *err = NULL;
	gs_status_t status;
	gs_grid_storage_t *hc = NULL;
	gs_container_t *container = NULL;
	gs_container_t *container_bis = NULL;
	gs_download_info_t dl_info;
	char *ns;
	char cname[60];
	char path[60];
	char *source_path;
	struct stat64 local_stats;


	srand(time(NULL));

	if (argc != 3) {
		g_error("Usage: %s NS local_path\n", args[0]);
		return rc;
	}

	memset(&dl_info, 0x00, sizeof(dl_info));

	ns = args[1];
	source_path = args[2];

	bzero(cname, sizeof(cname));
	bzero(path, sizeof(path));
	g_snprintf(cname, sizeof(cname), "SOLR%d", rand());
	g_snprintf(path, sizeof(path), "CONTENT%d", rand());

	printf("Working with container [%s] and content [%s]\n", cname, path);

	/*init the local path */
	if (-1 == stat64(source_path, &local_stats))
		return rc;
	else
		printf("local path %s found\n", source_path);

	if (-1 == (input_fd = open(source_path, O_RDONLY|O_LARGEFILE))) {
		printf("cannot open the local file (%s)\n", strerror(errno));
		goto end_label;
	} else 
		printf("local path %s found and opened\n", source_path);

	hc = gs_grid_storage_init( ns, &err );
	if(!hc) {
		printf("failed to init hc\n");
		goto end_label;
	}

	container = gs_get_container(hc, cname, 1, &err);
	if(!container) {
		printf("Failed to resolve container\n");
		goto end_label;
	}

	status = gs_upload_content (container, path, local_stats.st_size, feed_from_fd, &input_fd, &err);
	if(status != GS_OK && err) {
		printf("upload error \n");
		printf("error info : [%d]|[%s]\n", err->code, err->msg);
	}

	container_bis = gs_get_container(hc, cname, 1, &err);
        if(!container_bis) {
                printf("Failed to resolve container bis\n");
                goto end_label;
        }

	local_path = g_malloc0(256);
	g_snprintf(local_path, 256, "%d", rand());
	printf("local_path defined => %s", local_path);
/*open the destination file decriptor */
        if (!open_destination()) {
                printf("failed to open the destination file descriptor to path=%s\n", local_path);
                goto end_label;
        }
        else
                printf("destination file descriptor ready fd=%d path=%s\n", output_fd, local_path);

	/*download the content */
	dl_info.offset = 0;
	dl_info.size = 0;
	dl_info.writer = write_to_fd;
	dl_info.user_data = &output_fd;
	rc = dl_nocache(container_bis, path, &dl_info, &err);
	
end_label:

	 if (output_fd >= 0) {
                close(output_fd);
                output_fd = -1;
        }

	if(container) {
		gs_container_free(container);
		container = NULL;
	}

	if(container_bis) {
		gs_container_free(container_bis);
		container_bis = NULL;
	}

	if(hc) {
		gs_grid_storage_free(hc);
		hc = NULL;
	}

	if(err) {
		gs_error_free(err);
		err= NULL;
	}
}

