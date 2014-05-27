#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

// TODO FIXME replacce with GLib equivalent
#include <openssl/md5.h>

#include <../lib/gs_internals.h>

static void
md5_dump_hex(MD5_CTX *md5_ctx, const gchar *tag)
{
	unsigned char md5[MD5_DIGEST_LENGTH];
	char md5_str[MD5_DIGEST_LENGTH*2+1], *c;

	bzero(md5_str, sizeof(md5_str));
	bzero(md5, sizeof(md5));

	MD5_Final(md5, md5_ctx);
	buffer2str(md5, sizeof(md5), md5_str, sizeof(md5_str));
	for (c=md5_str; *c ;c++)
		*c = g_ascii_tolower(*c);
	g_print("%s %s\n", md5_str, tag);
}

static size_t
random_size(size_t max)
{
	return 1 + (random() % max);
}

static ssize_t
output_normal(void *uData, const char *b, const size_t bSize)
{
	MD5_CTX *md5_ctx;
	ssize_t managed;

	md5_ctx = uData;
	managed = bSize;

	g_printerr("# %"G_GSIZE_FORMAT" bytes received pointer=%p\n", bSize, b);
	MD5_Update(md5_ctx, b, bSize);
	return managed;
}

static ssize_t
output_partial(void *uData, const char *b, const size_t bSize)
{
	if (!bSize)
		return 0;
	return output_normal(uData, b, random_size(bSize));
}

static ssize_t
output_firstbytes(void *uData, const char *b, const size_t bSize)
{
	static gboolean first = TRUE;

	if (!first) {
		g_printerr("# %"G_GSIZE_FORMAT" bytes received pointer=%p ... +++ STOP WANTED +++\n", bSize, b);
		return 0;
	}
	first = 0;
	return output_partial(uData, b, bSize);
}

static ssize_t
output_fail(void *uData, const char *b, const size_t bSize)
{
	if (!bSize)
		return 0;

	size_t s, max;
	s = random() % bSize;
	max = bSize/10;
	if (s < max) {
		g_printerr("# %"G_GSIZE_FORMAT" bytes received pointer=%p"
			" +++ FAILED +++ (%"G_GSIZE_FORMAT" %"G_GSIZE_FORMAT")\n",
			bSize, b, s, max);
		return -1;
	}
	
	return output_partial(uData, b, bSize);
}

static void
main_title(const gchar *fmt, ...)
{
	size_t msg_len;
	gchar *msg;
	va_list va;

	va_start(va, fmt);
	msg = g_strdup_vprintf(fmt, va);
	va_end(va);

	assert(msg);
	msg_len = strlen(msg);
	g_printerr("\n################################################################################\n");
	g_printerr("# %s\n", msg);
	g_printerr("################################################################################\n\n");
	g_free(msg);
	
}

int main (int argc, char ** args)
{
	int rc = -1;
	MD5_CTX md5_ctx;

	gs_error_t *err = NULL;
	gs_status_t status;
	gs_download_info_t dl_info;
	gs_grid_storage_t *client;
	gs_container_t *container;
	char *ns, *cName, *cPath;

	close(0);
	openlog("gs_test_get", LOG_PID, LOG_LOCAL7);
	if (log4c_init())
		g_error("log4c_init() error\n");
	if (argc != 6)
		g_error("Usage: %s NS CONTAINER CONTENT OFFSET SIZE\n", args[0]);

	ns = args[1];
	cName = args[2];
	cPath = args[3];
	memset( &dl_info, 0x00, sizeof(dl_info) );
	dl_info.offset = g_ascii_strtoll(args[4], NULL, 10 );
	dl_info.size = g_ascii_strtoll(args[5], NULL, 10 );

	main_title("API initiation");
	client = gs_grid_storage_init( ns, &err );
	g_printerr("# gs_grid_storage_init(%s) %d %s\n", ns,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!client || err!=NULL)
		goto error_client;

	main_title("Timeout settings");
	status = gs_grid_storage_set_timeout( client, 0, 4000, &err);
	g_printerr("# gs_grid_storage_set_timeout(%s,%d,%d) %d %s\n", ns, 0, 4000,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!status || err!=NULL)
		goto error_timeout;
	
	main_title("Container location");
	container = gs_get_storage_container( client, cName, 1, &err );
	g_printerr("# gs_get_storage_container(%s,%s) %d %s\n",
		ns, cName, gs_error_get_code(err), gs_error_get_message(err));
	if (!container || err!=NULL)
		goto error_container;

	/* Try some GET cases */
	main_title("download NORMAL");
	bzero(&md5_ctx, sizeof(md5_ctx));
	MD5_Init(&md5_ctx);
	dl_info.user_data = &md5_ctx;
	dl_info.writer = &output_normal;
	status = gs_download_content_by_name(container, cPath, &dl_info, &err );
	g_printerr("# gs_download_content_by_name(%s,%s,%s,offset=%"G_GINT64_FORMAT",size=%"G_GINT64_FORMAT",TOTAL) %d %s\n",
		ns, cName, cPath, dl_info.offset, dl_info.size,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!status || err!=NULL)
		goto error_get;
	md5_dump_hex(&md5_ctx, "TOTAL");
	
	bzero(&md5_ctx, sizeof(md5_ctx));
	MD5_Init(&md5_ctx);

	main_title("download by parts");
	bzero(&md5_ctx, sizeof(md5_ctx));
	MD5_Init(&md5_ctx);
	dl_info.user_data = &md5_ctx;
	dl_info.writer = &output_partial;
	status = gs_download_content_by_name(container, cPath, &dl_info, &err );
	g_printerr("# gs_download_content_by_name(%s,%s,%s,offset=%"G_GINT64_FORMAT",size=%"G_GINT64_FORMAT",PARTIAL) %d %s\n",
		ns, cName, cPath, dl_info.offset, dl_info.size,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!status || err!=NULL)
		goto error_get;
	md5_dump_hex(&md5_ctx,"PARTS");

	main_title("download the first bytes");
	bzero(&md5_ctx, sizeof(md5_ctx));
	MD5_Init(&md5_ctx);
	dl_info.user_data = &md5_ctx;
	dl_info.writer = &output_firstbytes;
	status = gs_download_content_by_name(container, cPath, &dl_info, &err );
	g_printerr("# gs_download_content_by_name(%s,%s,%s,offset=%"G_GINT64_FORMAT",size=%"G_GINT64_FORMAT",FIRST_BYTES) %d %s\n",
		ns, cName, cPath, dl_info.offset, dl_info.size,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!status || err!=NULL)
		goto error_get;

	main_title("download that should fail");
	bzero(&md5_ctx, sizeof(md5_ctx));
	MD5_Init(&md5_ctx);
	dl_info.user_data = &md5_ctx;
	dl_info.writer = &output_fail;
	status = gs_download_content_by_name(container, cPath, &dl_info, &err );
	g_printerr("# gs_download_content_by_name(%s,%s,%s,offset=%"G_GINT64_FORMAT",size=%"G_GINT64_FORMAT",FIRST_BYTES) %d %s\n",
		ns, cName, cPath, dl_info.offset, dl_info.size,
		gs_error_get_code(err), gs_error_get_message(err));
	if (!status)
		goto error_get;
	md5_dump_hex(&md5_ctx,"FAIL");

	main_title("ALL TESTS PASSED");
	rc = 0;

error_get:
	gs_container_free(container);
error_timeout:
error_container:
	gs_grid_storage_free(client);
error_client:
	return rc;
}
