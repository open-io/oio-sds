#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent"
#endif

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./config.h"

static gboolean is_running = TRUE;
static gchar hostname[1024] = {0,0};
static int fd_out = -1;

static void
sighandler_config(int s)
{
	switch (s) {
	case SIGUSR1:
	case SIGUSR2:
	case SIGCHLD:
		break;
	case SIGPIPE:
		metautils_pclose(&fd_out);
		break;
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		is_running = FALSE;
		break;
	}
	signal(s, sighandler_config);
}

static inline void
set_sighandlers(void)
{
	signal(SIGTERM, sighandler_config);
	signal(SIGQUIT, sighandler_config);
	signal(SIGINT,  sighandler_config);
	signal(SIGPIPE, sighandler_config);
	signal(SIGUSR1, sighandler_config);
	signal(SIGUSR2, sighandler_config);
	signal(SIGCHLD, sighandler_config);
}

static ne_request*
_build_request(ne_session *http_session, const gchar *path_url)
{
	ne_request *http_request;

	http_request = ne_request_create(http_session, "GET", path_url);
	ne_add_request_header(http_request, "User-Agent", "HoneyComb-gridagent-httpconf");
	return http_request;
}

static int
read_to_stream(void *userdata, const char *buf, size_t len)
{
	size_t really_written;
	FILE *stream_out;
	
	if (!len)
		return 0;
	stream_out = userdata;
	really_written = fwrite(buf, 1, len, stream_out);
	return !(really_written == len);
}

static int
read_to_gba(void *userdata, const char *buf, size_t len)
{
	GByteArray *gba;

	if (len) {
		gba = userdata;
		g_byte_array_append(gba, (const guint8*)buf, len);
	}
	return 0;
}

static GByteArray*
_download_to_gba(ne_session *session, const gchar *path_url, GError **error)
{
	GByteArray *gba;
	ne_request *http_request;

	DEBUG("About to download [%s] into a memory buffer", path_url);

	gba = g_byte_array_new();
	http_request = _build_request(session, path_url);
	ne_add_response_body_reader(http_request, ne_accept_2xx, read_to_gba, gba);

	switch (ne_request_dispatch(http_request)) {
	case NE_OK:
		if (ne_get_status(http_request)->klass != 2) {
			GSETERROR (error, "Failed to download '%s': %s", path_url, ne_get_error(session));
			g_byte_array_free(gba, TRUE);
			gba = NULL;
		}
		break;
	case NE_AUTH:
	case NE_CONNECT:
	case NE_TIMEOUT:
	case NE_ERROR:
	default:
		GSETERROR(error,"Failed download '%s': %s", path_url, ne_get_error(session));
		g_byte_array_free(gba, TRUE);
		gba = NULL;
		break;
	}

	ne_request_destroy(http_request);
	return gba;
}

static GByteArray*
download_file_services(ne_session *session, GError **error)
{
	gchar path_url[1024];

	g_snprintf(path_url, sizeof(path_url), "%s/%s/%s", gridconf_distant_basedir, hostname, gridconf_distant_listsrv_basename);
	return _download_to_gba(session, path_url, error);
}

static GByteArray*
download_file_list(ne_session *session, GError **error)
{
	gchar path_url[1024];

	g_snprintf(path_url, sizeof(path_url), "%s/%s/%s", gridconf_distant_basedir, hostname, gridconf_distant_listfiles_basename);
	return _download_to_gba(session, path_url, error);
}

static gboolean
_download_to_file(ne_session *session, const gchar *path_url, const gchar *path_local, GError **error)
{
	gchar *dirname, path_tmp[2048];
	gboolean rc = FALSE;
	int rc_dispatch;
	FILE *stream_out;
	ne_request *http_request;

	g_snprintf(path_tmp, sizeof(path_tmp), "%s.%d.%ld", path_local, getpid(), time(0));
	DEBUG("About to download [%s] into [%s]", path_url, path_tmp);

	/*create the destination*/
	dirname = g_path_get_dirname(path_tmp);
	if (!dirname) {
		GSETERROR(error,"Failed to extract the dirname of '%s'", path_tmp);
		return FALSE;
	}
	if (-1 == g_mkdir_with_parents(dirname,0755)) {
		g_free(dirname);
		GSETERROR(error,"Failed to create the dirname of '%s' : %s", path_tmp, strerror(errno));
		return FALSE;
	}
	g_free(dirname);
	
	/*open the destination*/
	stream_out = fopen(path_tmp,"w");
	if (!stream_out) {
		GSETERROR(error,"Failed to open '%s' in write mode : %s", path_local, strerror(errno));
		return FALSE;
	}
	
	http_request = _build_request(session, path_url);
	ne_add_response_body_reader(http_request, ne_accept_2xx, read_to_stream, stream_out);

	switch (rc_dispatch = ne_request_dispatch(http_request)) {
	case NE_OK:
		if (ne_get_status(http_request)->klass != 2) {
			GSETERROR (error, "Failed to download '%s': %s", path_url, ne_get_error(session));
			goto label_error;
		}
		break;
	case NE_AUTH:
	case NE_CONNECT:
	case NE_TIMEOUT:
	case NE_ERROR:
		GSETERROR(error,"Failed download '%s' (rc=%d) : %s", path_url, rc_dispatch, ne_get_error(session));
		goto label_error;
	}
	
	if (-1 == g_rename(path_tmp, path_local)) {
		GSETERROR(error,"Failed to commit the temporary download file '%s' : %s", path_tmp, strerror(errno));
		goto label_error;
	}
	
	g_chmod(path_local,0644);
	DEBUG("Download of '%s' succeeded", path_url);
	rc = TRUE;
label_error:
	ne_request_destroy(http_request);
	fclose(stream_out);
	if (g_file_test(path_tmp, G_FILE_TEST_IS_REGULAR))
		g_remove(path_tmp);
	return rc;
}

static gboolean
download_each_configuration_file(ne_session *http_session, GByteArray *gba, GError **error)
{
	gboolean rc = FALSE;
	GRegex *path_validator;
	gchar path_uri[1024], path_local[2048];
	gchar **lines, **pl, *line;
	
	DEBUG("About to download all the configuration files");
	memset(path_uri, 0x00, sizeof(path_uri));
	memset(path_local, 0x00, sizeof(path_local));
	path_validator = g_regex_new("/GRID/([^/]+|[^/]+/[^/]+)/conf/[^/]+", 0, 0, error);
	if (!path_validator) {
		GSETERROR(error,"Abnormal condition, check your GLib2 version");
		return FALSE;
	}
	
	/*Split the buffer into a sequence of '\n'-temrinated lines*/
	g_byte_array_append(gba, (guint8*)"", 1);
	lines = g_strsplit((gchar*)gba->data, "\n", 0);
	for (pl=lines; is_running && pl && *pl ;pl++) {
		guint line_nb;
		gchar *path_escaped;

		line_nb = pl - lines + 1;
		line = *pl;
		if (!*line) /*empty line*/
			continue;

		/*vaidate the file to downlaod*/
		if (g_strstr_len(line, strlen(line), "..")) {
			WARN("Dangerous path found at line %u", line_nb);
			continue;
		}
		if (!g_regex_match(path_validator, line, 0, NULL)) {
			WARN("Invalid path found at line %u", line_nb);
			continue;
		}
	
		/*map the paths and download now!*/
		path_escaped = g_uri_escape_string(line, "", FALSE);
		g_snprintf(path_uri, sizeof(path_uri), "%s/%s/%s", gridconf_distant_basedir, hostname, line);
		g_free(path_escaped);
		g_strlcpy(path_local, line, sizeof(path_local)-1);
		if (!_download_to_file(http_session, path_uri, path_local, error)) {
			GSETERROR(error,"Failed to download '%s' in local '%s' (at line %d)",
				path_uri, path_local, line_nb);
			goto label_error;
		}
	}

	DEBUG("All the files have been downloaded");
	rc = TRUE;
label_error:
	if (lines)
		g_strfreev(lines);
	g_regex_unref(path_validator);
	return rc;
}

static gboolean
dump_gba(GByteArray *gba, int fd, GError **error)
{
	ssize_t wrc;
	guint written, wrc_u;

	if (!gba) {
		GSETERROR(error,"No data has been received");
		return FALSE;
	}

	written = 0;
	while (is_running && written < gba->len) {
		wrc = write(fd, gba->data+written, gba->len-written);
		if (wrc<0) {
			GSETERROR(error,"write error : %s", strerror(errno));
			return FALSE;
		}
		wrc_u = wrc;
		written += wrc_u;
	}
	return TRUE;
}

int
main_http_config(const gchar *hn, int fd)
{
	int rc;
	GError *error = NULL;
	GByteArray *gba_services = NULL;
	GByteArray *gba_files = NULL;
	ne_session *http_session;

	set_sighandlers();
	fd_out = fd;

	DEBUG("Starting a new configuration process");
	rc = -1;

	bzero(hostname, sizeof(hostname));
	if (!hn)
		gethostname(hostname,sizeof(hostname));
	else
		g_strlcpy(hostname, hn, sizeof(hostname)-1);

	http_session = ne_session_create("http", gridconf_host, gridconf_port);
	ne_set_connect_timeout(http_session, 1);
	ne_set_read_timeout(http_session, 4);

	/*downlaod each file*/
	if (!is_running)
		goto label_error;

	gba_files = download_file_list(http_session, &error);
	if (!gba_files) {
		ERROR("Failed to get the files list file : %s", gerror_get_message(error));
		goto label_error;
	}
	
	if (!is_running)
		goto label_error;
	
	gba_services = download_file_services(http_session, &error);
	if (!gba_services) {
		ERROR("Failed to get the services definition file : %s", gerror_get_message(error));
		goto label_error;
	}
	
	if (!is_running)
		goto label_error;
	
	if (!download_each_configuration_file(http_session, gba_files, &error)) {
		ERROR("Failed to download a configuration file : %s", gerror_get_message(error));
		goto label_error;
	}

	if (!is_running)
		goto label_error;

	if (!dump_gba(gba_services, fd_out, &error)) {
		ERROR("Failed to dump the configuration to fd=%d : %s", fd_out, gerror_get_message(error));
		goto label_error;
	}

	rc = 0;
label_error:
	ne_session_destroy(http_session);
	metautils_pclose(&fd_out);
	if (gba_services)
		g_byte_array_free(gba_services, TRUE);
	if (gba_files)
		g_byte_array_free(gba_files, TRUE);
	DEBUG("http_config child pid=%d exiting with rc=%d", getpid(), rc);
	return rc;
}

