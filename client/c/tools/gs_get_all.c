#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.ls"
#endif

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

#include "../lib/gs_internals.h"
#include "./gs_tools.h"

char *optarg;
int optind, opterr, optopt;

char *meta0_url = NULL;
char *container_name = NULL;
int flag_verbose = 0;
int flag_quiet = 0;
int flag_prop = 0;

static char *base_dir = NULL;
static int flag_help = 0;
static int nb_elements = 0;

static void
help(void)
{
	g_printerr("usage: gs_ls [OPTIONS...]\n");
	g_printerr("Description:\n");
	g_printerr("\tGridStorage container absorber utility\n");
	g_printerr("\tList the contents available in a container and downloads them in a local directory\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -q : quiet mode, no output\n");
	g_printerr("\t -v : increase the verbosity\n");
	g_printerr("\t -p : also download container and content properties\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
	g_printerr("\t -C <TOKEN> : the name of the local directory\n");
}


static int
parse_opt(int argc, char **args)
{
	int opt;

	while ((opt = getopt(argc, args, "qvhpm:d:C:")) != -1) {
		switch (opt) {

		case 'h':
			flag_help = ~0;
			break;
		case 'q':
			flag_quiet = ~0;
			break;
		case 'v':
			flag_verbose++;
			break;
		case 'p':
			flag_prop = ~0;
			break;

		case 'm':
			/*meta0 url */
			IGNORE_ARG('m');
			if (meta0_url)
				free(meta0_url);
			meta0_url = strdup(optarg);
			break;

		case 'd':
			/*container info */
			IGNORE_ARG('d');
			if (container_name)
				free(container_name);
			container_name = strdup(optarg);
			break;

		case 'C':
			/*destination download directory */
			IGNORE_ARG('C');
			if (base_dir)
				free(base_dir);
			base_dir = strdup(optarg);
			break;

		case '?':
		default:
			PRINT_ERROR("unexpected option %c (%s)\n", optopt, strerror(opterr));
			return 0;
		}
	}
	return 1;
}


static int
conf_check(void)
{
	if (flag_quiet)
		flag_verbose = 0;

	if (!base_dir) {
		PRINT_ERROR("no destination directory (use -C option)");
		return 0;
	}

	return 1;
}


static ssize_t
write_to_fd(void *uData, const char *b, const size_t bSize)
{
	int fd;
	ssize_t nbW;

	fd = *((int *) uData);
	nbW = -1;

	if (b && bSize > 0) {
		nbW = write(fd, b, bSize);
		if (nbW > 0) {
			PRINT_DEBUG("wrote %"G_GSSIZE_FORMAT" bytes among %"G_GSIZE_FORMAT" (from %p) in fd=%d\n", nbW , bSize, b, fd);
		}
		else {
			PRINT_ERROR("download error fd=%d : %s\n", fd, strerror(errno));
			sleep(3600);
		}
	}
	else {
		PRINT_ERROR("Failed to write a downloaded file : %s\n", strerror(errno));
	}
	return nbW;
}


static gboolean
dump_container_properties(gs_container_t * container)
{
	GSList *properties = NULL, *list = NULL;
        struct metacnx_ctx_s cnx;
	gchar path[1024];
	int output_fd;
	GError *error = NULL;

	metacnx_clear(&cnx);
        if (!metacnx_init_with_addr(&cnx, &(container->meta2_addr), &error)) {
		PRINT_ERROR("Invalid META2 address : %s", error->message);
		g_clear_error(&error);
               	return FALSE; 
        }

	/* Change default timeout */
	cnx.timeout.req = 10000;
	cnx.timeout.cnx = 10000;

	if (!meta2_remote_list_all_container_properties(&cnx, container->cID, &properties, &error)) {
		PRINT_ERROR("Failed to list container properties : %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}
        metacnx_close(&cnx);
        metacnx_clear(&cnx);

	/* open container properties file */
	memset(path, '\0', sizeof(path));
	g_snprintf(path, sizeof(path), "%s/container.properties", base_dir);
	output_fd = open(path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (output_fd < 0) {
		PRINT_ERROR("Failed to open [%s] as the container properties target : %s\n", path, strerror(errno));
		return FALSE;
	}
	/*  Print container properties to file */
	if (g_slist_length(properties)>0) {
		for (list = properties; list && list->data; list = list->next) {
			gchar *txt = g_strdup_printf("%s\n", (char*)list->data);
			write_to_fd(&output_fd, txt, strlen(txt));
			g_free(txt);
		}
	}
	/*then adjust the file rights */
	fchmod(output_fd, S_IRGRP | S_IRUSR | S_IWUSR);
	close(output_fd);

	g_slist_foreach(properties, gslist_free_element, g_free);
	g_slist_free(properties);

	return TRUE;
}


static gboolean
dump_content_properties(gs_content_t * content)
{
	gs_content_info_t *info = NULL;
	gs_container_t *container = NULL;
	GSList *properties = NULL, *list = NULL;
        struct metacnx_ctx_s cnx;
	gchar path[1024];
	int output_fd;
	GError *error = NULL;

	info = &(content->info);
	if (info == NULL) {
		PRINT_ERROR("Info in content is NULL");
		return FALSE;
	}
	container = info->container;
	if (container == NULL) {
		PRINT_ERROR("Container in content is NULL");
		return FALSE;
	}

        metacnx_clear(&cnx);
        if (!metacnx_init_with_addr(&cnx, &(container->meta2_addr), &error)) {
		PRINT_ERROR("Invalid META2 address : %s", error->message);
		g_clear_error(&error);
               	return FALSE;
        }

	/* Change default timeout */
	cnx.timeout.req = 10000;
	cnx.timeout.cnx = 10000;

	if (!meta2_remote_list_all_content_properties(&cnx, container->cID, info->path, &properties, &error)) {
		PRINT_ERROR("Failed to list content properties : %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}
        metacnx_close(&cnx);
        metacnx_clear(&cnx);

	/* open content properties file */
	memset(path, '\0', sizeof(path));
	g_snprintf(path, sizeof(path), "%s/%s.properties", base_dir, info->path);
	output_fd = open(path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (output_fd < 0) {
		PRINT_ERROR("Failed to open [%s] as the content properties target : %s\n", path, strerror(errno));
		return FALSE;
	}
	/* Print content properties to file */
	if (g_slist_length(properties)>0) {
		for (list = properties; list && list->data; list = list->next) {
			gchar *txt = g_strdup_printf("%s\n", (char*)list->data);
			write_to_fd(&output_fd, txt, strlen(txt));
			g_free(txt);
		}
	}
	/*then adjust the file rights */
	fchmod(output_fd, S_IRGRP | S_IRUSR | S_IWUSR);
	close(output_fd);

	g_slist_foreach(properties, gslist_free_element, g_free);
	g_slist_free(properties);

	return TRUE;
}


static int
my_content_filter(gs_content_t * content, void *user_data)
{
	char original_path[1024], path[1024], *ptr;
	int output_fd;
	gs_error_t *err = NULL;
	static gs_content_info_t info;
	static gs_container_info_t container_info;
	gs_download_info_t dl_info;

	(void) user_data;

	if (!content) {
		PRINT_ERROR("Invalid content received\n");
		return -1;
	}
	if (!gs_content_get_info(content, &info, &err)
	    || !gs_container_get_info(info.container, &container_info, &err)) {
		PRINT_ERROR("cannot read the information about a content (%s)\n", gs_error_get_message(err));
		gs_error_free(err);
		return -1;
	}

	/*purify the path */
	g_strlcpy(original_path, info.path, sizeof(original_path));
	for (ptr = original_path; *ptr; ptr++) {
		register int c;
		c = *ptr;
		if (c == '/' || g_ascii_isspace(c))
			*ptr = '_';
	}

	PRINT_DEBUG("About to download [grid://%s/%s/%s] (%"G_GINT64_FORMAT" bytes) in [%s/%s]\n",
	    meta0_url, container_info.name, info.path, info.size, base_dir, original_path);

	/*open the destination file */
	g_snprintf(path, sizeof(path), "%s/%s", base_dir, original_path);
	output_fd = open(path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (output_fd < 0) {
		PRINT_ERROR("Failed to open [%s] as the download target : %s\n", path, strerror(errno));
		return -1;
	}

	/*download the content */
	memset(&dl_info, 0x00, sizeof(dl_info));
	dl_info.offset = 0;
	dl_info.size = 0;
	dl_info.writer = write_to_fd;
	dl_info.user_data = &output_fd;

	if (GS_OK != gs_download_content(content, &dl_info, &err)) {
		close(output_fd);
		unlink(path);
		if (flag_verbose) {
			PRINT_ERROR("grid storage error: cannot download [grid://%s/%s/%s] in [%s]. Cause:\n\t%s\r\n",
			    meta0_url, container_name, info.path, path, gs_error_get_message(err));
		}
		else {
			PRINT_ERROR("grid storage error: cannot download [grid://%s/%s/%s] in [%s]\n",
			    meta0_url, container_name, info.path, path);
		}
		return -1;
	}

	/*then adjust the file rights and reply the success */
	fchmod(output_fd, S_IRGRP | S_IRUSR | S_IWUSR);
	close(output_fd);
	g_print("download: [grid://%s/%s/%s] in [%s] (%"G_GINT64_FORMAT" bytes)\n", meta0_url, container_name, info.path, path,
	    info.size);
	nb_elements++;

	/* Save content properties */
	if (flag_prop && !dump_content_properties(content))
		return -1;

	return 0;
}


static int
list_container(gs_grid_storage_t * gs, const char *cName)
{
	int rc = -1;
	gs_error_t *err = NULL;
	gs_container_t *container = NULL;

	if (!gs || !cName)
		return -1;

	container = gs_get_storage_container(gs, cName, NULL, 0, &err);
	if (!container) {
		PRINT_ERROR("cannot find %s\n", cName);
		goto exit_label;
	}
	else
		PRINT_DEBUG("%s found\n", cName);

	/* Dump container properties */
	if (flag_prop && !dump_container_properties(container))
		return -1;

	nb_elements = 0;
	if (!gs_list_container(container, NULL, my_content_filter, NULL, &err)) {
		PRINT_ERROR("cannot download all the contents of %s\n", cName);
		goto exit_label;
	}
	else
		PRINT_DEBUG("%s listed\n", cName);

	g_print("total:%i elements in [grid://%s/%s/]\n", nb_elements, meta0_url, cName);

	rc = 0;
      exit_label:
	if (rc < 0) {
		if (err) {
			PRINT_ERROR("Failed to list [%s] cause:\n", cName);
			PRINT_DEBUG("\t%s\n", gs_error_get_message(err));
			gs_error_free(err);
		}
		else {
			PRINT_ERROR("Failed to list [%s]\n", cName);
		}
	}
	gs_container_free(container);
	return rc;
}


int
main(int argc, char **args)
{
	int rc = ~0;
	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = NULL;

	close(0);

	if (!parse_opt(argc, args)) {
		PRINT_ERROR("cannot parse the options, see the help section (--help option)\n");
		return ~0;
	}

	if (flag_help) {
		help();
		return 0;
	}

	if (!conf_check()) {
		PRINT_ERROR("invalid configuration, see the help section (--help option)\n");
		help();
		return ~0;
	}

	if (0 > chdir(base_dir)) {
		PRINT_ERROR("Failed to change the working directory : %s\n", strerror(errno));
		return ~0;
	}

	gs = gs_grid_storage_init(meta0_url, &err);
	if (gs == NULL) {
		if (optind<argc){
			free(meta0_url);
			meta0_url=strtok(args[optind],"/");
			free(container_name);
			container_name=strtok(NULL,"/");
			if(container_name!=NULL){
				gs = gs_grid_storage_init(meta0_url, &err);
				if(!gs){
					PRINT_ERROR("cannot init the GridStorage client\n");
					goto error_gs;
				}
			}
			else{
				PRINT_ERROR("missing options\n");
				help();
				return 0;
			}
		}
		else{
			PRINT_ERROR("missing options\n");
			help();
			return 0;
		}
	}

	if (0 > list_container(gs, container_name)) {
		PRINT_ERROR("cannot list %s in namespace %s\n", container_name, meta0_url);
		goto error_list;
	}

	rc = 0;
      error_list:
	gs_grid_storage_free(gs);
      error_gs:
	if (err)
		gs_error_free(err);
	return rc;
}
