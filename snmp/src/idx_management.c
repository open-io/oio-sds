#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.snmp.manag"
#endif

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <metautils/lib/metautils.h>

#include "idx_management.h"

#define IDX_STORE_PATH "/GRID/common/run/"
#define NEW_EXT ".new"

static int
read_known_service_from_file(GArray *known_services, const char *file_name, GError **error) {
	int fd;
	guint8 buff[256];
	ssize_t r;
	GByteArray *data = NULL;
	int service_number = 0;
	struct grid_service_data *services = NULL;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		GSETERROR(error, "Failed to open file [%s] : %s", file_name, strerror(errno));
		return(0);
	}

	data = g_byte_array_new();

	while ((r = read(fd, buff, sizeof(buff))) > 0) {
		data = g_byte_array_append(data, buff, r);
	}

	metautils_pclose(&fd);

	if (r < 0) {
		GSETERROR(error, "Failed to read data from file [%s] : %s", file_name, strerror(errno));
		g_byte_array_free(data, TRUE);
		return(0);
	}

	service_number = ( data->len * sizeof(guint8) ) / sizeof(struct grid_service_data);
	services = (struct grid_service_data *)g_byte_array_free(data, FALSE);

	known_services = g_array_append_vals(known_services, services, service_number);

	g_free(services);

	return(1);
}

static int
save_known_service_to_file(GArray *known_services, const char *file_name, GError **error) {
	char new_file_name[strlen(file_name) + strlen(NEW_EXT) + 1];
	int fd;
	guint i;
	ssize_t written;
	ssize_t wl;
	struct grid_service_data *service;

	memset(new_file_name, '\0', strlen(file_name) + strlen(NEW_EXT) + 1);

	sprintf(new_file_name, "%s%s", file_name, NEW_EXT);

	fd = open(new_file_name, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		GSETERROR(error, "Failed to open file [%s] : %s", new_file_name, strerror(errno));
		return(0);
	}

	for (i = 0; i < known_services->len; i++) {
		service = &g_array_index(known_services, struct grid_service_data, i);

		written = 0;

		while(written < (int)sizeof(struct grid_service_data)) {
			wl = write(fd, service + written, sizeof(struct grid_service_data) - written);
			if (wl < 0) {
				GSETERROR(error, "Failed to write to file [%s] : %s", new_file_name, strerror(errno));
				metautils_pclose(&fd);
				return(0);
			}

			written += wl;
		}

	}

	metautils_pclose(&fd);

	if (0 > rename(new_file_name, file_name)) {
		GSETERROR(error, "Failed to move file [%s] to [%s] : %s", new_file_name, file_name, strerror(errno));
		return(0);
	}

	return(1);
}

int get_idx_of_service(const char *service_type, struct grid_service_data *service, GError **error) {
	char file_name[strlen(IDX_STORE_PATH) + strlen(service_type) +1];
	struct stat file_stat;
	int rc;
	GArray *known_services = NULL;
	struct grid_service_data *known_service = NULL;
	gboolean idx_found = FALSE;
	int last_idx = 0;

	memset(file_name, '\0', strlen(IDX_STORE_PATH) + strlen(service_type) +1);
	memset(&file_stat, 0, sizeof(struct stat));

	sprintf(file_name, "%s%s_snmp_idx.dat", IDX_STORE_PATH, service_type);

	rc = stat(file_name, &file_stat);
	if (rc < 0 && errno != ENOENT && errno != ENOTDIR) {
		GSETERROR(error, "Failed to stat file [%s] : %s", file_name, strerror(errno));
		return(0);
	}

	known_services = g_array_new(TRUE, TRUE, sizeof(struct grid_service_data));

	if (rc < 0) {

		service->idx = 0;
		g_array_append_val(known_services, *service);

		if (!save_known_service_to_file(known_services, file_name, error)) {
			GSETERROR(error, "Failed to save known services to file [%s]", file_name);
			g_array_free(known_services, TRUE);
			return(0);
		}
	} else {
		guint i;

		read_known_service_from_file(known_services, file_name, error);

		for (i = 0; i < known_services->len; i++) {
			known_service = &g_array_index(known_services, struct grid_service_data, i);

			if (0 == g_ascii_strcasecmp(service->desc, known_service->desc)) {
				service->idx = known_service->idx;
				idx_found = TRUE;
				break;
			} else if (known_service->idx > last_idx)
				last_idx = known_service->idx;
		}

		if (!idx_found) {	
			service->idx = last_idx+1;
			g_array_append_val(known_services, *service);

			if (!save_known_service_to_file(known_services, file_name, error)) {
				GSETERROR(error, "Failed to save known sevices to file [%s]", file_name);
				g_array_free(known_services, TRUE);
				return(0);
			}
		}
	}

	g_array_free(known_services, TRUE);

	return(1); 
}
