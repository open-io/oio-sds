/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.client.bench.put_content_scenario"
#endif

#include <glib.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "gs_bench.h"
#include "grid_client.h"
#include "metautils.h"

static ssize_t
input_file_feeder(void *uData, char *b, size_t bSize)
{
	if (!b || !bSize) {
		ERROR("API : invalid buffer for reading");
		return -1;
	}

	memcpy(b, uData, bSize);

	return bSize;
}

static ssize_t
random_feeder(void *uData, char *b, size_t bSize)
{
	(void)uData;

	if (!b || !bSize) {
		ERROR("API : invalid buffer for reading");
		return -1;
	}

	int random_fd = open("/dev/urandom", O_RDONLY);
	if (random_fd == -1) {
		GRID_ERROR("Error opening /dev/urandom: %s", strerror(errno));
		return 0;
	}
	read(random_fd, b, bSize);
	close(random_fd);
	//read(*((gint8*)uData), b, bSize);
	return bSize;
}

gboolean put_content_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len)
{
	gchar content_name[64];
	gchar container_name[64];
	gs_status_t upload_status;
	gs_error_t * error = NULL;
	gint *p_content_size = NULL;
	char *input_file_name = NULL;
	char *input_buf = NULL;
	int input_fd;
	ssize_t read_size = 0;
	gs_container_t *container = NULL;

	g_assert(sdata);
	g_assert(result_str);

	/* The first option is always the use_cache flag. Here it is unused. */
	//gboolean *use_cache = sdata->options->data;

	if (sdata->options->next == NULL || sdata->options->next->data == NULL) {
		ERROR("put_content_scenario needs a content size (integer) as second option");
		return FALSE;
	}
	p_content_size = sdata->options->next->data;

	if (sdata->options->next->next == NULL || sdata->options->next->next->data == NULL) {
		INFO("put_content_scenario: no input file name given, using /dev/urandom for content generation.");
	} else {
		input_file_name = sdata->options->next->next->data;
		input_fd = open(input_file_name, O_RDONLY);
		if (input_fd == -1) {
			GRID_ERROR("Error opening [%s]: %s", input_file_name, strerror(errno));
			return FALSE;
		}
		input_buf = malloc(*p_content_size);
		do {
			read_size += read(input_fd, input_buf + read_size, *p_content_size - read_size);
			lseek(input_fd, 0, SEEK_SET);
		} while (read_size < *p_content_size);
		close(input_fd);
	}

	/* Get container name from generator or use a fixed name if no generator was given */
	if (sdata->container_generator != NULL)
		sdata->container_generator(container_name, sizeof(container_name), sdata->callback_userdata);
	else
		g_strlcpy(container_name, "BENCHCONTAINER", sizeof(container_name));
	container = gs_get_storage_container(sdata->gs, container_name, NULL, TRUE, &error);
	if (container == NULL) {
		ERROR("Failed to get container [%s] : %s", container_name, gs_error_get_message(error));
		gs_error_free(error);
		if (input_buf)
			free(input_buf);
		return FALSE;
	}

	sdata->content_generator(content_name, sizeof(content_name), sdata->callback_userdata);
	g_snprintf(result_str, result_str_len, "PUT %s/%s/%s", gs_get_namespace(sdata->gs), container_name, content_name);

	if (input_file_name)
		upload_status = gs_upload_content_v2(container, content_name, *p_content_size, input_file_feeder, input_buf, "stgpol", "machin=truc", &error);
	else
		upload_status = gs_upload_content_v2(container, content_name, *p_content_size, random_feeder, NULL, "stgpol", "machin=truc", &error);

	gs_container_free(container);

	if (upload_status != GS_OK) {
		ERROR("put content [%s] failed with error: %s", content_name, gs_error_get_message(error));
		gs_error_free(error);
		if (input_buf)
			free(input_buf);
		return FALSE;
	}

	if (input_buf)
		free(input_buf);

	return TRUE;
}

