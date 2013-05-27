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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.agent.write_message_worker"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <metautils.h>

#include "agent.h"
#include "io_scheduler.h"
#include "message.h"
#include "write_message_worker.h"

int write_message_worker(worker_t *worker, GError **error) {
	ssize_t wl = 0;
	worker_data_t *data = NULL;
	message_t *message = NULL;

	TRACE_POSITION();

	data = &(worker->data);
	message = (message_t*)data->session;
	worker->clean = message_cleanup;

	TRACE("Writing message of size %d bytes on socket", message->length);

	if (data->buffer == NULL) {
		gint message_length_size = data->size_64 ? sizeof(guint64) : sizeof(message->length);
		data->buffer_size = message_length_size + message->length;
		data->buffer = g_malloc0(data->buffer_size);
		memcpy(data->buffer, &(message->length), message_length_size);
		memcpy(data->buffer + message_length_size, message->data, message->length);
	}

	wl = write(data->fd, data->buffer + data->done, data->buffer_size - data->done);
	if (wl <= 0) {
		GSETERROR(error, "An error occured while writing message : %s", strerror(errno));
		return 0;
	}

	data->done += wl;

	return (data->done < data->buffer_size);
}

