#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.read_message_worker"
#endif

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./io_scheduler.h"
#include "./request_worker.h"
#include "./message.h"
#include "./read_message_worker.h"

int read_message_data_worker(worker_t *worker, GError **error) {
	ssize_t rl = 0;
	message_t *message = NULL;
	worker_data_t *data = NULL;

	TRACE_POSITION();

	g_assert(worker->clean == message_cleanup);
	data = &(worker->data);
	message = (message_t*)data->session;
	g_assert(message != NULL);
	g_assert(message->length > 0);

	if (data->buffer == NULL) {
		data->buffer_size = message->length;
		data->buffer = g_malloc0(data->buffer_size);
	}

	rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
	TRACE2("fd=%d buffer=%p size=%u done=%u + %"G_GSSIZE_FORMAT, data->fd, data->buffer, data->buffer_size, data->done, rl);
	if (rl < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 1;
		GSETERROR(error, "Read of message data failed with error : %s", strerror(errno));
		return 0;
	}

	if (rl == 0 && data->done < data->buffer_size) {
		GSETERROR(error, "Connection closed while reading message");
		return 0;
	}

	data->done += rl;

	/* Check if the message is starting with '\0'.
	 * If yes it propably means that the size was sent on 64 bits.
	 * So we have to read 4 more bytes */
	if (data->done > sizeof(guint32) && ((gchar*)data->buffer)[0] == '\0') {
		data->done -= sizeof(guint32);
		g_memmove(data->buffer, data->buffer+sizeof(guint32), data->done);
		data->size_64 = TRUE;
	}

	if (data->done >= data->buffer_size) {	/* The data of message has been read */

		/* Set message data, and reset buffer */
		message->data = data->buffer;
		data->buffer = NULL;
		data->buffer_size = 0;
		data->done = 0;

		/* branch to next worker */
		worker->func = request_worker;
		worker->clean = message_cleanup;
		return request_worker(worker, error);
	}

	return(1);
}

int read_message_size_worker(worker_t *worker, GError **error) {
	ssize_t rl = 0;
	worker_data_t *data = NULL;

	TRACE_POSITION();

	data = &(worker->data);
	g_assert(data->session == NULL);

	if (data->buffer == NULL) {
		message_t dummy;
		g_assert(data->buffer_size == 0);
		data->done = 0;
		data->buffer_size = sizeof(dummy.length);
		data->buffer = g_malloc0(data->buffer_size);
	}

	rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
	TRACE2("fd=%d buffer=%p size=%u done=%u + %"G_GSSIZE_FORMAT, data->fd, data->buffer, data->buffer_size, data->done, rl);

	if (rl < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 1;
		GSETERROR(error, "Read of message size failed with error : %s", strerror(errno));
		return 0;
	}

	if (rl == 0 && data->done < data->buffer_size) {
		GSETERROR(error, "Connection closed while reading message size");
		return 0;
	}

	data->done += rl;

	if (data->done >= data->buffer_size) {	/* The size of message has been read */

		/* Set message length */
		message_t *message = g_malloc0(sizeof(message_t));
		memcpy(&(message->length), data->buffer, data->buffer_size);
		if (message->length <= 0) {
			GSETERROR(error, "Invalid message size");
			message_clean(message);
			return 0;
		}

		/* reset data */
		g_free(data->buffer);
		data->buffer = NULL;
		data->buffer_size = 0;
		data->done = 0;

		/* branch to next worker */
		worker->data.session = message;
		worker->func = read_message_data_worker;
		worker->clean = message_cleanup;
		return read_message_data_worker(worker, error);
	}

	return(1);
}

