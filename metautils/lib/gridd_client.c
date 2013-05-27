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
# define G_LOG_DOMAIN "grid.client"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <glib.h>

#include "./gridd_client.h"
#include "./hashstr.h"
#include "./metatypes.h"
#include "./metautils.h"
#include "./metautils_internals.h"
#include "./metacomm.h"

#ifndef URL_MAXLEN
# define URL_MAXLEN 32
#endif

enum client_step_e
{
	NONE = 0,
	CONNECTING,
	CONNECTED,
	REQ_SENDING,
	REP_READING_SIZE,
	REP_READING_DATA,
	STATUS_OK,
	STATUS_FAILED
};

struct client_s
{
	gchar orig_url[URL_MAXLEN];

	gchar url[URL_MAXLEN];
	guint nb_redirects;

	int fd;
	enum client_step_e step;
	GByteArray *request;
	guint sent_bytes;

	GTimeVal tv_step;
	GTimeVal tv_start;
	gdouble delay_step;
	gdouble delay_overall;

	guint32 size;
	GByteArray *reply;

	gpointer ctx;
	client_on_reply on_reply;

	GError *error;
	GString *past_url;
	gboolean keepalive;
};

static GError *
socket_get_error(int fd)
{
	int sock_err = sock_get_error(fd);
	return NEWERROR(errno_to_errcode(sock_err), "[errno=%d] %s",
			sock_err, strerror(sock_err));
}

static const gchar *
_status2str(enum client_step_e step)
{
	switch (step) {
		case NONE:
			return "NONE";
		case CONNECTING:
			return "CONNECTING";
		case CONNECTED:
			return "CONNECTED";
		case REQ_SENDING:
			return "REQ_SENDING";
		case REP_READING_SIZE:
			return "REP_READING_SIZE";
		case REP_READING_DATA:
			return "REP_READING_DATA";
		case STATUS_OK:
			return "STATUS_OK";
		case STATUS_FAILED:
			return "STATUS_FAILED";
		default:
			return "???";
	}
}

static int
_connect(const gchar *url, GError **err)
{
	struct sockaddr_storage ss;
	gsize slen;
	int fd;

	GRID_TRACE2("%s(%s)", __FUNCTION__, url);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);
	if (!grid_string_to_sockaddr(url, NULL, (struct sockaddr*)&ss, &slen)) {
		*err = NEWERROR(EINVAL, "no port");
		return -1;
	}

	if (0 > (fd = socket(AF_INET, SOCK_STREAM, 0))) {
		*err = NEWERROR(errno, "socket error (%s)", strerror(errno));
		return -1;
	}

	sock_set_non_blocking(fd, TRUE);
	sock_set_linger(fd, 1, 0);
	sock_set_reuseaddr(fd, TRUE);
	sock_set_nodelay(fd, TRUE);

	if (0 > connect(fd, (struct sockaddr*)&ss, slen)) {
		if (errno != 0 && errno != EINPROGRESS) {
			*err = NEWERROR(errno, "connect error (%s)", strerror(errno));
			close(fd);
			return -1;
		}
	}

	*err = NULL;
	return fd;
}

static GError*
_client_connect(struct client_s *client)
{
	GError *err = NULL;
	client->fd = _connect(client->url, &err);
	g_get_current_time(&(client->tv_step));

	if (client->fd < 0) {
		g_assert(err != NULL);
		g_prefix_error(&err, "Connect error: ");
		return err;
	}

	UTILS_ASSERT(err == NULL);
	client->step = CONNECTING;
	return NULL;
}

static void
_client_trace(const gchar *tag, struct client_s *client)
{
	if (client->reply && client->reply->len >= 4) {
		GRID_TRACE2("Client %s fd=%d ka=%d step=%d/%s size=%"G_GUINT32_FORMAT" read=%u [%02X%02X%02X%02X...]",
				tag, client->fd, client->keepalive, client->step, _status2str(client->step),
				client->size,
				client->reply->len,
				client->reply->data[0], client->reply->data[1],
				client->reply->data[2], client->reply->data[3]);
	}
	else {
		GRID_TRACE2("Client %s fd=%d ka=%d step=%d/%s size=%"G_GUINT32_FORMAT" read=%u",
				tag, client->fd, client->keepalive, client->step, _status2str(client->step),
				client->size, 0);
	}
}

static inline int
_client_to_pollfd(struct client_s *client, struct pollfd *pfd)
{
	int interest;

	if (!(interest = gridd_client_interest(client)))
		return 0;

	pfd->fd = client->fd;
	pfd->events = 0;
	pfd->revents = 0;
	if (interest & CLIENT_WR)
		pfd->events = POLLOUT;
	if (interest & CLIENT_RD)
		pfd->events = POLLIN;
	return 1;
}

static void
_client_reset_request(struct client_s *client)
{
	if (client->request)
		g_byte_array_unref(client->request);
	client->request = NULL;
	client->ctx = NULL;
	client->on_reply = NULL;
	client->sent_bytes = 0;
	client->nb_redirects = 0;
}

static void
_client_reset_reply(struct client_s *client)
{
	client->size = 0;
	if (!client->reply)
		client->reply = g_byte_array_new();
	else if (client->reply->len > 0)
		g_byte_array_set_size(client->reply, 0);
}

static void
_client_reset_cnx(struct client_s *client)
{
	if (client->fd >= 0) {
		close(client->fd);
		client->fd = -1;
	}
	client->step = NONE;
}

static void
_client_reset_target(struct client_s *client)
{
	memset(client->url, 0, sizeof(client->url));
	memset(client->orig_url, 0, sizeof(client->orig_url));
}

static void
_client_reset_error(struct client_s *client)
{
	if (client->error)
		g_clear_error(&(client->error));
}

static void
_client_expire(struct client_s *c, GTimeVal *now)
{
	if (gridd_client_finished(c))
		return;
	if (gridd_client_expired(c, now)) {
		_client_reset_cnx(c);
		c->error = NEWERROR(0, "Timeout");
		c->step = STATUS_FAILED;
	}
}

static void
_clients_expire(struct client_s **clients, GTimeVal *now)
{
	while (*clients)
		_client_expire(*(clients++), now);
}

/* ------------------------------------------------------------------------- */

static gboolean
_client_looped(struct client_s *client, const gchar *url)
{
	gboolean rc;
	gchar *start, *end;

	start = client->past_url->str;
	while (start && *start) {
		if (!(end = strchr(start, '|'))) /* EOL */
			return !g_ascii_strcasecmp(url, start);
		*end = '\0';
		rc = !g_ascii_strcasecmp(url, start);
		*end = '|';
		if (rc)
			return TRUE;
		start = end+1;
	}
	return FALSE;
}

static GError *
_client_manage_reply(struct client_s *client, MESSAGE reply)
{
	GError *err;
	gint status = 0;
	gchar *message = NULL;

	if (!metaXClient_reply_simple(reply, &status, &message, NULL))
		return NEWERROR(500, "Invalid reply");

	GRID_TRACE2("%s(fd=%d,url=%s,%d,%s)", __FUNCTION__,
			client->fd, client->url, status, message);
	switch (status / 100) {
		case 0:
			err = NEWERROR(status, "net error: %s", message);
			g_free(message);
			close(client->fd);
			client->fd = -1;
			client->step = STATUS_FAILED;
			return err;
		case 1: /* Informational reply :  */
			g_get_current_time(&(client->tv_step));
			client->step = REP_READING_SIZE;
			g_free(message);
			return NULL;
		case 2:
			g_get_current_time(&(client->tv_step));
			client->step = (status==200) ? STATUS_OK : REP_READING_SIZE;
			if (client->step == STATUS_OK) {
				if (!client->keepalive) {
					GRID_TRACE2("Closing because of no Keepalive set");
					close(client->fd);
					client->fd = -1;
				}
			}
			g_free(message);
			if (client->on_reply) {
				if (!client->on_reply(client->ctx, reply))
					return NEWERROR(500, "Handler error");
			}
			return NULL;
		case 3: /* redirection */
			if (status == CODE_REDIRECT) {
				/* Reset the context */
				_client_reset_reply(client);
				_client_reset_cnx(client);
				client->sent_bytes = 0;

				if ((++ client->nb_redirects) > 7) {
					g_free(message);
					return NEWERROR(CODE_TOOMANY_REDIRECT,
							"Too many redirections");
				}

				/* Save the current URL to avoid looping, and check
				 * for a potential loop */
				g_string_append_c(client->past_url, '|');
				g_string_append(client->past_url, client->url);
				if (_client_looped(client, message)) {
					g_free(message);
					return NEWERROR(CODE_LOOP_REDIRECT,
							"Looping on redirections");
				}

				/* Replace the URL */
				memset(client->url, 0, sizeof(client->url));
				g_strlcpy(client->url, message, sizeof(client->url)-1);
				if (NULL != (err = _client_connect(client))) {
					g_free(message);
					g_prefix_error(&err, "Redirection error: Connect error: ");
					return err;
				}

				g_free(message);
				return NULL;
			}
			/* FALLTHROUGH */
		default: /* all other are considered errors */
			err = NEWERROR(status, "remote error: %s", message);
			g_free(message);
			if (!client->keepalive)
				_client_reset_cnx(client);
			_client_reset_reply(client);
			return err;
	}
}

static GError *
_client_manage_reply_data(struct client_s *client)
{
	gsize s = 0;
	MESSAGE reply = NULL;
	GError *err = NULL;

	s = client->reply->len;

	message_create(&reply, NULL);
	if (!message_unmarshall(reply, client->reply->data, &s, &err)) {
		g_prefix_error(&err, "Decoding error: ");
		(void) message_destroy(reply, NULL);
		return err;
	}

	err = _client_manage_reply(client, reply);
	(void) message_destroy(reply, NULL);
	return err;
}

static GError *
_client_manage_event(struct client_s *client)
{
	ssize_t rc;
	guint8 d[8192];

	switch (client->step) {

		case CONNECTING:
			g_assert(client->fd >= 0);
			client->step = client->request ? REQ_SENDING : CONNECTED;
			return NULL;

		case REQ_SENDING:

			client->step = REQ_SENDING;
			g_get_current_time(&(client->tv_step));
			_client_trace("SENDING", client);

			if (!client->request)
				return NULL;
			_client_reset_reply(client);

			/* Continue to send the request */
			rc = write(client->fd,
					client->request->data + client->sent_bytes,
					client->request->len - client->sent_bytes);

			GRID_TRACE2("Client fd=%d sent rc=%"G_GSSIZE_FORMAT" max=%u",
					client->fd, rc, client->request->len - client->sent_bytes);

			if (rc < 0)
				return (errno == EINTR || errno == EAGAIN) ? NULL :
					NEWERROR(errno, "write error (%s)", strerror(errno));
			if (rc > 0)
				client->sent_bytes += rc;

			if (client->sent_bytes < client->request->len)
				return NULL;

			client->step = REP_READING_SIZE;

		case REP_READING_SIZE:

			client->step = REP_READING_SIZE;
			g_get_current_time(&(client->tv_step));
			_client_trace("READING_SIZE", client);

			if (!client->reply)
				client->reply = g_byte_array_new();

			if (client->reply->len < 4) {
				/* Continue reading the size */
				rc = read(client->fd, d, sizeof(d));
				GRID_TRACE2("Client fd=%d read rc=%"G_GSSIZE_FORMAT,
						client->fd, rc);

				if (rc < 0)
					return (errno == EINTR || errno == EAGAIN) ? NULL :
						NEWERROR(errno, "read error (%s)", strerror(errno));
				if (rc > 0)
					g_byte_array_append(client->reply, d, rc);
			}

			if (client->reply->len < 4) {
				if (!rc)
					return NEWERROR(errno, "EOF!");
				return NULL;
			}

			client->size = g_ntohl(*((guint32*)(client->reply->data)));

		case REP_READING_DATA:

			client->step = REP_READING_DATA;
			g_get_current_time(&(client->tv_step));
			_client_trace("READING_DATA", client);
			rc = 0;

			if (client->reply->len < client->size+4) {
				rc = read(client->fd, d, sizeof(d));
				GRID_TRACE2("Client fd=%d data read rc=%"G_GSSIZE_FORMAT, client->fd, rc);

				if (rc < 0)
					return (errno == EINTR || errno == EAGAIN) ? NULL :
						NEWERROR(errno, "read error (%s)", strerror(errno));

				if (rc > 0)
					g_byte_array_append(client->reply, d, rc);
			}

			if (client->reply->len >= client->size+4) {
				GError *err = _client_manage_reply_data(client);
				if (err) {
					client->step = STATUS_FAILED;
					_client_trace("FAILED", client);
					g_prefix_error(&err, "request failed: ");
					return err;
				}
				else {
					if (client->step != CONNECTING && client->step != STATUS_FAILED
							&& client->step != STATUS_OK) {
						client->reply = g_byte_array_remove_range(client->reply, 0,
								client->size+4);
						client->step = REP_READING_SIZE;
						client->size = 0;
					}
				}
			}
			else if (!rc)
				return NEWERROR(errno, "EOF!");
			return NULL;

		default:
			_client_trace("UNEXPECTED", client);
			g_assert_not_reached();
			return NEWERROR(0, "Invalid state");
	}

	g_assert_not_reached();
	return NEWERROR(0, "BUG unreachable code");
}

static void
_client_react(struct client_s *client)
{
	GError *err = NULL;

retry:
	_client_trace("PRE-EVENT", client);
	if (!(err = _client_manage_event(client))) {
		GRID_TRACE2("Client fd=%d event managed", client->fd);
		if (client->step == REP_READING_SIZE && client->reply
				&& client->reply->len >= 4)
				goto retry;
	}
	else {
		GRID_TRACE("Client fd=%d event error: (%d) %s",
				client->fd, err->code, err->message);
		_client_reset_request(client);
		_client_reset_reply(client);
		_client_reset_cnx(client);
		client->error = err;
		client->step = STATUS_FAILED;
	}
}

/* CONSTRUCTORS ------------------------------------------------------------ */

struct client_s *
gridd_client_create_empty(void)
{
	struct client_s *client;

	client = g_malloc0(sizeof(*client));
	client->fd = -1;
	client->step = NONE;
	client->delay_overall = 300.0;
	client->delay_step = 30.0;
	client->past_url = g_string_new("");

	return client;
}

struct client_s *
gridd_client_create_idle(const gchar *target)
{
	struct client_s *client;

	UTILS_ASSERT(target != NULL);

	client = gridd_client_create_empty();
	g_strlcpy(client->url, target, sizeof(client->url));
	memcpy(client->orig_url, client->url, sizeof(client->url));
	client->step = NONE;

	return client;
}

struct client_s *
gridd_client_create(const gchar *target, GByteArray *req, gpointer ctx,
                client_on_reply cb)
{
	struct client_s *client;

	GRID_TRACE2("%s(%s,[%p,%u],%p,%p", __FUNCTION__, target,
			req?req->data:NULL, req?req->len:0, ctx, cb);
	UTILS_ASSERT(target != NULL);
	UTILS_ASSERT(req != NULL);

	client = gridd_client_create_idle(target);
	client->ctx = ctx;
	client->on_reply = cb;
	client->request = g_byte_array_ref(req);
	return client;
}

struct client_s **
gridd_client_create_many(gchar **targets, GByteArray *req, gpointer ctx,
                client_on_reply cb)
{
	guint i, max;
	struct client_s **clients;

	GRID_TRACE2("%s(%p,[%p,%u],%p,%p", __FUNCTION__, targets,
			req?req->data:NULL, req?req->len:0, ctx, cb);

	UTILS_ASSERT(targets != NULL);
	UTILS_ASSERT(req != NULL);

	max = g_strv_length(targets);
	clients = g_malloc0(sizeof(struct client_s*) * (max+1));

	for (i=0; i<max ;i++)
		clients[i] = gridd_client_create(targets[i], req, ctx, cb);

	GRID_TRACE2("%s %u clients created", __FUNCTION__,
			g_strv_length((gchar**)clients));
	return clients;
}

/* GETTERS ----------------------------------------------------------------- */

const gchar*
gridd_client_url(struct client_s *client)
{
	client->url[ sizeof(client->url)-1 ] = '\0';
	return client->url;
}

int
gridd_client_fd(struct client_s *client)
{
	UTILS_ASSERT(client != NULL);
	return client->fd;
}

int
gridd_client_interest(struct client_s *client)
{
	UTILS_ASSERT(client != NULL);
	switch (client->step) {
		case NONE:
			return 0;
		case CONNECTING:
			return CLIENT_WR;
		case CONNECTED:
			g_assert(!client->request);
			return 0;
		case REQ_SENDING:
			return client->request != NULL ?  CLIENT_WR : 0;
		case REP_READING_SIZE:
			return CLIENT_RD;
		case REP_READING_DATA:
			return CLIENT_RD;
		case STATUS_OK:
		case STATUS_FAILED:
			return 0;
		default:
			g_assert_not_reached();
	}
}

GError *
gridd_client_error(struct client_s *client)
{
	if (!client || !client->error)
		return NULL;
	return NEWERROR(client->error->code, client->error->message);
}

GError *
gridd_clients_error(struct client_s **clients)
{
	struct client_s *c;

	if (!clients)
		return NEWERROR(EINVAL, "NULL clients array");

	for (; (c = *clients) ;clients++) {
		if (c->step != STATUS_OK) {
			GError *e = gridd_client_error(c);
			if (e != NULL)
				return e;
		}
	}

	return NULL;
}

/* DESTRUCTORS ------------------------------------------------------------- */

void
gridd_client_clean(struct client_s *client)
{
	if (!client)
		return;
	_client_reset_reply(client);
	_client_reset_request(client);
	_client_reset_cnx(client);
	_client_reset_target(client);
	_client_reset_error(client);
	if (client->reply)
		g_byte_array_free(client->reply, TRUE);
	if (client->past_url)
		g_string_free(client->past_url, TRUE);
	memset(client, 0, sizeof(*client));
	client->fd = -1;
}

void
gridd_client_free(struct client_s *client)
{
	if (!client)
		return;
	gridd_client_clean(client);
	g_free(client);
}

void
gridd_clients_free(struct client_s **clients)
{
	struct client_s **c;

	if (!clients)
		return;
	for (c=clients; *c ;c++)
		gridd_client_free(*c);
	g_free(clients);
}

/* SETTERS ----------------------------------------------------------------- */

void
gridd_client_set_keepalive(struct client_s *client, gboolean on)
{
	if (!client)
		return;
	client->keepalive = on;
}

void
gridd_client_set_timeout(struct client_s *client, gdouble to_step, gdouble to_overall)
{
	if (client) {
		client->delay_overall = to_overall;
		client->delay_step = to_step;
	}
}

GError*
gridd_client_set_fd(struct client_s *client, int fd)
{
	UTILS_ASSERT(client != NULL);

	switch (client->step) {
		case NONE: /* ok */
			break;
		case CONNECTING:
			if (client->request != NULL)
				return NEWERROR(500, "Request pending");
			/* PASSTHROUGH */
		case CONNECTED: /* ok */
			break;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			return NEWERROR(500, "Request pending");
		case STATUS_OK:
		case STATUS_FAILED:
			/* ok */
			break;
	}

	/* reset any connection and request */
	_client_reset_reply(client);
	_client_reset_request(client);
	_client_reset_cnx(client);
	_client_reset_target(client);

	/* Set the established connection */
	memset(client->orig_url, 0, sizeof(client->orig_url));
	memset(client->url, 0, sizeof(client->url));
	client->fd = fd;
	client->step = CONNECTING; /* CONNECTING instead of CONNECTED helps
								  coping with not really yet connected
								  sockets */

	return NULL;
}

/* TRIGGERS ---------------------------------------------------------------- */

GError*
gridd_client_request(struct client_s *client,
		GByteArray *req, gpointer ctx, client_on_reply cb)
{
	UTILS_ASSERT(client != NULL);

	switch (client->step) {
		case NONE:
		case CONNECTING:
		case CONNECTED:
			if (client->request != NULL)
				return NEWERROR(500, "Request already pending");
			/* ok */
			break;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			return NEWERROR(500, "Request not terminated");
		case STATUS_OK:
		case STATUS_FAILED:
			/* ok */
			break;
	}

	/* if any, reset the last reply */
	_client_reset_reply(client);
	_client_reset_request(client);
	_client_reset_error(client);

	/* Now set the new request components */
	client->ctx = ctx;
	client->on_reply = cb;
	client->request = g_byte_array_ref(req);
	return NULL;
}

GError*
gridd_client_connect_url(struct client_s *client, const gchar *url)
{
	g_assert(client != NULL);
	g_assert(url != NULL);

	_client_reset_cnx(client);
	_client_reset_target(client);
	_client_reset_reply(client);

	g_strlcpy(client->orig_url, url, URL_MAXLEN);
	memcpy(client->url, client->orig_url, URL_MAXLEN);
	client->step = NONE;

	return NULL;
}

GError*
gridd_client_connect_addr(struct client_s *client,
		const struct addr_info_s *ai)
{
	gchar url[URL_MAXLEN];

	grid_addrinfo_to_string(ai, url, sizeof(url));
	return gridd_client_connect_url(client, url);
}

/* Looping ----------------------------------------------------------------- */

void
gridd_client_cnx_error(struct client_s *client)
{
	UTILS_ASSERT(client != NULL);
	if (client->error)
		g_error_free(client->error);
	client->error = socket_get_error(client->fd);
}

gboolean
gridd_client_finished(struct client_s *c)
{
	if (!c || c->error != NULL)
		return TRUE;

	switch (c->step) {
		case NONE:
			return TRUE;
		case CONNECTING:
			return FALSE;
		case CONNECTED:
			return TRUE;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			/* The only case where fd<0 is when an error occured,
			 * and 'error' MUST have been set */
			g_assert(c->fd >= 0);
			return FALSE;
		case STATUS_OK:
		case STATUS_FAILED:
			return TRUE;
	}

	g_assert_not_reached();
	return FALSE;
}

gboolean
gridd_clients_finished(struct client_s **clients)
{
	if (!clients)
		return TRUE;

	while (*clients) {
		if (!gridd_client_finished(*(clients++)))
			return FALSE;
	}

	return TRUE;
}

gboolean
gridd_client_start(struct client_s *client)
{
	GError *err = NULL;

	g_assert(client != NULL);

	g_get_current_time(&(client->tv_start));
	memcpy(&(client->tv_step), &(client->tv_start), sizeof(GTimeVal));

	if (client->step != NONE)
		return FALSE;

	g_assert(client->url[0] != 0);

	if (!(err = _client_connect(client)))
		return TRUE;

	client->step = STATUS_FAILED;
	client->error = err;
	return FALSE;
}

void
gridd_clients_start(struct client_s **clients)
{
	g_assert(clients != NULL);
	while (*clients)
		(void) gridd_client_start(*(clients++));
}

GError*
gridd_client_step(struct client_s *client)
{
	struct pollfd pfd = {-1, 0, 0};

	if (!_client_to_pollfd(client, &pfd)) // no event expected
		return NULL;

	int rc = poll(&pfd, 1, 1000);
	if (rc == 0) {
		GTimeVal now;
		g_get_current_time(&now);
		_client_expire(client, &now);
		return NULL;
	}
	if (rc < 0)
		return NEWERROR(errno, "poll errno=%d %s", errno, strerror(errno));

	if (pfd.revents & POLLERR)
		client->error = socket_get_error(client->fd);
	else
		_client_react(client);
	return NULL;
}

GError *
gridd_clients_step(struct client_s **clients)
{
	struct client_s ** _lookup_client(int fd, struct client_s **ppc) {
		struct client_s *c;
		for (; (c = *ppc) ;ppc++) {
			if (c->fd == fd)
				return ppc;
		}
		return ppc;
	}

	guint j;
	int rc;
	struct client_s *last, **plast;
	GTimeVal now;
	guint nbclients;

	UTILS_ASSERT(clients != NULL);
	nbclients = g_strv_length((gchar**)clients);
	UTILS_ASSERT(nbclients > 0);

	struct pollfd pfd[nbclients];

	for (j=0,plast=clients; NULL != (last = *plast) ;plast++) {
		if (last->fd >= 0) {
			if (_client_to_pollfd(last, pfd+j))
				j++;
		}
	}

	if (!j)
		return NULL;

	GRID_TRACE2("%s : %u active clients", __FUNCTION__, j);

	/* Wait for an event to happen */
	rc = poll(pfd, j, 100);
	if (!rc) {
		g_get_current_time(&now);
		_clients_expire(clients, &now);
		return NULL;
	}
	if (rc < 0)
		return NEWERROR(errno, "poll error (%s)", strerror(errno));

	/* Then manage each event */
	guint i;
	for (plast=clients,i=0; i<j ;i++) {

		if (!pfd[i].revents)
			continue;

		/* Find the client for this pollfd */
		plast = _lookup_client(pfd[i].fd, plast);
		UTILS_ASSERT(plast != NULL);
		last = *plast;

		/* Manage the poll() event */
		if (pfd[i].revents & POLLERR)
			gridd_client_cnx_error(last);
		else
			_client_react(last);
	}

	/* Now check for expired clients */
	g_get_current_time(&now);
	_clients_expire(clients, &now);

	return NULL;
}

GError *
gridd_client_loop(struct client_s *client)
{
	while (!gridd_client_finished(client)) {
		GError *err = gridd_client_step(client);
		if (err) {
			g_prefix_error(&err, "(Step) ");
			return err;
		}
	}
	return NULL;
}

GError *
gridd_clients_loop(struct client_s **clients)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, clients);

	while (!gridd_clients_finished(clients)) {
		GError *err = gridd_clients_step(clients);
		if (err) {
			g_prefix_error(&err, "(Step) ");
			return err;
		}
	}
	return NULL;
}

gboolean
gridd_client_expired(struct client_s *client, GTimeVal *now)
{
	inline gdouble seconds_elapsed(struct timeval *tv) {
		gdouble ds, du, dr;
		ds = tv->tv_sec;
		du = tv->tv_usec;
		dr = ds + (du / 1000000.0);
		return dr;
	}

	struct timeval diff;

	UTILS_ASSERT(client != NULL);

	switch (client->step) {
		case NONE:
		case CONNECTED:
			return FALSE;
		case CONNECTING:
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			if (client->delay_step > 0.0) {
				timersub(now, &(client->tv_step), &diff);
				if (seconds_elapsed(&diff) > client->delay_step)
					return TRUE;
			}
			if (client->delay_overall > 0.0) {
				timersub(now, &(client->tv_start), &diff);
				if (seconds_elapsed(&diff) > client->delay_overall)
					return TRUE;
			}
			return FALSE;
		case STATUS_OK:
		case STATUS_FAILED:
			return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

