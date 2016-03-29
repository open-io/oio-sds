/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>

#include "metautils.h"

#ifndef URL_MAXLEN
# define URL_MAXLEN STRLEN_ADDRINFO
#endif

#ifndef EVENT_BUFFER_SIZE
# define EVENT_BUFFER_SIZE 2048
#endif

enum client_step_e
{
	NONE = 0,
	CONNECTING,
	REQ_SENDING,
	REP_READING_SIZE,
	REP_READING_DATA,
	STATUS_OK,
	STATUS_FAILED
};

struct gridd_client_factory_s
{
	struct abstract_client_factory_s abstract;
};

struct gridd_client_s
{
	struct abstract_client_s abstract;
	GByteArray *request;
	GByteArray *reply;
	GError *error;

	gpointer ctx;
	client_on_reply on_reply;

	gint64 tv_step;
	gint64 tv_start;
	gint64 delay_step;
	gint64 delay_overall;

	guint32 size;

	guint nb_redirects;
	int fd;
	guint sent_bytes;

	enum client_step_e step : 16;
	gboolean keepalive : 8;
	gboolean forbid_redirect : 8;

	gchar orig_url[URL_MAXLEN];
	gchar url[URL_MAXLEN];
};

static void _client_free(struct gridd_client_s *client);
static GError* _client_connect_url(struct gridd_client_s *client, const gchar *url);
static GError* _client_request(struct gridd_client_s *client, GByteArray *req,
		gpointer ctx, client_on_reply cb);
static gboolean _client_expired(struct gridd_client_s *client, gint64 now);
static gboolean _client_finished(struct gridd_client_s *c);
static const gchar* _client_url(struct gridd_client_s *client);
static int _client_get_fd(struct gridd_client_s *client);
static int _client_interest(struct gridd_client_s *client);
static GError* _client_error(struct gridd_client_s *client);
static gboolean _client_start(struct gridd_client_s *client);
static GError* _client_set_fd(struct gridd_client_s *client, int fd);
static void _client_set_timeout(struct gridd_client_s *client, gdouble seconds);
static void _client_set_keepalive(struct gridd_client_s *client, gboolean on);
static void _client_react(struct gridd_client_s *client);
static gboolean _client_expire(struct gridd_client_s *client, gint64 now);
static void _client_fail(struct gridd_client_s *client, GError *why);

static void _factory_clean(struct gridd_client_factory_s *self);
static struct gridd_client_s * _factory_create_client (
		struct gridd_client_factory_s *self);

struct gridd_client_factory_vtable_s VTABLE_FACTORY =
{
	_factory_clean,
	_factory_create_client
};

struct gridd_client_vtable_s VTABLE_CLIENT =
{
	_client_free,
	_client_connect_url,
	_client_request,
	_client_error,
	_client_interest,
	_client_url,
	_client_get_fd,
	_client_set_fd,
	_client_set_keepalive,
	_client_set_timeout,
	_client_expired,
	_client_finished,
	_client_start,
	_client_react,
	_client_expire,
	_client_fail
};

static int
_connect(const gchar *url, GError **err)
{
	struct sockaddr_storage sas;
	gsize sas_len = sizeof(sas);

	if (!grid_string_to_sockaddr (url, (struct sockaddr*) &sas, &sas_len)) {
		g_error_transmit(err, NEWERROR(EINVAL, "invalid URL"));
		return -1;
	}

	int fd = socket_nonblock(sas.ss_family, SOCK_STREAM, 0);
	if (0 > fd) {
		g_error_transmit(err, NEWERROR(EINVAL, "socket error: (%d) %s", errno, strerror(errno)));
		return -1;
	}

	sock_set_reuseaddr(fd, TRUE);

	if (0 != metautils_syscall_connect (fd, (struct sockaddr*)&sas, sas_len)) {
		if (errno != EINPROGRESS && errno != 0) {
			g_error_transmit(err, NEWERROR(EINVAL, "connect error: (%d) %s", errno, strerror(errno)));
			metautils_pclose (&fd);
			return -1;
		}
	}

	sock_set_linger_default(fd);
	sock_set_nodelay(fd, TRUE);
	sock_set_tcpquickack(fd, TRUE);
	*err = NULL;
	return fd;
}

static GError*
_client_connect(struct gridd_client_s *client)
{
	GError *err = NULL;
	client->fd = _connect(client->url, &err);

	if (client->fd < 0) {
		EXTRA_ASSERT(err != NULL);
		g_prefix_error(&err, "Connect error: ");
		return err;
	}

	EXTRA_ASSERT(err == NULL);
	client->tv_step = oio_ext_monotonic_time ();
	client->step = CONNECTING;
	return NULL;
}

static void
_client_reset_request(struct gridd_client_s *client)
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
_client_reset_reply(struct gridd_client_s *client)
{
	client->size = 0;
	if (!client->reply)
		client->reply = g_byte_array_new();
	else if (client->reply->len > 0)
		g_byte_array_set_size(client->reply, 0);
}

static void
_client_reset_cnx(struct gridd_client_s *client)
{
	if (client->fd >= 0)
		metautils_pclose(&(client->fd));
	client->step = NONE;
}

static void
_client_reset_target(struct gridd_client_s *client)
{
	memset(client->url, 0, sizeof(client->url));
	memset(client->orig_url, 0, sizeof(client->orig_url));
}

static void
_client_reset_error(struct gridd_client_s *client)
{
	if (client->error)
		g_clear_error(&(client->error));
}

static GError *
_client_manage_reply(struct gridd_client_s *client, MESSAGE reply)
{
	GError *err;
	guint status = 0;
	gchar *message = NULL;

	if (NULL != (err = metaXClient_reply_simple(reply, &status, &message))) {
		g_prefix_error (&err, "reply: ");
		return err;
	}
	STRING_STACKIFY(message);

	if (CODE_IS_NETWORK_ERROR(status)) {
		err = NEWERROR(status, "net error: %s", message);
		metautils_pclose(&(client->fd));
		client->step = STATUS_FAILED;
		return err;
	}

	if (status == CODE_TEMPORARY) {
		client->step = REP_READING_SIZE;
		return NULL;
	}

	if (CODE_IS_OK(status)) {
		client->step = (status==CODE_FINAL_OK) ? STATUS_OK : REP_READING_SIZE;
		if (client->step == STATUS_OK) {
			if (!client->keepalive)
				metautils_pclose(&(client->fd));
		}
		if (client->on_reply) {
			if (!client->on_reply(client->ctx, reply))
				return NEWERROR(CODE_INTERNAL_ERROR, "Handler error");
		}
		return NULL;
	}

	if (status == CODE_REDIRECT && !client->forbid_redirect) {
		/* Reset the context */
		_client_reset_reply(client);
		_client_reset_cnx(client);
		client->sent_bytes = 0;

		if ((++ client->nb_redirects) > 3)
			return NEWERROR(CODE_TOOMANY_REDIRECT, "Too many redirections");

		/* Replace the URL */
		g_strlcpy(client->url, message, URL_MAXLEN);
		if (NULL != (err = _client_connect(client)))
			g_prefix_error(&err, "Redirection error: Connect error: ");
		return err;
	}

	/* all other are considered errors */
	if (status != CODE_REDIRECT)
		err = NEWERROR(status, "Request error: %s", message);
	else
		err = NEWERROR(status, "%s", message);

	if (!client->keepalive)
		_client_reset_cnx(client);
	_client_reset_reply(client);
	return err;
}

static GError *
_client_manage_reply_data(struct gridd_client_s *c)
{
	GError *err = NULL;
	MESSAGE r = message_unmarshall(c->reply->data, c->reply->len, &err);
	if (!r)
		g_prefix_error(&err, "Decoding: ");
	else
		err = _client_manage_reply(c, r);
	metautils_message_destroy(r);
	return err;
}

static GError *
_client_manage_event_in_buffer(struct gridd_client_s *client, guint8 *d, gsize ds)
{
	guint32 s32;
	ssize_t rc;

	switch (client->step) {

		case CONNECTING:
			EXTRA_ASSERT(client->fd >= 0);
			EXTRA_ASSERT(client->request != NULL);
			client->step = REQ_SENDING;
			return NULL;

		case REQ_SENDING:

			client->step = REQ_SENDING;

			if (!client->request)
				return NULL;
			_client_reset_reply(client);

			/* Continue to send the request */
			rc = metautils_syscall_write(client->fd,
					client->request->data + client->sent_bytes,
					client->request->len - client->sent_bytes);

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

			if (!client->reply)
				client->reply = g_byte_array_new();

			if (client->reply->len < 4) {
				/* Continue reading the size */
				rc = metautils_syscall_read(client->fd, d, (4 - client->reply->len));
				if (rc < 0)
					return (errno == EINTR || errno == EAGAIN) ? NULL :
						NEWERROR(errno, "read error (%s)", strerror(errno));
				if (rc > 0)
					g_byte_array_append(client->reply, d, rc);

				if (client->reply->len < 4) {
					if (!rc)
						return NEWERROR(errno, "EOF!");
					return NULL;
				}
			}

			EXTRA_ASSERT (client->reply->len == 4);
			s32 = *((guint32*)(client->reply->data));
			client->size = g_ntohl(s32);

		case REP_READING_DATA:

			client->step = REP_READING_DATA;
			rc = 0;

			EXTRA_ASSERT (client->reply->len <= client->size + 4);
			if (client->reply->len < client->size + 4) {
				gsize remaiming = client->size + 4 - client->reply->len;
				gsize dmax = ds;
				if (dmax > remaiming)
					dmax = remaiming;
				rc = metautils_syscall_read(client->fd, d, dmax);
				if (rc < 0)
					return (errno == EINTR || errno == EAGAIN) ? NULL :
						NEWERROR(errno, "read error (%s)", strerror(errno));
				if (rc > 0)
					g_byte_array_append(client->reply, d, rc);
			}

			EXTRA_ASSERT (client->reply->len <= client->size + 4);
			if (client->reply->len == client->size + 4) {
				GError *err = _client_manage_reply_data(client);
				if (err) {
					client->step = STATUS_FAILED;
					return err;
				}
				else {
					if (client->step != CONNECTING && client->step != STATUS_FAILED
							&& client->step != STATUS_OK) {
						client->reply = g_byte_array_set_size(client->reply, 0);
						client->step = REP_READING_SIZE;
						client->size = 0;
					}
				}
			}
			else if (!rc)
				return NEWERROR(errno, "EOF!");
			return NULL;

		default:
			g_assert_not_reached();
			return NEWERROR(0, "Invalid state");
	}

	g_assert_not_reached();
	return NEWERROR(0, "BUG unreachable code");
}

static GError *
_client_manage_event(struct gridd_client_s *client)
{
	guint8 d[EVENT_BUFFER_SIZE];
	return _client_manage_event_in_buffer(client, d, EVENT_BUFFER_SIZE);
}

/* ------------------------------------------------------------------------- */

static void
_client_react(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (!client)
		return;
	GError *err = NULL;

	client->tv_step = oio_ext_monotonic_time ();
retry:
	if (!(err = _client_manage_event(client))) {
		if (client->step == REP_READING_SIZE && client->reply
				&& client->reply->len >= 4)
				goto retry;
	}
	else {
		_client_reset_request(client);
		_client_reset_reply(client);
		_client_reset_cnx(client);
		client->error = err;
		client->step = STATUS_FAILED;
	}
}

static const gchar*
_client_url(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (!client)
		return NULL;
	else {
		client->url[ sizeof(client->url)-1 ] = '\0';
		return client->url;
	}
}

static int
_client_get_fd(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	return client ? client->fd : -1;
}

static int
_client_interest(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (!client)
		return 0;

	switch (client->step) {
		case NONE:
			return 0;
		case CONNECTING:
			return CLIENT_WR;
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
			return 0;
	}
}

static GError *
_client_error(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (!client || !client->error)
		return NULL;
	return NEWERROR(client->error->code, "%s", client->error->message);
}

static void
_client_free(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	_client_reset_reply(client);
	_client_reset_request(client);
	_client_reset_cnx(client);
	_client_reset_target(client);
	_client_reset_error(client);
	if (client->reply)
		g_byte_array_free(client->reply, TRUE);
	client->fd = -1;
	SLICE_FREE (struct gridd_client_s, client);
}

static void
_client_set_keepalive(struct gridd_client_s *client, gboolean on)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	client->keepalive = BOOL(on);
}

static void
_client_set_timeout(struct gridd_client_s *client, gdouble seconds)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	client->delay_step = client->delay_overall = seconds * (gdouble) G_TIME_SPAN_SECOND;
}

static GError*
_client_set_fd(struct gridd_client_s *client, int fd)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (fd >= 0) {
		switch (client->step) {
			case NONE: /* ok */
				break;
			case CONNECTING:
				if (client->request != NULL)
					return NEWERROR(CODE_INTERNAL_ERROR, "Request pending");
				break;
			case REQ_SENDING:
			case REP_READING_SIZE:
			case REP_READING_DATA:
				return NEWERROR(CODE_INTERNAL_ERROR, "Request pending");
			case STATUS_OK:
			case STATUS_FAILED:
				/* ok */
				break;
		}
	}

	/* reset any connection and request */
	_client_reset_reply(client);
	_client_reset_request(client);
	_client_reset_target(client);

	/* XXX do not call _client_reset_cnx(), or close the connexion.
	 * It is the responsibility of the caller to manage this, because it
	 * explicitely breaks the pending socket management. */
	client->fd = fd;

	client->step = (client->fd >= 0) ? CONNECTING : NONE;

	return NULL;
}

static GError*
_client_connect_url(struct gridd_client_s *client, const gchar *url)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (NULL == url || !url[0])
		return NEWERROR(CODE_INTERNAL_ERROR, "Bad address");

	if (*url != '/' && !metautils_url_valid_for_connect(url))
		return NEWERROR(CODE_BAD_REQUEST, "Bad address [%s]", url);

	EXTRA_ASSERT(client != NULL);

	_client_reset_cnx(client);
	_client_reset_target(client);
	_client_reset_reply(client);

	g_strlcpy(client->orig_url, url, URL_MAXLEN);
	g_strlcpy(client->url, url, URL_MAXLEN);
	client->step = NONE;
	return NULL;
}

static GError*
_client_request(struct gridd_client_s *client, GByteArray *req,
		gpointer ctx, client_on_reply cb)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if ( NULL == req)
		return NEWERROR(CODE_INTERNAL_ERROR, "Invalid parameter");

	switch (client->step) {
		case NONE:
		case CONNECTING:
			if (client->request != NULL)
				return NEWERROR(CODE_INTERNAL_ERROR, "Request already pending");
			/* ok */
			break;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			return NEWERROR(CODE_INTERNAL_ERROR, "Request not terminated");
		case STATUS_OK:
		case STATUS_FAILED:
			/* ok */
			if (client->fd >= 0)
				client->step = REQ_SENDING;
			else
				client->step = CONNECTING;
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

static gboolean
_client_expired(struct gridd_client_s *client, gint64 now)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);
	switch (client->step) {
		case NONE:
			return FALSE;
		case CONNECTING:
			return (now - client->tv_start) > COMMON_CNX_TIMEOUT;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			if (client->delay_step > 0) {
				if ((now - client->tv_step) > client->delay_step)
					return TRUE;
			}
			if (client->delay_overall > 0) {
				if ((now - client->tv_start) > client->delay_overall)
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

static gboolean
_client_expire(struct gridd_client_s *client, gint64 now)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (_client_finished(client))
		return FALSE;
	if (!_client_expired(client, now))
		return FALSE;
	_client_reset_cnx(client);
	client->error = NEWERROR(ERRCODE_READ_TIMEOUT, "Timeout");
	client->step = STATUS_FAILED;
	return FALSE;
}

static gboolean
_client_finished(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	if (client->error != NULL)
		return TRUE;

	switch (client->step) {
		case NONE:
			return TRUE;
		case CONNECTING:
			return FALSE;
		case REQ_SENDING:
		case REP_READING_SIZE:
		case REP_READING_DATA:
			/* The only case where fd<0 is when an error occured,
			 * and 'error' MUST have been set */
			EXTRA_ASSERT(client->fd >= 0);
			return FALSE;
		case STATUS_OK:
		case STATUS_FAILED:
			return TRUE;
	}

	g_assert_not_reached();
	return FALSE;
}

static gboolean
_client_start(struct gridd_client_s *client)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);

	client->tv_start = client->tv_step = oio_ext_monotonic_time ();

	if (client->step != NONE)
		return FALSE;

	if (!client->url[0]) {
		_client_reset_error(client);
		client->error = NEWERROR(EINVAL, "No target");
		return FALSE;
	}

	GError *err = _client_connect(client);
	if (NULL == err)
		return TRUE;

	client->step = STATUS_FAILED;
	client->error = err;
	return FALSE;
}

static void
_client_fail(struct gridd_client_s *client, GError *why)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->abstract.vtable == &VTABLE_CLIENT);
	if (client->error != NULL)
		g_clear_error(&(client->error));
	client->error = NEWERROR(why->code, "%s", why->message);
}

static void
_factory_clean(struct gridd_client_factory_s *self)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->abstract.vtable == &VTABLE_FACTORY);
	SLICE_FREE(struct gridd_client_factory_s, self);
}

static struct gridd_client_s *
_factory_create_client (struct gridd_client_factory_s *factory)
{
	EXTRA_ASSERT(factory != NULL);
	EXTRA_ASSERT(factory->abstract.vtable == &VTABLE_FACTORY);
	(void) factory;
	struct gridd_client_s *client = gridd_client_create_empty();
	if (!client)
		return NULL;
	gridd_client_set_timeout(client, COMMON_CLIENT_TIMEOUT);
	return client;
}

/* ------------------------------------------------------------------------- */

struct gridd_client_s *
gridd_client_create_empty(void)
{
	struct gridd_client_s *client = SLICE_NEW0(struct gridd_client_s);
	if (unlikely(NULL == client))
		return NULL;

	client->abstract.vtable = &VTABLE_CLIENT;
	client->fd = -1;
	client->step = NONE;
	client->delay_overall = GRIDC_DEFAULT_TIMEOUT_OVERALL * (gdouble)G_TIME_SPAN_SECOND;
	client->delay_step = GRIDC_DEFAULT_TIMEOUT_STEP * (gdouble)G_TIME_SPAN_SECOND;

	return client;
}

void
gridd_client_no_redirect (struct gridd_client_s *c)
{
	if (!c) return;
	EXTRA_ASSERT(c->abstract.vtable == &VTABLE_CLIENT);
	c->forbid_redirect = 1;
}

struct gridd_client_factory_s *
gridd_client_factory_create(void)
{
	struct gridd_client_factory_s *factory = SLICE_NEW0(struct gridd_client_factory_s);
	factory->abstract.vtable = &VTABLE_FACTORY;
	return factory;
}

#define GRIDD_CALL(self,F) VTABLE_CALL(self,struct abstract_client_s*,F)

void
gridd_client_free (struct gridd_client_s *self)
{
	GRIDD_CALL(self,clean)(self);
}

GError *
gridd_client_connect_url (struct gridd_client_s *self, const gchar *u)
{
	GRIDD_CALL(self,connect_url)(self,u);
}

GError *
gridd_client_request (struct gridd_client_s *self, GByteArray *req,
		gpointer ctx, client_on_reply cb)
{
	GRIDD_CALL(self,request)(self,req,ctx,cb);
}

GError *
gridd_client_error (struct gridd_client_s *self)
{
	GRIDD_CALL(self,error)(self);
}

int
gridd_client_interest (struct gridd_client_s *self)
{
	GRIDD_CALL(self,interest)(self);
}

const gchar *
gridd_client_url (struct gridd_client_s *self)
{
	GRIDD_CALL(self,get_url)(self);
}

int
gridd_client_fd (struct gridd_client_s *self)
{
	GRIDD_CALL(self,get_fd)(self);
}

GError *
gridd_client_set_fd(struct gridd_client_s *self, int fd)
{
	GRIDD_CALL(self,set_fd)(self,fd);
}

void
gridd_client_set_keepalive(struct gridd_client_s *self, gboolean on)
{
	GRIDD_CALL(self,set_keepalive)(self,on);
}

void
gridd_client_set_timeout (struct gridd_client_s *self, gdouble seconds)
{
	GRIDD_CALL(self,set_timeout)(self,seconds);
}

gboolean
gridd_client_expired(struct gridd_client_s *self, gint64 now)
{
	GRIDD_CALL(self,expired)(self,now);
}

gboolean
gridd_client_finished (struct gridd_client_s *self)
{
	GRIDD_CALL(self,finished)(self);
}

gboolean
gridd_client_start (struct gridd_client_s *self)
{
	GRIDD_CALL(self,start)(self);
}

gboolean
gridd_client_expire (struct gridd_client_s *self, gint64 now)
{

	GRIDD_CALL(self,expire)(self,now);
}

void
gridd_client_react (struct gridd_client_s *self)
{
	GRIDD_CALL(self,react)(self);
}

void
gridd_client_fail (struct gridd_client_s *self, GError *why)
{
	GRIDD_CALL(self,fail)(self,why);
}

