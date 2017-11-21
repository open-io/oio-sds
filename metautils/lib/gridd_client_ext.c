/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <poll.h>
#include <sys/types.h>

#include "metautils.h"

struct gridd_client_s *
gridd_client_create_idle(const gchar *target)
{
	struct gridd_client_s *client = gridd_client_create_empty();
	if (unlikely(NULL == client))
		return NULL;

	GError *err = gridd_client_connect_url(client, target);
	if (likely(NULL == err))
		return client;

	GRID_WARN("Client creation failed: (%d) %s", err->code, err->message);
	g_clear_error(&err);
	gridd_client_free(client);
	return NULL;
}

struct gridd_client_s *
gridd_client_create(const gchar *target, GByteArray *req, gpointer ctx,
                client_on_reply cb)
{
	EXTRA_ASSERT(req != NULL);

	struct gridd_client_s *client = gridd_client_create_idle(target);
	if (!client)
		return NULL;
	GError *err = gridd_client_request(client, req, ctx, cb);
	if (NULL == err)
		return client;

	GRID_WARN("gridd client creation error : (%d) %s", err->code, err->message);
	g_clear_error(&err);
	gridd_client_free(client);
	return NULL;
}

GError *
gridd_client_loop(struct gridd_client_s *client)
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

struct gridd_client_s **
gridd_client_create_many(gchar **targets, GByteArray *req, gpointer ctx,
                client_on_reply cb)
{
	EXTRA_ASSERT(targets != NULL);
	EXTRA_ASSERT(req != NULL);

	const gint max = (gint)g_strv_length(targets);
	struct gridd_client_s **clients = g_malloc0(sizeof(void*) * (max+1));

	gint i;
	for (i = 0; i < max; i++) {
		struct gridd_client_s *client = gridd_client_create(targets[i], req, ctx, cb);
		if (!client)
			break;
		clients[i] = client;
	}
	if (i < max) { /* something went wrong, rolling back */
		for (; i >= 0; i--) {
			gridd_client_free(clients[i]);
			clients[i] = NULL;
		}
		g_free(clients);
		clients = NULL;
	}

	return clients;
}

void
gridd_clients_free(struct gridd_client_s **clients)
{
	if (clients) {
		struct gridd_client_s **c;
		for (c=clients; *c ;c++)
			gridd_client_free(*c);
		g_free(clients);
	}
}

GError *
gridd_clients_error(struct gridd_client_s **clients)
{
	if (NULL != clients) {
		struct gridd_client_s *c;
		for (; (c = *clients) ;clients++) {
			GError *e = gridd_client_error(c);
			if (e != NULL)
				return e;
		}
	}

	return NULL;
}

void
gridd_clients_set_timeout(struct gridd_client_s **clients, gdouble seconds)
{
	for (; *clients ;++clients)
		gridd_client_set_timeout(*clients, seconds);
}

void
gridd_clients_set_timeout_cnx(struct gridd_client_s **clients, gdouble seconds)
{
	for (; *clients ;++clients)
		gridd_client_set_timeout_cnx(*clients, seconds);
}

gboolean
gridd_clients_finished(struct gridd_client_s **clients)
{
	if (clients) {
		struct gridd_client_s *p;
		for (; NULL != (p = *clients) ;clients++) {
			if (!gridd_client_finished(p))
				return FALSE;
		}
	}

	return TRUE;
}

void
gridd_clients_start(struct gridd_client_s **clients)
{
	if (unlikely(NULL == clients))
		return;
	for (; *clients ;++clients) {
		if (gridd_client_start(*clients))
			continue;
		GError *err = gridd_client_error(*clients);
		GRID_WARN("STARTUP failed fd=%d [%s] : (%d) %s",
					gridd_client_fd(*clients),
					gridd_client_url(*clients),
					err ? err->code : 0,
					err ? err->message : "?");
		if (err)
			g_clear_error(&err);
	}
}

static void
_clients_expire(struct gridd_client_s **clients, gint64 now)
{
	if (clients) {
		struct gridd_client_s *c;
		for (; NULL != (c = *clients) ;++clients) {
			gridd_client_expire(c, now);
		}
	}
}

static int
_client_to_pollfd(struct gridd_client_s *client, struct pollfd *pfd)
{
	int fd = gridd_client_fd(client);
	int interest = gridd_client_interest(client);

	if (fd < 0 || !interest)
		return 0;

	pfd->fd = fd;
	pfd->events = 0;
	pfd->revents = 0;
	if (interest & CLIENT_WR)
		pfd->events = POLLOUT;
	if (interest & CLIENT_RD)
		pfd->events = POLLIN;
	return 1;
}

GError*
gridd_client_step(struct gridd_client_s *client)
{
	int rc;
	struct pollfd pfd = {-1, 0, 0};

	if (!_client_to_pollfd(client, &pfd))
		return NULL;

retry:
	rc = metautils_syscall_poll(&pfd, 1, 1000);
	if (rc == 0) {
		gridd_client_expire(client, oio_ext_monotonic_time ());
		return NULL;
	}
	if (rc < 0) {
		if (errno == EINTR) goto retry;
		return NEWERROR(errno, "poll errno=%d %s", errno, strerror(errno));
	}

	if (pfd.revents & POLLERR) {
		GError *err = socket_get_error(pfd.fd);
		g_prefix_error(&err, "%s: ", gridd_client_url(client));
		gridd_client_fail(client, err);
	} else if (pfd.revents & (POLLIN|POLLOUT)) {
		gridd_client_react(client);
	}
	return NULL;
}

GError *
gridd_clients_step(struct gridd_client_s **clients)
{
	struct gridd_client_s ** _lookup_client(int fd, struct gridd_client_s **ppc) {
		struct gridd_client_s *c;
		for (; (c = *ppc) ;ppc++) {
			if (gridd_client_fd(c) == fd)
				return ppc;
		}
		return ppc;
	}

	guint i, j;
	int rc;
	struct gridd_client_s *last, **plast;
	guint nbclients;

	EXTRA_ASSERT(clients != NULL);
	nbclients = g_strv_length((gchar**)clients);
	EXTRA_ASSERT(nbclients > 0);

	struct pollfd pfd[nbclients];

	for (j=0,plast=clients; NULL != (last = *plast) ;plast++) {
		if (_client_to_pollfd(last, pfd+j))
			j++;
	}
	if (!j)
		return NULL;

retry:
	/* Wait for an event to happen */
	rc = metautils_syscall_poll (pfd, j, 100);
	if (rc == 0) {
		_clients_expire(clients, oio_ext_monotonic_time ());
		return NULL;
	}
	if (rc < 0) {
		if (errno == EINTR) goto retry;
		return NEWERROR(errno, "poll error (%s)", strerror(errno));
	}

	/* Then manage each event */
	for (plast=clients,i=0; i<j ;i++) {
		if (!pfd[i].revents)
			continue;

		/* Find the client for this pollfd */
		plast = _lookup_client(pfd[i].fd, plast);
		EXTRA_ASSERT(plast != NULL);
		last = *plast;

		/* Manage the poll() event */
		if (pfd[i].revents & POLLERR) {
			GError *err = socket_get_error(pfd[i].fd);
			g_prefix_error(&err, "%s: ", gridd_client_url(last));
			gridd_client_fail(last, err);
		} else {
			gridd_client_react(last);
		}
	}

	/* Now check for expired clients */
	_clients_expire(clients, oio_ext_monotonic_time ());
	return NULL;
}

GError *
gridd_clients_loop(struct gridd_client_s **clients)
{
	while (!gridd_clients_finished(clients)) {
		GError *err = gridd_clients_step(clients);
		if (err) {
			g_prefix_error(&err, "(Step) ");
			return err;
		}
	}
	return NULL;
}

GError *
gridd_client_run (struct gridd_client_s *self)
{
	if (!self)
		return NEWERROR(CODE_INTERNAL_ERROR, "creation error");
	if (!gridd_client_start(self))
		return NEWERROR(CODE_INTERNAL_ERROR, "starting error");
	GError *err;
	if (NULL != (err = gridd_client_loop (self)))
		return err;
	if (NULL != (err = gridd_client_error (self)))
		return err;
	return NULL;
}

GError *
gridd_client_exec (const gchar *to, gdouble seconds, GByteArray *req)
{
	return gridd_client_exec4 (to, seconds, req, NULL);
}

static gboolean
_cb_exec4 (GPtrArray *tmp, MESSAGE reply)
{
	if (!metautils_message_has_BODY (reply))
		return TRUE;
	GByteArray *body = NULL;
	GError *e = metautils_message_extract_body_gba(reply, &body);
	if (e) {
		GRID_WARN("BUG/Corruption : (%d) %s", e->code, e->message);
		g_clear_error (&e);
		return FALSE;
	} else {
		g_ptr_array_add(tmp, body);
		return TRUE;
	}
}

GError *
gridd_client_exec4 (const gchar *to, gdouble seconds, GByteArray *req,
		GByteArray ***out)
{
	if (!to) {
		g_byte_array_unref (req);
		return NEWERROR(CODE_INTERNAL_ERROR, "No target");
	}

	GPtrArray *tmp = NULL;
	if (out)
		tmp = g_ptr_array_new();

	struct gridd_client_s *client = gridd_client_create(to, req,
			(out ? tmp : NULL), out ? (client_on_reply)_cb_exec4 : NULL);
	g_byte_array_unref (req);
	if (!client) {
		if (tmp) g_ptr_array_free (tmp, TRUE);
		return NEWERROR(CODE_INTERNAL_ERROR, "client creation");
	}
	if (seconds > 0.0)
		gridd_client_set_timeout (client, seconds);
	GError *err = gridd_client_run (client);
	gridd_client_free (client);

	if (!err && out) {
		*out = (GByteArray**) metautils_gpa_to_array (tmp, TRUE);
		tmp = NULL;
	}
	if (tmp) {
		g_ptr_array_set_free_func (tmp, (GDestroyNotify)g_byte_array_unref);
		g_ptr_array_free (tmp, TRUE);
	}
	return err;
}

static gboolean
_cb_exec_and_concat (GByteArray *tmp, MESSAGE reply)
{
	gsize bsize = 0;
	void *b = metautils_message_get_BODY(reply, &bsize);
	if (b && bsize)
		g_byte_array_append(tmp, b, bsize);
	return TRUE;
}

GError *
gridd_client_exec_and_concat (const gchar *to, gdouble seconds, GByteArray *req,
		GByteArray **out)
{
	if (!to) {
		g_byte_array_unref (req);
		return NEWERROR(CODE_INTERNAL_ERROR, "No target");
	}

	GByteArray *tmp = NULL;
	if (out)
		tmp = g_byte_array_sized_new(512);

	struct gridd_client_s *client = gridd_client_create(to, req,
			out ? tmp : NULL, out ? (client_on_reply)_cb_exec_and_concat : NULL);
	g_byte_array_unref (req);
	if (!client) {
		if (tmp) g_byte_array_free (tmp, TRUE);
		return NEWERROR(CODE_INTERNAL_ERROR, "client creation");
	}
	if (seconds > 0.0)
		gridd_client_set_timeout (client, seconds);
	GError *err = gridd_client_run (client);
	gridd_client_free (client);

	if (!err && out) {
		*out = tmp;
		tmp = NULL;
	}
	if (tmp)
		metautils_gba_unref (tmp);
	return err;
}

GError *
gridd_client_exec_and_concat_string (const gchar *to, gdouble seconds, GByteArray *req,
		gchar **out)
{
	GByteArray *tmp = NULL;
	GError *err = gridd_client_exec_and_concat (to, seconds, req, out ? &tmp : NULL);

	if (err) {
		if (tmp) g_byte_array_unref (tmp);
		return err;
	}
	if (out) {
		g_byte_array_append (tmp, (guint8*)"", 1);
		*out = (gchar*) g_byte_array_free (tmp, FALSE);
	}
	return NULL;
}

GError *
gridd_client_exec_and_decode (const gchar *to, gdouble seconds,
		GByteArray *req, GSList **out, body_decoder_f decode)
{
	GByteArray ** bodies = NULL;
	GError *err = gridd_client_exec4 (to, seconds, req,
			(out && decode) ? &bodies : NULL);
	if (err) {
		metautils_gba_cleanv (bodies);
		return err;
	}
	if (out && decode && bodies) {
		GSList *items = NULL;
		for (GByteArray **pbody=bodies; *pbody && !err ;pbody++) {
			GByteArray *body = *pbody;
			if (!body->data || body->len<=0)
				continue;
			GSList *l = NULL;
			if (!decode(&l, body->data, body->len, &err)) {
				g_prefix_error (&err, "Decoding error: ");
				break;
			}
			if (l)
				items = metautils_gslist_precat (items, l);
		}
		*out = items;
	}
	metautils_gba_cleanv (bodies);
	return err;
}

gdouble
oio_clamp_timeout(gdouble timeout, gint64 deadline)
{
	if (deadline <= 0)
		return timeout;

	const gint64 now = oio_ext_monotonic_time();
	if (now > deadline)
		return 0.000001;

	const gint64 remaining = deadline - now;
	const gdouble dl_to = ((gdouble)remaining) / (gdouble)G_TIME_SPAN_SECOND;
	return MIN(timeout, dl_to);
}

gint64
oio_clamp_deadline(gdouble timeout, gint64 deadline)
{
	const gint64 dl_local = oio_ext_monotonic_time() + (G_TIME_SPAN_SECOND * timeout);
	return (deadline > 0) ? MIN(deadline, dl_local) : dl_local;
}

