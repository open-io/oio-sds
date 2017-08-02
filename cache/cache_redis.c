/*
OpenIO SDS cache
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <hiredis/hiredis.h>

#include <metautils/lib/metautils.h>

#include "cache_redis.h"

struct oio_cache_redis_s;

static void _redis_destroy (struct oio_cache_s *self);
static enum oio_cache_status_e _redis_put (struct oio_cache_s *self, const char *k, const char *v);
static enum oio_cache_status_e _redis_del (struct oio_cache_s *self, const char *k);
static enum oio_cache_status_e _redis_get (struct oio_cache_s *self, const char *k, gchar **out);

static struct oio_cache_vtable_s vtable_redis =
{
	_redis_destroy, _redis_put, _redis_del, _redis_get
};

struct oio_cache_redis_s
{
	const struct oio_cache_vtable_s *vtable;
	struct redisContext *redis;
};

/* Constructors ------------------------------------------------------------- */

struct oio_cache_s *
oio_cache_make_redis (const char *ip, int port, const struct timeval timeout)
{
	EXTRA_ASSERT (ip != NULL);
	struct oio_cache_redis_s *self = SLICE_NEW0 (struct oio_cache_redis_s);
	self->vtable = &vtable_redis;
	self->redis = redisConnectWithTimeout (ip, port, timeout);
	return (struct oio_cache_s*) self;
}

/* Handling ----------------------------------------------------------------- */

static enum oio_cache_status_e
redis_parse_reply(struct redisContext *ctx, struct redisReply *reply, gchar **out)
{
	enum oio_cache_status_e status;

	if (reply == NULL) {
		switch (ctx->err) {
			case REDIS_ERR_IO:  // socket error
			case REDIS_ERR_EOF: // closed connection
			case REDIS_ERR_PROTOCOL: // parse error
			case REDIS_ERR_OTHER:
				status = OIO_CACHE_DISCONNECTED;
				break;

			default:
				g_assert_not_reached();
		}

		// TODO log ctx->errstr
		return status;
	}

	switch (reply->type) {

		case REDIS_REPLY_ERROR:
			// TODO log the error that's in reply->str
			status = OIO_CACHE_FAIL;
			break;

		case REDIS_REPLY_NIL:
			status = OIO_CACHE_NOTFOUND;
			break;

		case REDIS_REPLY_STRING:
			if (reply->str != NULL) {
				*out = g_strdup (reply->str);
				status = OIO_CACHE_OK;
			} else {
				status = OIO_CACHE_FAIL;
			}
			break;

		case REDIS_REPLY_STATUS:
			if (g_strcmp0(reply->str, "OK") == 0)
				status = OIO_CACHE_OK;
			else
				status = OIO_CACHE_FAIL;
			break;

		case REDIS_REPLY_INTEGER: // number of keys removed with DEL
			if (reply->integer > 0)
				status = OIO_CACHE_OK;
			else
				status = OIO_CACHE_NOTFOUND;
			break;

		// This should never happen as we only store string keys
		case REDIS_REPLY_ARRAY:
		default:
			g_assert_not_reached();
	}

	freeReplyObject (reply);

	return status;
}

/* Interface ---------------------------------------------------------------- */

static void
_redis_destroy (struct oio_cache_s *self)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	if (!c)
		return;
	redisFree (c->redis);
	c->redis = NULL;
	SLICE_FREE (struct oio_cache_redis_s, c);
}

static enum oio_cache_status_e
_redis_put (struct oio_cache_s *self, const char *k, const char *v)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	struct redisReply *reply = redisCommand (c->redis, "SET %s %s", k, v);
	return redis_parse_reply (c->redis, reply, NULL);
}

static enum oio_cache_status_e
_redis_del (struct oio_cache_s *self, const char *k)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	struct redisReply *reply = redisCommand (c->redis, "DEL %s", k);
	return redis_parse_reply (c->redis, reply, NULL);
}

static enum oio_cache_status_e
_redis_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	struct redisReply *reply = redisCommand (c->redis, "GET %s", k);
	return redis_parse_reply (c->redis, reply, out);
}
