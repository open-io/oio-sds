/*
OpenIO SDS cache
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <hiredis/hiredis.h>

#include <metautils/lib/metautils.h>

#include "cache_redis.h"

#include <glib.h>


struct oio_cache_redis_s;

static void _redis_destroy (struct oio_cache_s *self);
static enum oio_cache_status_e _redis_put (struct oio_cache_s *self,
					   const char *k, const char *v);
static enum oio_cache_status_e _redis_del (struct oio_cache_s *self,
					   const char *k);
static enum oio_cache_status_e _redis_get (struct oio_cache_s *self,
					   const char *k, gchar **out);
static guint _redis_cleanup_older(struct oio_cache_s *self,
				  const gint64 expiration_time);
static guint _redis_cleanup_exceeding(struct oio_cache_s *self,
				      const guint limit);

static struct oio_cache_vtable_s vtable_redis =
{
	_redis_destroy, _redis_put, _redis_del,
	_redis_get, _redis_cleanup_older, _redis_cleanup_exceeding
};

struct oio_cache_redis_s
{
	const struct oio_cache_vtable_s *vtable;
	struct redisContext *redis;
	gint64 expiration_time; 
};

/* Concurrency ----------------------------------------------------------- */

static GMutex _redis_mutex = {0};

static struct redisReply*
_redis_command (struct redisContext *c, const char *cmd,
		const char *k, const char* v)
{
	struct redisReply *reply;
	g_mutex_lock(&_redis_mutex);
	if (NULL == v)
		reply = redisCommand(c,cmd,k);
	else
		reply = redisCommand(c,cmd,k,v);
	g_mutex_unlock(&_redis_mutex);
	return reply;
}

static struct redisReply**
_redis_pipeline_command (struct redisContext *c, const char **cmd,
			 const char **k, const char** v, const gint cmd_nb)
{
	gint tmp;
	struct redisReply **replies = g_malloc0(sizeof(struct redisReply*) * cmd_nb);
	if (NULL == replies)
		return NULL;
	g_mutex_lock(&_redis_mutex);
	for(tmp = 0; tmp < cmd_nb; tmp++) {
		if(NULL == v [tmp])
			redisAppendCommand(c, cmd[tmp], k[tmp]);
		else
			redisAppendCommand(c, cmd[tmp], k[tmp], v[tmp]);
	}
	for(tmp = 0; tmp < cmd_nb; tmp++) {
		redisGetReply(c, (void**) &(replies [tmp])); 
	}
	g_mutex_unlock(&_redis_mutex);
	return replies;
}


/* Constructors ------------------------------------------------------------- */

struct oio_cache_s *
oio_cache_make_redis (const char *ip, int port, const struct timeval timeout,
		      const gint64 expiration_time)
{
	EXTRA_ASSERT (ip != NULL);
	struct oio_cache_redis_s *self = SLICE_NEW0 (struct oio_cache_redis_s);
	self->vtable = &vtable_redis;
	self->redis = redisConnectWithTimeout (ip, port, timeout);
	self->expiration_time = expiration_time;
	return (struct oio_cache_s*) self;
}

/* Handling ----------------------------------------------------------------- */

static enum oio_cache_status_e
redis_parse_reply(struct redisContext *ctx, struct redisReply *reply,
		  gchar **out)
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
_redis_put_pipeline (struct oio_cache_s *self, const char *k, const char *v)
{
	enum oio_cache_status_e status;
	struct redisReply **reply;
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	char* expiration_time = g_strdup_printf("%"G_GINT64_FORMAT,c->expiration_time);
	if (!expiration_time)
		return OIO_CACHE_FAIL;
	char *keys [] = {(char*)k,(char*)k};
	char *values[] = {(char*)v,(char*)expiration_time};
	char *commands[] = {"SET %s %s", "EXPIRE %s %s"};
	reply = _redis_pipeline_command(c->redis, (const char**)commands, (const char**)keys, (const char**)values, 2);
	// juste pour le free ....
	status = redis_parse_reply(c->redis,reply [1], NULL); 
	status = redis_parse_reply(c->redis,reply [0], NULL);
	g_free(expiration_time);
	g_free(reply);
	return status;
}

static enum oio_cache_status_e
_redis_put (struct oio_cache_s *self, const char *k, const char *v)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	if (c->expiration_time != NO_EXPIRATION_TIME) {
		return _redis_put_pipeline(self, k, v);
	}
	struct redisReply *reply = _redis_command (c->redis, "SET %s %s", k, v);
	return redis_parse_reply (c->redis, reply, NULL);
}

static enum oio_cache_status_e
_redis_del (struct oio_cache_s *self, const char *k)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	struct redisReply *reply = _redis_command (c->redis, "DEL %s", k, NULL);
	return redis_parse_reply (c->redis, reply, NULL);
}

static enum oio_cache_status_e
_redis_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	struct oio_cache_redis_s *c = (struct oio_cache_redis_s*) self;
	struct redisReply *reply = _redis_command (c->redis, "GET %s", k, NULL);
	return redis_parse_reply (c->redis, reply, out);
}

static guint
_redis_cleanup_older (struct oio_cache_s *self, const gint64 expiration_time)
{
	(void) self; (void) expiration_time;
	return 0;
}

static guint
_redis_cleanup_exceeding (struct oio_cache_s *self, const guint limit)
{
	(void) self; (void) limit;
	return 0;
}


