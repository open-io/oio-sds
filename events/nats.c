/*
OpenIO SDS event queue
Copyright (C) 2023 OVH SAS

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


#include <glib.h>

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/internals.h>
#include <events/events_variables.h>

#include "cnats.h"

static void
_parse_urls(const gchar *endpoints, natsOptions *options)
{
	gchar **urls = g_strsplit(endpoints, ",", 10);

	int count = -1;
	while (urls[++count]);

	natsOptions_SetServers(options, (const char**)urls, count);

	g_strfreev(urls);
}


GError*
nats_create(const gchar *endpoint, struct nats_s **out)
{
	g_assert_nonnull(out);

	GError *err = NULL;
	struct nats_s out1 = {0};

	natsOptions_Create(&(out1.opts));
	_parse_urls(endpoint, out1.opts);

	if (!err) {
		*out = g_memdup(&out1, sizeof(struct nats_s));
	}

	return err;
}


GError*
nats_declare_stream(jsCtx *js_ctx, const char* stream, const char* subject)
{
	natsStatus status = NATS_OK;
	GError *err = NULL;
	jsErrCode jerr = 0;
	jsStreamInfo *si = NULL;

	// First check if the stream already exists.
	status = js_GetStreamInfo(&si, js_ctx, stream, NULL, &jerr);
	if (status == NATS_NOT_FOUND) {
		jsStreamConfig  cfg;
		// Initialize the configuration structure.
		jsStreamConfig_Init(&cfg);
		cfg.Name = stream;
		// Set the subject
		cfg.Subjects = (const char*[1]){subject};
		cfg.SubjectsLen = 1;
		// Make it a memory stream.
		cfg.Storage = js_MemoryStorage;
		// Add the stream,
		status = js_AddStream(&si, js_ctx, &cfg, NULL, &jerr);
	}

	if (status == NATS_OK) {
		printf("Stream %s has %" PRIu64 " messages (%" PRIu64 " bytes)\n",
			si->Config->Name, si->State.Msgs, si->State.Bytes);

		// Need to destroy the returned stream object.
		jsStreamInfo_Destroy(si);
	}

	return err;
}


GError*
nats_connect(struct nats_s *nats)
{
	if (nats->conn) {
		GRID_DEBUG("Nats already connected");
		return NULL;
	}

	GError *err = NULL;
	natsStatus status = NATS_OK;

	if (nats->conn == NULL) {
		// Open nats connection
		status = natsConnection_Connect(&(nats->conn), nats->opts);
		if (status != NATS_OK) {
			err = SYSERR("Failed to connect to nats. Code: %d", status);
			return err;
		}
	}

	// Connects to jetstream server
	jsOptions js_opts;
	jsOptions_Init(&js_opts);

	status = natsConnection_JetStream(&(nats->js_ctx), nats->conn, &js_opts);
	if (status != NATS_OK) {
		err = SYSERR("Failed to connect to nats jetstream server. Code: %d", status);
		return err;
	}

	return err;
}

GError*
nats_send_msg(struct nats_s *nats, void *msg, size_t msglen,
		const gchar *routing_key)
{
	GError *err = NULL;
	natsStatus status = NATS_OK;
	natsMsg *nats_msg;

	status = natsMsg_Create(&nats_msg, routing_key, NULL, (const char*)msg, msglen);
	if (status != NATS_OK) {
		err = SYSERR("Failed to create nats message. (Code=%d)", status);
		goto exit;
	}

	status = natsConnection_PublishMsg(nats->conn, nats_msg);
	if (status != NATS_OK) {
		err = SYSERR("Failed to publish nats message. (Code=%d)", status);
		goto exit;
	}

exit:
	natsMsg_Destroy(nats_msg);
	return err;
}

void
nats_destroy(struct nats_s *nats)
{
	if (!nats) {
		return;
	}

	memset(nats, 0, sizeof(struct nats_s));
	g_free(nats);
}