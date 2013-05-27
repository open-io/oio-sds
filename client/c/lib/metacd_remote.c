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
# define LOG_DOMAIN "grid.client.metacd.remote"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <sys/poll.h>

#include <glib.h>
#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>

#include "./metacd_remote.h"
#include "../metacd_module/metacd_module.h"

#define TIMEOUT_CNX 100
#define TIMEOUT_OP 2000

static int
connect_to_unix_socket(const struct metacd_connection_info_s *mi, GError **err)
{
	int fd=-1;
	struct {
		int cnx;
		int op;
	} timeout;
	struct sockaddr_un sun;

	sun.sun_family = PF_LOCAL;
	g_strlcpy (sun.sun_path, mi->metacd.path, sizeof(sun.sun_path));

	/*opens a non-blocking socket*/
	if (-1==(fd=socket(PF_LOCAL,SOCK_STREAM,0))) {
		GSETERROR(err,"cannot open a PF_LOCAL socket (%s)", strerror(errno));
		goto errorLabel;
	}

	timeout.cnx = mi->metacd.timeout.cnx;
	timeout.op = mi->metacd.timeout.op;

	if (timeout.cnx >= 0) {
		if (-1 == fcntl (fd, F_SETFL, (fcntl(fd, F_GETFL) | O_NONBLOCK))) {
			GSETERROR(err,"cannot set the non blocking mode (%s)", strerror(errno));
			goto errorLabel;
		}
	}

	if (-1==(connect(fd, (struct sockaddr*) &sun, sizeof(sun)))) {
		if (errno!=EINTR && errno!=EINPROGRESS) {
			GSETERROR(err,"cannot connect to %s (%s)", mi->metacd.path, strerror(errno));
			goto errorLabel;
		} else if (errno!=EALREADY && timeout.cnx>=0) {
			int rc;
			struct pollfd pfd;
			for (;;) {
				pfd.fd = fd;
				pfd.events = POLLOUT|POLLERR|POLLNVAL|POLLHUP;
				pfd.revents = 0;
				rc = poll(&pfd,1,timeout.cnx);
				switch (rc)
				{
					case 0:/*timeout*/
						GSETCODE(err,ERRCODE_CONN_TIMEOUT,"METAcd connection timeout");
						goto errorLabel;
					case -1:
						if (errno==EINTR) break; /*interrupted*/
						GSETERROR(err,"Cannot connect to METACD through %s (%s)", sun.sun_path, strerror(errno));
						goto errorLabel;
					case 1:
						if ((pfd.revents&POLLERR) || (pfd.revents&POLLHUP) || (pfd.revents&POLLNVAL)) {
							GSETERROR(err,"Cannot connect to %s (poll events : %04X)", sun.sun_path, pfd.revents);
							goto errorLabel;
						}
						if (pfd.revents&POLLOUT) {
							TRACE("Socket fd=%i connected", fd);
							goto successLabel;
						}
						/*no break statement, voluntarily because this is an error managed by the default clause*/
					default:
						GSETERROR(err,"Cannot connect to %s (unexpected event)", sun.sun_path);
						goto errorLabel;
				}
			}
		}
	}

successLabel:
	return fd;

errorLabel:
	if (fd>=0)
		close(fd);
	return -1;
}

inline const gchar *make_metacd_path(const gchar *content_path, const gchar *content_version)
{
	const gchar *vers = content_version ? content_version : "1";
	return g_strconcat(content_path, "?version=", vers, NULL);
}

inline const gchar *make_metacd_path2(const gchar *content_path, content_version_t content_version)
{
	return g_strdup_printf("%s?version=%" G_GINT64_FORMAT, content_path, content_version);
}

inline void destroy_metacd_path(const gchar *metacd_path)
{
	g_free((gpointer)metacd_path);
}

static MESSAGE
metacd_create_request (const struct metacd_connection_info_s *mi, const container_id_t cID, GError **err)
{
	MESSAGE request=NULL;

	if (!mi) {
		GSETERROR(err, "invalid parameter");
		return NULL;
	}

	if (!message_create(&request,err)) {
		GSETERROR(err,"cannot create a request message");
		return NULL;
	}

	/*Sets the container ID if provided*/
	if (cID) {
		if (!message_add_field (request, MSGKEY_CID, sizeof(MSGKEY_CID)-1, cID, sizeof(container_id_t), err)) {
			GSETERROR(err, "Cannot set the containerId in the request");
			goto errorLabel;
		}
	}

	/*sets the namespace name*/
	if (!message_add_field (request, MSGKEY_NS, sizeof(MSGKEY_NS)-1, mi->metacd.nsName, strlen(mi->metacd.nsName), err)) {
		GSETERROR(err,"Cannot set the namespace name in the request");
		goto errorLabel;
	} else TRACE(MSGKEY_NS" set to %s", mi->metacd.nsName);

	/*set the provided session ID*/
	if (mi->cnx_id && mi->cnx_id_size>0) {
		TRACE("requesting METAcd mi=%p id=%p size=%lu", mi,
			(mi->cnx_id ? mi->cnx_id : NULL), (mi->cnx_id ? mi->cnx_id_size : 0));
		if (!message_set_ID(request, mi->cnx_id, mi->cnx_id_size, err)) {
			GSETERROR(err,"Cannot add the container ID in the message");
			goto errorLabel;
		}
	}

	return request;
errorLabel:
	if (request) {
		if (!message_destroy(request,NULL))
			ALERT("Cannot free a message structure, possible memory leak");
	}
	return NULL;
}


static gboolean
concat_contents (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	struct meta2_raw_content_s **pContent=NULL, *decoded=NULL;

	(void)code;

	pContent = (struct meta2_raw_content_s**) udata;
	if (!pContent)
		return FALSE;
	/*unserialize the body*/
	decoded = meta2_maintenance_content_unmarshall_buffer(body, bodySize, err);
	if (!decoded)
		return FALSE;
	/*append the chunks*/
	if (!(*pContent)) {
		*pContent = decoded;
	} else {
		if ((*pContent)->raw_chunks) {
			(*pContent)->raw_chunks = g_slist_concat( (*pContent)->raw_chunks, decoded->raw_chunks);
		} else {
			(*pContent)->raw_chunks = decoded->raw_chunks;
		}
		decoded->raw_chunks = NULL;
		meta2_maintenance_destroy_content(decoded);
	}
	return TRUE;
}


/* ------------------------------------------------------------------------- */


GSList*
metacd_remote_get_meta0(const struct metacd_connection_info_s *mi, GError **err)
{
	int fd = -1;
	GTimer *timer=NULL;
	GSList *result=NULL;
	MESSAGE request=NULL;
	struct code_handler_s rs_codes [] = {
		{206,REPSEQ_BODYMANDATORY,addr_info_concat,NULL},
		{200,REPSEQ_FINAL|REPSEQ_BODYMANDATORY,addr_info_concat,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {&result,0,rs_codes};

	if (!mi) {
		GSETERROR (err,"invalid parameter");
		return NULL;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi,NULL,err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_GETM0, sizeof(MSGNAME_METACD_GETM0)-1, err))
	{
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);

	STOP_TIMER(timer,"metacd_remote_get_meta1.success");
	g_timer_destroy (timer);

	return result;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_get_meta1.error");
		g_timer_destroy (timer);
	}
	return NULL;
}


GSList*  metacd_remote_get_meta1 (const struct metacd_connection_info_s *mi, const container_id_t cID,
		int ro, GSList *exclude, GError **err)
{
	int fd = -1;
	GTimer *timer=NULL;
	GSList *result=NULL;
	MESSAGE request=NULL;
	struct code_handler_s rs_codes [] = {
		{200,REPSEQ_FINAL|REPSEQ_BODYMANDATORY,addr_info_concat,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {&result,0,rs_codes};

	if (!mi || !cID) {
		GSETERROR (err,"invalid parameter");
		return NULL;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi,cID,err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_GETM1, sizeof(MSGNAME_METACD_GETM1)-1, err))
	{
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	if( NULL != exclude) {
		GByteArray *encoded = NULL;

		if (!(encoded = addr_info_marshall_gba(exclude, err))) {
			GSETERROR(err, "Exclude meta1 encode error");
			goto errorLabel;
		}

		int rc = 0;
		rc = message_set_BODY(request, encoded->data, encoded->len, err);

		g_byte_array_free(encoded, TRUE);
		if (!rc) {
			GSETERROR(err,"Request configuration failure");
			goto errorLabel;
		}
	}

	if(ro) {
		if (!message_add_field (request, "RO", strlen("RO"), "TRUE", strlen("TRUE"), err)) {
			GSETERROR(err,"Cannot set the read_only state in the request");
			goto errorLabel;
		}
	}


	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);

	STOP_TIMER(timer,"metacd_remote_get_meta1.success");
	g_timer_destroy (timer);
	return result;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_get_meta1.error");
		g_timer_destroy (timer);
	}
	return NULL;
}

gboolean
metacd_remote_set_meta1_master (const struct metacd_connection_info_s *mi, const container_id_t cid,
		const char *master, GError **e)
{
	int fd = -1;
	GTimer *timer=NULL;
	MESSAGE request=NULL;

	struct code_handler_s rs_codes [] = {
		{200,REPSEQ_FINAL,NULL,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {NULL,0,rs_codes};

	if (!mi) {
		GSETERROR (e, "Invalid parameter");
		return FALSE;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi, cid, e))) {
		GSETERROR (e, "Cannot create the metacd request");
		goto e_label;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_SET_M1_MASTER, sizeof(MSGNAME_METACD_SET_M1_MASTER) - 1, e)) {
		GSETERROR (e, "Cannot set the name of the request");
		goto e_label;
	}

	message_add_fields_str(request, NAME_MSGKEY_M1_MASTER, g_strdup(master),
				NULL);

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, e))) {
		GSETERROR (e, "cannot connect to the metacd");
		goto e_label;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (e, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (e, "cannot update meta1 master");
		goto e_label;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");
	
	shutdown(fd,SHUT_RDWR);
	close(fd);
	
	STOP_TIMER(timer,"metacd_remote_set_meta1_master.success");
	g_timer_destroy (timer);
	return TRUE;

e_label:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_decache.error");
		g_timer_destroy (timer);
	}
	return FALSE;
}


GSList*  metacd_remote_get_meta2 (const struct metacd_connection_info_s *mi, const container_id_t cID, GError **err)
{
	int fd = -1;
	GTimer *timer=NULL;
	GSList *result=NULL;
	MESSAGE request=NULL;
	struct code_handler_s rs_codes [] = {
		{200,REPSEQ_FINAL|REPSEQ_BODYMANDATORY,addr_info_concat,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {&result,0,rs_codes};

	if (!mi || !cID) {
		GSETERROR (err,"invalid parameter");
		return NULL;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi,cID,err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_GETM2, sizeof(MSGNAME_METACD_GETM2)-1, err))
	{
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");
	shutdown(fd,SHUT_RDWR);
	close(fd);

	STOP_TIMER(timer,"metacd_remote_get_meta2.success");
	g_timer_destroy (timer);
	return result;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_get_meta2.error");
		g_timer_destroy (timer);
	}
	return NULL;
}


gboolean metacd_remote_decache (const struct metacd_connection_info_s *mi, const container_id_t cID, GError **err)
{
	int fd = -1;
	GTimer *timer=NULL;
	MESSAGE request=NULL;
	struct code_handler_s rs_codes [] = {
		{200,REPSEQ_FINAL,NULL,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {NULL,0,rs_codes};

	if (!mi) {
		GSETERROR (err,"invalid parameter");
		return FALSE;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi,cID,err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_DECACHE, sizeof(MSGNAME_METACD_DECACHE)-1, err))
	{
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");
	
	shutdown(fd,SHUT_RDWR);
	close(fd);
	
	STOP_TIMER(timer,"metacd_remote_decache.success");
	g_timer_destroy (timer);
	return TRUE;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_decache.error");
		g_timer_destroy (timer);
	}
	return FALSE;
}


gboolean metacd_remote_decache_all (const struct metacd_connection_info_s *mi, GError **err)
{
	int fd = -1;
	GTimer *timer=NULL;
	MESSAGE request=NULL;
	struct code_handler_s rs_codes [] = {
		{200,REPSEQ_FINAL,NULL,NULL},
		{0,0,NULL,NULL}
	};
	struct reply_sequence_data_s rs_data = {NULL,0,rs_codes};

	if (!mi) {
		GSETERROR (err,"invalid parameter");
		return FALSE;
	}

	timer = g_timer_new();
	START_TIMER(timer);

	if (!(request = metacd_create_request(mi,NULL,err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	if (!message_set_NAME (request, MSGNAME_METACD_DECACHE, sizeof(MSGNAME_METACD_DECACHE)-1, err))
	{
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}

	/*send the request and read the responses*/
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &rs_data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");
	
	shutdown(fd,SHUT_RDWR);
	close(fd);
	
	STOP_TIMER(timer,"metacd_remote_decache.success");
	g_timer_destroy (timer);
	return TRUE;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	if (timer) {
		STOP_TIMER(timer,"metacd_remote_decache.error");
		g_timer_destroy (timer);
	}
	return FALSE;
}


struct meta2_raw_content_s*
metacd_remote_get_content (const struct metacd_connection_info_s *mi, const container_id_t cID,
	const gchar *path, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 206, REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	int fd = -1;
	MESSAGE request=NULL;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!mi || !cID || !path) {
		GSETERROR(err,"invalid parameter");
		goto errorLabel;
	}

	/*init the request*/
	if (!(request = metacd_create_request(mi, cID, err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}
	if (!message_add_field(request, MSGKEY_PATH, sizeof(MSGKEY_PATH)-1, path, strlen(path), err)) {
		GSETERROR(err, "Cannot set the path in the request");
		goto errorLabel;
	}
	if (!message_set_NAME(request, MSGNAME_METACD_V2_CHUNKS_GET, sizeof(MSGNAME_METACD_V2_CHUNKS_GET)-1, err)) {
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);

	return result;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	return NULL;
}

gboolean
metacd_remote_forget_content(struct metacd_connection_info_s *mi,
	const container_id_t cID, const gchar *path, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 206, 0, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	int fd = -1;
	MESSAGE request=NULL;
	struct reply_sequence_data_s data = { NULL, 0 , codes };

	if (!mi || !cID || !path) {
		GSETERROR(err,"invalid parameter");
		goto errorLabel;
	}

	/*init the request*/
	if (!(request = metacd_create_request(mi, cID, err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}
	if (!message_add_field(request, MSGKEY_PATH, sizeof(MSGKEY_PATH)-1, path, strlen(path), err)) {
		GSETERROR(err, "Cannot set the path in the request");
		goto errorLabel;
	}
	if (!message_set_NAME(request, MSGNAME_METACD_V1_CHUNKS_DEL, sizeof(MSGNAME_METACD_V1_CHUNKS_DEL)-1, err)) {
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);

	return TRUE;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	return FALSE;
}

gboolean
metacd_remote_flush_content(struct metacd_connection_info_s *mi, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 206, 0, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	int fd = -1;
	MESSAGE request=NULL;
	struct reply_sequence_data_s data = { NULL, 0 , codes };

	if (!mi) {
		GSETERROR(err,"invalid parameter");
		goto errorLabel;
	}

	/*init the request*/
	if (!(request = metacd_create_request(mi, NULL, err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}
	if (!message_set_NAME(request, MSGNAME_METACD_V1_CHUNKS_FLUSH, sizeof(MSGNAME_METACD_V1_CHUNKS_FLUSH)-1, err)) {
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);

	return TRUE;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	return FALSE;
}


gboolean
metacd_remote_save_content(struct metacd_connection_info_s *mi, struct meta2_raw_content_s *content, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	int fd = -1;
	size_t path_len;
	MESSAGE request = NULL;
	GByteArray *gba_body = NULL;
	struct reply_sequence_data_s data = { NULL, 0, codes };
	const gchar *metacd_path = NULL;

	if (!mi || !content) {
		GSETERROR(err,"invalid parameter");
		return FALSE;
	}

	gba_body = meta2_maintenance_marshall_content(content, err);
	if (!gba_body) {
		GSETERROR(err,"Serialization error");
		return FALSE;
	}

	/*init the request*/
	if (!(request = metacd_create_request(mi, content->container_id, err))) {
		GSETERROR (err,"cannot create the metacd request");
		goto errorLabel;
	}

	metacd_path = make_metacd_path2(content->path, content->version);
	path_len = strlen(metacd_path);
	if (!message_add_field(request, MSGKEY_PATH, sizeof(MSGKEY_PATH)-1,
			metacd_path, path_len, err)) {
		GSETERROR(err, "Cannot set the path in the request");
		destroy_metacd_path(metacd_path);
		goto errorLabel;
	}
	destroy_metacd_path(metacd_path);
	if (!message_set_NAME(request, MSGNAME_METACD_V2_CHUNKS_PUT, sizeof(MSGNAME_METACD_V2_CHUNKS_PUT)-1, err)) {
		GSETERROR (err, "Cannot set the name of the request");
		goto errorLabel;
	}
	if (!message_set_BODY(request, gba_body->data, gba_body->len, err)) {
		GSETERROR (err, "Cannot set the BODY of the request");
		goto errorLabel;
	}

	/*open the connection*/
	if (0>(fd=connect_to_unix_socket(mi, err))) {
		GSETERROR (err, "cannot connect to the metacd");
		goto errorLabel;
	}
	if (!metaXClient_reply_sequence_run (err, request, fd, mi->metacd.timeout.op, &data)) {
		GSETERROR (err, "cannot resolver META2");
		goto errorLabel;
	}

	if (!message_destroy(request, NULL))
		ALERT("cannot free a message structure, possible memory leak");

	shutdown(fd,SHUT_RDWR);
	close(fd);
	g_byte_array_free(gba_body, TRUE);
	return TRUE;

errorLabel:
	if (request) {
		if (!message_destroy(request, NULL))
			ALERT("cannot free a message structure, possible memory leak");
	}
	if (fd>=0) {
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}
	g_byte_array_free(gba_body, TRUE);
	return FALSE;
}


