/*
OpenIO SDS metautils
Copyright (C) 2025 OVH SAS

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <metautils/lib/common_variables.h>

#include "metautils.h"
#include "common_main.h"

static int
_dgram_connect_and_send (const char *url, GError **err,
		const uint8_t *buf, gsize *len)
{
	int fd;
	ssize_t rc;
	struct sockaddr_storage sas;
	gsize sas_len = sizeof(sas);

	if (!grid_string_to_sockaddr (url, (struct sockaddr*) &sas, &sas_len)) {
		g_error_transmit(err, NEWERROR(EINVAL, "invalid URL: %s", url));
		return -1;
	}

	// blocking socket
resocket:
	fd = metautils_syscall_socket(sas.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		if (errno == EINTR)
			goto resocket;
		g_error_transmit(
			err,
			NEWERROR(EINVAL, "socket error: (%d) %s", errno, strerror(errno))
		);
		return -1;
	}

reconnect:
	if (metautils_syscall_connect(fd, (struct sockaddr*) &sas, sas_len) != 0) {
		if (errno == EINTR)
			goto reconnect;
		g_error_transmit(err, NEWERROR(CODE_NETWORK_ERROR,
				"connect error %s: (%d) %s",
				url, errno, strerror(errno)));
		metautils_pclose (&fd);
		return -1;
	}

resend:
	rc = sendto(fd, buf, *len,
			MSG_FASTOPEN|MSG_NOSIGNAL, (struct sockaddr*) &sas, sas_len);
	if (rc < 0) {
		if (errno == EINTR)
			goto resend;
		g_error_transmit(err, NEWERROR(CODE_NETWORK_ERROR,
				"sendto error %s: (%d) %s",
				url, errno, strerror(errno)));
		metautils_pclose (&fd);
		return -1;
	}

	metautils_pclose (&fd);
	/* From the manual of sd_notify:
	 *     If the status was sent, these functions return a positive value.
	 */
	return rc > 0;
}

int oio_sd_notify(int unset_env UNUSED, const char *msg) {
	const gchar *e = g_getenv("NOTIFY_SOCKET");
	if (!oio_str_is_set(e)) {
		GRID_DEBUG("No systemd context, not notifying msg=%s", msg);
		return 0;
	}

	GError *err = NULL;
	gsize len = strlen(msg);
	int rc = _dgram_connect_and_send(e, &err, (const guint8*) msg, &len);
	if (rc < 0) {
		GRID_WARN("systemd connect error msg=%s path=%s err=%s", msg, e, err->message);
		g_clear_error(&err);
	}
	return rc;
}

int oio_sd_notifyf(int unset_env UNUSED, const char *fmt, ...) {
	GString *s = g_string_new("");
	va_list ap;

	va_start(ap, fmt);
	g_string_vprintf(s, fmt, ap);
	va_end(ap);

	int rc = oio_sd_notify(unset_env, s->str);
	g_string_free(s, TRUE);
	return rc;
}

