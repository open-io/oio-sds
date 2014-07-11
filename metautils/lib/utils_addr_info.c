#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "metautils_syscall.h"
#include "metacomm.h"

gboolean
metautils_addr_valid_for_connect(const struct addr_info_s *a)
{
	return a->port != 0 && !data_is_zeroed(&(a->addr), sizeof(a->addr));
}

gboolean
metautils_url_valid_for_connect(const gchar *url)
{
	if (NULL == url) {
		errno = EINVAL;
		return FALSE;
	}
	addr_info_t ai;
	memset(&ai, 0, sizeof(ai));
	if (!grid_string_to_addrinfo(url, NULL, &ai))
		return FALSE;
	return metautils_addr_valid_for_connect(&ai);
}

gint
addrinfo_connect_nopoll(const addr_info_t * a, gint ms, GError ** err)
{
	struct sockaddr_storage sas;
	gsize sasSize = sizeof(struct sockaddr_storage);
	int fd = -1;

	if (!addrinfo_to_sockaddr(a, (struct sockaddr *) &sas, &sasSize)) {
		GSETERROR(err, "addr_info conversion error");
		return -1;
	}

	if (ms > 0)
		fd = socket_nonblock(sas.ss_family, SOCK_STREAM, 0);
	else
		fd = metautils_syscall_socket(sas.ss_family, SOCK_STREAM, 0);

	if (fd < 0) {
		GSETERROR(err, "Socket error: (%d) %s", errno, strerror(errno));
		return -1;
	}

	sock_set_reuseaddr(fd, TRUE);

	if (0 == metautils_syscall_connect(fd, (struct sockaddr *) &sas, sasSize))
		return fd;

	if (errno == EALREADY || errno == EINPROGRESS || errno == EINTR) {
		errno = 0;
		return fd;
	}

	GSETERROR(err, "Connect error: (%d) %s", errno, strerror(errno));
	metautils_pclose(&fd);
	return -1;
}

gint
addrinfo_connect(const addr_info_t * a, gint ms, GError ** err)
{
	int fd = addrinfo_connect_nopoll(a, ms, err);

	if (fd < 0) {
		GSETERROR(err, "addr_info conversion error");
		return -1;
	}

	sock_set_linger_default(fd);
	sock_set_nodelay(fd, TRUE);
	sock_set_tcpquickack(fd, TRUE);

	int rc;
	struct pollfd p;
retry:
	p.fd = fd;
	p.events = POLLOUT | POLLERR | POLLNVAL | POLLHUP;
	p.revents = 0;
	rc = poll(&p, 1, ms);

	if (rc == 0) {	/*timeout */
		GSETCODE(err, ERRCODE_CONN_TIMEOUT, "connect timeout");
	}
	else if (rc == -1) {
		if (errno == EINTR)
			goto retry;
		GSETERROR(err, "poll error: (%d) %s", errno, strerror(errno));
	}
	else if ((p.revents & POLLERR) || (p.revents & POLLHUP) || (p.revents & POLLNVAL)) {
		int e = sock_get_error(fd);
		GSETCODE(err, CODE_NETWORK_ERROR, "connect error: (%d) %s",
				e, strerror(e));
	}
	else if (p.revents & POLLOUT) {
		return fd;
	}
	else {
		GSETERROR(err, "connect unexpected error");
	}

	/* executed only upon error */
	metautils_pclose(&fd);
	errno = 0;
	return -1;
}


void
addr_info_clean(gpointer p)
{
	if (p)
		g_free(p);
}

void
addr_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		g_free(d);
}

gboolean
l4_address_split(const gchar * url, gchar ** host, gchar ** port)
{
	int len;
	gchar wrkUrl[512];

	if (!host || !port)
		return FALSE;

	g_strlcpy(wrkUrl, url, sizeof(wrkUrl));
	len = strlen(wrkUrl);

	if (*wrkUrl == '[') {	/*[IP]:PORT */
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon || last_semicolon - wrkUrl >= len)
			return FALSE;

		*(last_semicolon - 1) = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl + 1);
	}
	else {
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon || last_semicolon - wrkUrl >= len)
			return FALSE;

		*last_semicolon = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl);
	}
	return TRUE;
}

gint
addr_info_compare(gconstpointer a, gconstpointer b)
{
	addr_info_t addrA, addrB;

	if (!a || !b)
		return 0;
	if (a == b)
		return TRUE;

	memset(&addrA, 0, sizeof(addr_info_t));
	memset(&addrB, 0, sizeof(addr_info_t));

	g_memmove(&addrA, a, sizeof(addr_info_t));
	g_memmove(&addrB, b, sizeof(addr_info_t));

	if (addrA.type != addrB.type)
		return CMP(addrB.type,addrA.type);

	if (addrA.port != addrB.port)
		return CMP(addrB.port,addrA.port);

	switch (addrA.type) {
		case TADDR_V4:
			return memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v4));
		case TADDR_V6:
			return memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v6));
		default:
			g_assert_not_reached();
			return 0;
	}
}

gboolean
addr_info_equal(gconstpointer a, gconstpointer b)
{
	addr_info_t addrA, addrB;

	if (!a || !b)
		return FALSE;
	if (a == b)
		return TRUE;
	g_memmove(&addrA, a, sizeof(addr_info_t));
	g_memmove(&addrB, b, sizeof(addr_info_t));

	if (addrA.type != addrB.type)
		return FALSE;

	if (addrA.port != addrB.port)
		return FALSE;

	switch (addrA.type) {
	case TADDR_V4:
		return 0 == memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v4)) ? TRUE : FALSE;
	case TADDR_V6:
		return 0 == memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v6)) ? TRUE : FALSE;
	default:
		FATAL("Invalid address type");
		return FALSE;
	}
}

guint
addr_info_hash(gconstpointer k)
{
	addr_info_t addr;

	g_memmove(&addr, k, sizeof(addr_info_t));
	/*forces a NULL's padding if the address if ipv4 */
	if (addr.type == TADDR_V4)
		memset(
		    ((guint8 *) & (addr.addr.v4)) + sizeof(addr.addr.v4),
		    0x00, sizeof(addr.addr.v6) - sizeof(addr.addr.v4));

	return djb_hash_buf((guint8 *) &addr, sizeof(addr_info_t));
}

addr_info_t *
addr_info_from_service_str(const gchar *service)
{
	gchar **t = NULL;
	gchar **addr_tok = NULL;
	GError *local_error = NULL;
	addr_info_t* addr = NULL;

	t = g_strsplit(service, "|", 3);
	if(g_strv_length(t) != 3) {
		goto end_label;
	}

	addr_tok = g_strsplit(t[2], ":", 2);
	if(g_strv_length(addr_tok) != 2) {
		goto end_label;
	}

	addr = build_addr_info(addr_tok[0], atoi(addr_tok[1]), &local_error);

end_label:

	if(local_error)
		g_clear_error(&local_error);
	if(addr_tok)
		g_strfreev(addr_tok);
	if(t)
		g_strfreev(t);
	return addr;
}

