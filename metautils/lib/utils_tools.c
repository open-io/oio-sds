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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "metautils"
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metautils_internals.h"

static gchar *b2h[] =
{
	"00", "01", "02", "03", "04", "05", "06", "07",
	"08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
	"10", "11", "12", "13", "14", "15", "16", "17",
	"18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
	"20", "21", "22", "23", "24", "25", "26", "27",
	"28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
	"30", "31", "32", "33", "34", "35", "36", "37",
	"38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
	"40", "41", "42", "43", "44", "45", "46", "47",
	"48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
	"50", "51", "52", "53", "54", "55", "56", "57",
	"58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
	"60", "61", "62", "63", "64", "65", "66", "67",
	"68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
	"70", "71", "72", "73", "74", "75", "76", "77",
	"78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
	"80", "81", "82", "83", "84", "85", "86", "87",
	"88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
	"90", "91", "92", "93", "94", "95", "96", "97",
	"98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
	"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
	"A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
	"B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7",
	"B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
	"C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
	"C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
	"D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
	"D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
	"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7",
	"E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
	"F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
	"F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};

static gchar hexa[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

void
gslist_free_element(gpointer d, gpointer u)
{
	((GDestroyNotify) u) (d);
}

/* ------------------------------------------------------------------------- */

static inline void
_strv_pointers_concat(gchar **ptrs, gchar *d, gchar **src)
{
	gchar *s;
	register gchar c;

	while (NULL != (s = *(src++))) {
		*(ptrs++) = d;
		do {
			*(d++) = (c = *(s++));
		} while (c);
	}
}

static inline gsize
_strv_total_length(gchar **v)
{
	gsize total = 0;
	for (; *v; v++)
		total += 1+strlen(*v);
	return total;
}

gchar **
g_strdupv2(gchar **src)
{
	gsize header_size;
	gchar *raw;

	header_size = sizeof(void*) * (1+g_strv_length(src));

	raw = g_malloc0(header_size + _strv_total_length(src));
	_strv_pointers_concat((gchar**)raw, raw + header_size, src);
	return (gchar**)raw;
}

/* ------------------------------------------------------------------------- */

#include <poll.h>

gint
sock_to_write(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#define WRITE() do { \
		written = write(fd, ((guint8 *)buf) + nbSent, bufSize - nbSent); \
		if (written > 0) { \
			ui_written = written; \
			nbSent += ui_written; \
		} \
		if (written < 0) { \
			if (errno != EAGAIN && errno != EINTR) { \
				GSETERROR(err, "Write error (%s)", strerror(errno)); \
				return -1; \
			} \
		} \
} while (0)

	gsize ui_written;
	ssize_t written;
	gsize nbSent = 0;

	if (fd < 0 || !buf || bufSize <= 0) {
		GSETERROR(err, "invalid parameter");
		return -1;
	}

	WRITE();

	while (nbSent < bufSize) {
		int rc_poll;
		struct pollfd p;

		p.fd = fd;
		p.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
		p.revents = 0;

		errno = 0;
		rc_poll = poll(&p, 1, ms);

		if (rc_poll == 0) {	/*timeout */
			GSETCODE(err, ERRCODE_CONN_TIMEOUT, "Socket timeout");
			return (-1);
		}

		if (rc_poll == -1) {	/*poll error */
			if (errno != EINTR) {
				GSETERROR(err, "Socket error (%s) after %i bytes written", strerror(errno), nbSent);
				return (-1);
			}
			else {
				TRACE("poll interrupted (%s)", strerror(errno));
				continue;
			}
		}

		/*poll success */
		if (p.revents & POLLNVAL) {
			GSETERROR(err, "Socket (%d) is invalid after %i bytes sent", fd, nbSent);
			return -1;
		}
		if (p.revents & POLLERR) {
			int sock_err = sock_get_error(fd);
			GSETERROR(err, "Socket (%d) error after %i bytes written : (%d) %s", fd, nbSent, sock_err, strerror(sock_err));
			return -1;
		}
		if ((p.revents & POLLHUP)) {
			GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket (%d) closed after %i bytes written", fd, nbSent);
			return -1;
		}

		WRITE();
	}

	return nbSent;
}

gint
sock_to_read(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#define READ() do { \
		rc = read(fd, buf, bufSize); \
		if (rc > 0) \
			return rc; \
		if (rc == 0) { \
			GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d closed", fd); \
			return 0; \
		} \
		if (errno != EAGAIN && errno != EINTR) { \
			GSETCODE(err, errno_to_errcode(errno), "Read error (%s)", strerror(errno)); \
			return -1; \
		} \
	} while (0)

	gint rc;

	if (fd < 0 || !buf || bufSize <= 0) {
		GSETERROR(err, "invalid parameter");
		return -1;
	}

	/* on tente un premier READ, qui s'il reussit, nous epargne un appel a POLL */
	READ();

	/* pas de data en attente, donc attente protegee par le poll */
	for (;;) {
		struct pollfd p;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;

		/*wait for something to happen */
		rc = poll(&p, 1, ms);
		if (rc == 0) {	/*timeout */
			GSETCODE(err, ERRCODE_CONN_TIMEOUT, "Socket timeout");
			return -1;
		}

		if (rc < 0 && errno != EINTR) {	/*error */
			GSETCODE(err, errno_to_errcode(errno), "Socket error (%s)", strerror(errno));
			return -1;
		}
		if (rc == 1) {
			if (p.revents & POLLHUP && !(p.revents & POLLIN)) {
				GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d closed", fd);
				return 0;
			}
			if (p.revents & POLLERR) {
				int sock_err = sock_get_error(fd);
				GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d error : (%d) %s", fd, sock_err, strerror(sock_err));
				return 0;
			}
			READ();
		}
	}
}

gint
sock_to_read_size(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
	int n;
	gsize nbRead = 0;

	while (nbRead < bufSize) {
		n = sock_to_read(fd, ms, ((guint8 *) buf) + nbRead, bufSize - nbRead, err);
		if (n < 0) {
			GSETERROR(err, "Read failed after %i bytes", nbRead);
			return n;
		}
		else if (n == 0) {
			GSETERROR(err, "Socket closed after %i bytes read", nbRead);
			return n;
		}
		else
			nbRead += n;
	}
	return nbRead;
}

/* ------------------------------------------------------------------------- */

gint
sock_get_error(int fd)
{
	int sock_err = 0;
	socklen_t sock_err_size = sizeof(sock_err);

	if (fd < 0)
		return EINVAL;

	return (0 != getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_size)) ? -1 : sock_err;
}

gboolean
sock_set_tcpquickack(int fd, gboolean enabled)
{
	int opt_i = enabled ? 1 : 0;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);

	/*set the TCP_QUICKACK flag if the socket is a TCP/IP one */
	if (0 > getsockname(fd, (struct sockaddr *) &sa, &sa_len)) {
		GRID_WARN("cannot get the socket's address (%s)", strerror(errno));
		return FALSE;
	}

	if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6) {
		if (0 != setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void *) &opt_i, sizeof(opt_i))) {
			GRID_WARN("Cannot set the QUICKACK mode on socket %i (%s)", fd, strerror(errno));
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
sock_set_non_blocking(int fd, gboolean enabled)
{
	int flags;

	if (fd < 0) {
		errno = EAGAIN;
		return FALSE;
	}

	if (0 > (flags = fcntl(fd, F_GETFL)))
		return FALSE;

	flags = enabled ? flags|O_NONBLOCK : flags&(~O_NONBLOCK);

	if (!fcntl(fd, F_SETFL, flags))
		return TRUE;

	GRID_DEBUG("fd=%i set(O_NONBLOCK,%d): %d (%s)",
			fd, enabled, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_reuseaddr(int fd, gboolean enabled)
{
	int opt = enabled ? 1 : 0;
	if (!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(SO_REUSEADDR,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_keepalive(int fd, gboolean enabled)
{
	int opt = enabled ? 1 : 0;
	if (!setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(SO_KEEPALIVE,%d) : (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_nodelay(int fd, gboolean enabled)
{
	int opt = enabled ? 1 : 0;
	if (!setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(TCP_NODELAY,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_cork(int fd, gboolean enabled)
{
	int opt = enabled ? 1 : 0;
	if (!setsockopt(fd, IPPROTO_TCP, TCP_CORK, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(TCP_CORK,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_linger(int fd, int onoff, int linger)
{
	struct linger ls;
	ls.l_onoff = onoff;
	ls.l_linger = linger;

	if (!setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *) &ls, sizeof(ls)))
		return TRUE;
	WARN("fd=%i set(SO_LINGER,%d,%d): (%d) %s",
			fd, onoff, linger, errno, strerror(errno));
	return FALSE;
}


/* ------------------------------------------------------------------------- */

void
g_error_prefix_place(GError **e, const gchar *file, const gchar *func,
		int line)
{
	(void) file;
	gchar *tag = g_strdup_printf("(code=%d) [%s:%d]\n\t", (*e)->code, func, line);
	g_prefix_error(e, tag);
	g_free(tag);
}

void
g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...)
{
	GString *gstr;
	va_list localVA;

	if (!e)
		return;

	gstr = g_string_new("");

	if (line && func && file)
		g_string_printf(gstr, "(code=%i) [%s:%d] ", (code?code:(*e?(*e)->code:0)), func, line);

	va_start(localVA, fmt);
	g_string_append_vprintf(gstr, fmt, localVA);
	va_end(localVA);

	if (!*e)
		*e = g_error_new(g_quark_from_static_string(dom), code, gstr->str);
	else {
		g_string_append(gstr, "\n\t");
		g_prefix_error(e, gstr->str);
		if (code)
			(*e)->code = code;
	}

	g_string_free(gstr, TRUE);
}

void
g_error_transmit(GError **err, GError *e)
{
	if (err) {
		if (!*err) {
			g_propagate_error(err, e);
		}
		else {
			GSETMARK(err);
			GSETRAW(err, e->code, e->message);
			g_clear_error(&e);
		}
	}
	else {
		g_clear_error(&e);
	}
}

void
build_hash_path(const char *file_name, int hash_depth, int hash_size, char **hash_path)
{
	int file_len;
	char *file = g_strdup(file_name);
	char *ptr;
	int i;

	file_len = strlen(file);
	if (file_len < hash_depth * hash_size)
		return;

	*hash_path = g_try_new0(char, hash_depth * (hash_size + 1) + file_len + 1);
	if (*hash_path == NULL)
		return;

	/* Remove the starting / from file */
	if (file[0] == '/')
		ptr = file + 1;
	else
		ptr = file;

	for (i = 0; i < hash_depth; i++) {

		/* Add a / */
		g_strlcat(*hash_path, "/", strlen(*hash_path) + 2);

		/* Add a hash level */
		g_strlcat(*hash_path, ptr, strlen(*hash_path) + hash_size + 1);

		ptr = ptr + hash_size;
	}

	g_free(file);
}


static gsize
_buffer2str(const guint8 *s, size_t sS, char *d, size_t dS)
{
	gsize i, j;

	if (!s || !sS || !d || !dS)
		return 0;

	for (i=j=0; i<sS && j<(dS-1); i++) {
		register const gchar *h = b2h[((guint8*)s)[i]];
		d[j++] = h[0];
		d[j++] = h[1];
	}

	d[(j<dS ? j : dS-1)] = 0;

	return j;
}

void
buffer2str(const void *s, size_t sS, char *d, size_t dS)
{
	(void) _buffer2str(s, sS, d, dS);
}

gsize
container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize)
{
	return _buffer2str(id, sizeof(container_id_t), dst, dstsize);
}

void
name_to_id(const gchar * name, gsize nameLen, hash_sha256_t * id)
{
	SHA256((unsigned char *) name, nameLen, (unsigned char *) id);
}

void
name_to_id_v2(const gchar * name, gsize nameLen, const gchar * virtual_namespace, hash_sha256_t * id)
{
	gchar *full_name = NULL;
	if(!virtual_namespace) {
		/* old school client */
		name_to_id(name, nameLen, id);
		return;
	}
	full_name = g_strconcat(virtual_namespace, "/", name, NULL);
	
	SHA256((unsigned char *) full_name, strlen(full_name), (unsigned char *) id);

	if(full_name)
		g_free(full_name);
}

void
meta1_name2hash(container_id_t cid, const gchar *ns, const gchar *cname)
{
	gsize s;
	GChecksum *sum = NULL;

	sum = g_checksum_new(G_CHECKSUM_SHA256);

	if (ns && strchr(ns, '.')) {
		g_checksum_update(sum, (guint8*)ns, strlen(ns));
		g_checksum_update(sum, (guint8*)"/", 1);
	}
	if (cname)
		g_checksum_update(sum, (guint8*)cname, strlen(cname));

	memset(cid, 0, sizeof(container_id_t));
	s = sizeof(container_id_t);
	g_checksum_get_digest(sum, (guint8*)cid, &s);
	g_checksum_free(sum);
}

GSList *
gslist_split(GSList * list, gsize max)
{
	int i;
	GSList *sublist = NULL, *cursor = NULL, *ret = NULL;

	for (i = 1, cursor = list; cursor; cursor = cursor->next) {
		if (!cursor->data)
			continue;
		i++;
		sublist = g_slist_prepend(sublist, cursor->data);
		if (!(i % max)) {
			ret = g_slist_prepend(ret, sublist);
			sublist = NULL;
		}
	}
	if (sublist)
		ret = g_slist_prepend(ret, sublist);
	return ret;
}

void
gslist_chunks_destroy(GSList * list_of_lists, GDestroyNotify destroy_func)
{
	GSList *cursor;

	if (!list_of_lists)
		return;

	if (destroy_func) {
		for (cursor = list_of_lists; cursor; cursor = cursor->next) {
			GSList *nextList = (GSList *) cursor->data;

			if (!nextList)
				continue;
			g_slist_foreach(nextList, gslist_free_element, destroy_func);
			g_slist_free(nextList);
		}
	}
	else {
		for (cursor = list_of_lists; cursor; cursor = cursor->next) {
			GSList *nextList = (GSList *) cursor->data;

			if (!nextList)
				continue;
			g_slist_free(nextList);
		}
	}

	g_slist_free(list_of_lists);
}


static gboolean
_hex2bin(const guint8 *s, gsize sS, guint8 *d, register gsize dS, GError** error)
{
	if (!s || !d) {
		GSETERROR(error, "src or dst is null");
		return FALSE;
	}

	if (sS < dS * 2) {
		GSETERROR(error, "hexadecimal form too short");
		return FALSE;
	}

	while ((dS--) > 0) {
		register int i0, i1;

		i0 = hexa[*(s++)];
		i1 = hexa[*(s++)];

		if (i0<0 || i1<0) {
			GSETERROR(error, "Invalid hex");
			return FALSE;
		}

		*(d++) = (i0 & 0x0F) << 4 | (i1 & 0x0F);
	}

	return TRUE;
}

gboolean
hex2bin(const gchar *s, void *d, gsize dS, GError** error)
{
	return _hex2bin((guint8*)s, (s?strlen(s):0), (guint8*)d, dS, error);
}

gboolean
container_id_hex2bin(const gchar *s, gsize sS, container_id_t *d,
		GError ** error)
{
	return _hex2bin((guint8*)s, sS, (guint8*)d, 32, error);
}


/* ------------------------------------------------------------------------- */

void
g_slist_free_agregated(GSList * list2)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_free((GSList *) (cursor2->data));
	g_slist_free(list2);
}

void
g_slist_foreach_agregated(GSList * list2, GFunc callback, gpointer user_data)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_foreach((GSList *) (cursor2->data), callback, user_data);
}

static GSList *
gslist_hollow_copy(GSList *orig)
{
	GSList *l, *result;
	
	result = NULL;
	for (l=orig; l ;l=l->next) {
		if (l->data)
			result = g_slist_prepend(result, l->data);
	}
	return result;
}

GSList *
g_slist_agregate(GSList * list, GCompareFunc comparator)
{
	GSList *resL2 = NULL;	/*a list of lists of chunk_info_t */
	GSList *sorted = NULL;	/*a list of chunk_info_t */
	GSList *cursor1 = NULL;
	GSList *last_agregate = NULL;

	if (!list)
		return NULL;

	sorted = gslist_hollow_copy(list);
	if (!sorted)
		return NULL;
	sorted = g_slist_sort(sorted, comparator);
	if (!sorted)
		return NULL;

	for (cursor1 = sorted; cursor1; cursor1 = cursor1->next) {
		if (!cursor1->data)
			continue;
		if (last_agregate && 0 > comparator(last_agregate->data, cursor1->data)) {
			resL2 = g_slist_prepend(resL2, last_agregate);
			last_agregate = NULL;
		}
		last_agregate = g_slist_prepend(last_agregate, cursor1->data);
	}

	if (last_agregate)
		resL2 = g_slist_prepend(resL2, last_agregate);

	g_slist_free (sorted);
	return g_slist_reverse(resL2);
}

gchar **
buffer_split(const void *buf, gsize buflen, const gchar * separator, gint max_tokens)
{
	gchar **sp, *tmp;

	if (!buf || buflen <= 0)
		return NULL;
	
	tmp = g_strndup((gchar*)buf, buflen);
	sp = g_strsplit(tmp, separator, max_tokens);
	g_free(tmp);
	return sp;
}

gsize
strlen_len(const guint8 * s, gsize l)
{
	gsize i = 0;

	if (!s)
		return 0;
	for (i = 0; i < l; i++) {
		if (!*(s + i))
			return i;
	}
	return i;
}

gint
gerror_get_code(GError * err)
{
	return err ? err->code : 0;
}

const gchar *
gerror_get_message(GError * err)
{
	if (!err)
		return "no error";
	if (!err->message)
		return "no error message";
	return err->message;
}

guint
container_id_hash(gconstpointer k)
{
	const guint *b;
	guint max, i, h;

	if (!k)
		return 0;
	b = k;
	max = sizeof(container_id_t) / sizeof(guint);
	h = 0;
	for (i = 0; i < max; i++)
		h = h ^ b[i];
	return h;
}

gboolean
container_id_equal(gconstpointer k1, gconstpointer k2)
{
	return k1 && k2 && ((k1 == k2)
	    || (0 == memcmp(k1, k2, sizeof(container_id_t))));
}

void
g_free1(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		g_free(p1);
}

void
g_free2(gpointer p1, gpointer p2)
{
	(void) p1;
	if (p2)
		g_free(p2);
}

/* ----------------------------------------------------------------------------------- */

gboolean
convert_chunk_text_to_raw(const struct chunk_textinfo_s* text_chunk, struct meta2_raw_chunk_s* raw_chunk, GError** error)
{
	if (text_chunk == NULL) {
		GSETERROR(error, "text_chunk is null");
		return FALSE;
	}

	memset(raw_chunk, 0, sizeof(struct meta2_raw_chunk_s));

	if (text_chunk->id != NULL
		&& !hex2bin(text_chunk->id, &(raw_chunk->id.id), sizeof(hash_sha256_t), error)) {
			GSETERROR(error, "Failed to convert chunk id from hex to bin");
			return FALSE;
	}

	if (text_chunk->hash != NULL
		&& !hex2bin(text_chunk->hash, &(raw_chunk->hash), sizeof(chunk_hash_t), error)) {
			GSETERROR(error, "Failed to convert chunk hash from hex to bin");
			return FALSE;
	}

	if (text_chunk->size != NULL)
		raw_chunk->size = g_ascii_strtoll(text_chunk->size, NULL, 10);

	if (text_chunk->position != NULL)
		raw_chunk->position = g_ascii_strtoull(text_chunk->position, NULL, 10);

	if (text_chunk->metadata != NULL)
		raw_chunk->metadata = metautils_gba_from_string(text_chunk->metadata);

	return TRUE;
}

gboolean
data_is_zeroed(const void *data, gsize data_size)
{
        gchar zero[data_size];

        if (data == NULL)
                return TRUE;

        memset(zero, 0, sizeof(zero));

        if (0 == memcmp(zero, data, data_size))
                return TRUE;

        return FALSE;
}

static gboolean
_chunk_hash_is_null(const chunk_hash_t chunk_hash)
{
	return data_is_zeroed(chunk_hash, sizeof(chunk_hash_t));
}

static gboolean
_chunk_id_is_null(const chunk_id_t *chunk_id)
{
	return data_is_zeroed(chunk_id, sizeof(chunk_id_t));
}

static gboolean
_container_id_is_null(const container_id_t container_id)
{
	return data_is_zeroed(container_id, sizeof(container_id_t));
}

gboolean
convert_chunk_raw_to_text(const struct meta2_raw_content_s* raw_content, struct chunk_textinfo_s* text_chunk, GError** error)
{
	gchar buffer[2048];
	struct meta2_raw_chunk_s* raw_chunk = NULL;

	if (raw_content == NULL) {
		GSETERROR(error, "raw_content is null");
		return FALSE;
	}

	if (raw_content->raw_chunks == NULL) {
		GSETERROR(error, "raw_chunk list in content is null");
		return FALSE;
	}

	if (g_slist_length(raw_content->raw_chunks) == 0) {
		GSETERROR(error, "raw_chunk list in content is empty");
		return FALSE;
	}

	if (g_slist_length(raw_content->raw_chunks) > 1) {
		GSETERROR(error, "raw_chunk list in content contains more than a chunk, can't choose which one to use");
		return FALSE;
	}

	raw_chunk = g_slist_nth_data(raw_content->raw_chunks, 0);

	memset(text_chunk, 0, sizeof(struct chunk_textinfo_s));

	if (!_chunk_id_is_null( &(raw_chunk->id) )) {
		memset(buffer, '\0', sizeof(buffer));
		chunk_id_to_string(&(raw_chunk->id), buffer, sizeof(buffer));
		text_chunk->id = g_strdup(buffer);
	}

	if (strlen(raw_content->path) > 0)
		text_chunk->path = g_strdup(raw_content->path);

	text_chunk->size = g_strdup_printf("%"G_GINT64_FORMAT, raw_chunk->size);
	text_chunk->position = g_strdup_printf("%"G_GUINT32_FORMAT, raw_chunk->position);

	if (!_chunk_hash_is_null(raw_chunk->hash)) {
		memset(buffer, '\0', sizeof(buffer));
		buffer2str(raw_chunk->hash, sizeof(chunk_hash_t), buffer, sizeof(buffer));
		text_chunk->hash = g_strdup(buffer);
	}

	if (raw_chunk->metadata != NULL)
		text_chunk->metadata = g_strndup((gchar*)raw_chunk->metadata->data, raw_chunk->metadata->len);

	if (!_container_id_is_null( raw_content->container_id)) {
		memset(buffer, '\0', sizeof(buffer));
		container_id_to_string(raw_content->container_id, buffer, sizeof(buffer));
		text_chunk->container_id = g_strdup(buffer);
	}

	return TRUE;
}

gchar*
key_value_pair_to_string(key_value_pair_t * kv)
{
        gchar *str_value = NULL, *result = NULL;
        gsize str_value_len;

        if (!kv)
                return g_strdup("KeyValue|NULL|NULL");

        if (!kv->value)
                return g_strconcat("KeyValue|",(kv->key?kv->key:"NULL"),"|NULL", NULL);

        str_value_len = 8 + 3 * kv->value->len;
        str_value = g_malloc0(str_value_len);
        metautils_gba_data_to_string(kv->value, str_value, str_value_len);

        result = g_strconcat("KeyValue|",(kv->key?kv->key:"NULL"), "|", str_value, NULL);
        g_free(str_value);

        return result;
}

GSList*
metautils_array_to_list(void **orig)
{
	GSList *result = NULL;

	while (orig && *orig)
		result = g_slist_prepend(result, *(orig++));

	return g_slist_reverse(result);
}

GPtrArray*
metautils_list_to_gpa(GSList *orig)
{
	GPtrArray *gpa = g_ptr_array_new();
	for (; orig ; orig=orig->next)
		g_ptr_array_add(gpa, orig->data);
	g_ptr_array_add(gpa, NULL);
	return gpa;
}

void**
metautils_list_to_array(GSList *orig)
{
	return g_ptr_array_free(metautils_list_to_gpa(orig), FALSE);
}

GSList*
metautils_gpa_to_list(GPtrArray *gpa)
{
	GSList *result = NULL;
	guint i;

	for (i=0; i < gpa->len ;i++) {
		if (gpa->pdata[i])
			result = g_slist_prepend(result, gpa->pdata[i]);
	}

	return g_slist_reverse(result);
}

static inline const gchar *
strchr_guarded(const gchar *start, const gchar *end, gchar needle)
{
	for (; start < end ;start++) {
		if (needle == *start)
			return start;
	}
	return NULL;
}

static inline gboolean
strn_isprint(const gchar *start, const gchar *end)
{
	while (start < end) {
		register gchar c = *(start++);
		if (!g_ascii_isprint(c) && !g_ascii_isspace(c) && c!='\n')
			return FALSE;
	}
	return TRUE;
}

gchar **
metautils_decode_lines(const gchar *start, const gchar *end)
{
	GSList *lines = NULL;
	const gchar *p;

	if (!strn_isprint(start, end))
		return NULL;

	while (start < end) {
		for (; start < end && *start == '\n'; start++);

		if (!(p = strchr_guarded(start, end, '\n'))) {
			gchar *l = g_strndup(start, end-start);
			lines = g_slist_prepend(lines, l);
			break;
		}
		else {
			if (p > start) {
				gchar *l = g_strndup(start, p-start);
				lines = g_slist_prepend(lines, l);
			}
			start = p + 1;
		}
	}

	gchar **result = (gchar**) metautils_list_to_array(lines);
	g_slist_free(lines);
	return result;
}

GByteArray*
metautils_encode_lines(gchar **strv)
{
	GByteArray *gba;

	gba = g_byte_array_new();
	if (strv) {
		gchar **p;
		for (p=strv; *p ;++p) {
			g_byte_array_append(gba, (guint8*)*p, strlen(*p));
			g_byte_array_append(gba, (guint8*)"\n", 1);
		}
	}

	g_byte_array_append(gba, (guint8*)"", 1);
	g_byte_array_set_size(gba, gba->len - 1);
	return gba;
}

struct meta1_service_url_s*
meta1_unpack_url(const gchar *url)
{
	gchar *type, *host, *args;
	struct meta1_service_url_s *result;

	UTILS_ASSERT(url != NULL);

	int len = strlen(url);
	gchar *tmp = g_alloca(len+1);
	g_strlcpy(tmp, url, len+1);

	if (!(type = strchr(tmp, '|')))
		return NULL;
	*(type++) = '\0';

	if (!(host = strchr(type, '|')))
		return NULL;
	*(host++) = '\0';

	if (!(args = strchr(host, '|')))
		return NULL;
	*(args++) = '\0';

	result = g_malloc0(sizeof(*result) + strlen(args) + 1);
	result->seq = g_ascii_strtoll(url, NULL, 10);
	g_strlcpy(result->srvtype, type, sizeof(result->srvtype)-1);
	g_strlcpy(result->host, host, sizeof(result->host)-1);
	strcpy(result->args, args);

	return result;
}

void
meta1_service_url_clean(struct meta1_service_url_s *u)
{
	if (u)
		g_free(u);
}

void
meta1_service_url_vclean(struct meta1_service_url_s **uv)
{
	struct meta1_service_url_s **p;

	if (!uv)
		return;
	for (p=uv; *p ;p++)
		meta1_service_url_clean(*p);
	g_free(uv);
}

gchar*
meta1_pack_url(struct meta1_service_url_s *u)
{
	if (!u)
		return NULL;
	return g_strdup_printf("%"G_GINT64_FORMAT"|%s|%s|%s",
		u->seq, u->srvtype, u->host, u->args);
}

gboolean
meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst)
{
	return l4_address_init_with_url(dst, u->host, NULL);
}

gboolean
meta1_strurl_get_address(const gchar *str, struct addr_info_s *dst)
{
	gboolean rc;
	struct meta1_service_url_s *u;

	u = meta1_unpack_url(str);
	rc = meta1_url_get_address(u, dst);
	g_free(u);

	return rc;
}

gsize
metautils_strlcpy_physical_ns(gchar *d, const gchar *s, gsize dlen)
{
	register gsize count = 0;
	register gchar c;

	for (; dlen > 0 && (c = *(s++)) && c != '.' && count<dlen ;count++) { *(d++) = c; }

	*d = '\0';

	for (; (c = *(s++)) && c != '.' ;count++) { }

	return count;
}

gboolean
metautils_cfg_get_bool(const gchar *value, gboolean def)
{
	static gchar *array_yes[] = {"yes", "true", "on", "enable", "enabled", NULL};
	static gchar *array_no[] = {"no", "false", "off", "disable", "disabled", NULL};
	gchar **s;

	if (!value)
		return def;

	for (s=array_yes; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return TRUE;
	}

	for (s=array_no; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return FALSE;
	}

	return def;
}

int
metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored)
{
	(void) ignored;
	return g_strcmp0(a, b);
}

