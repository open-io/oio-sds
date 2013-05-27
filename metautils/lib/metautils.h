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

/**
 * @file metautils.h
 * The metautils API
 */

#ifndef __METAUTILS__H__
# define __METAUTILS__H__

/**
 * @defgroup metautils_utils Metautils
 * @ingroup metautils
 * @{
 */

# ifndef LOG_DEFAULT_DOMAIN
#  define LOG_DEFAULT_DOMAIN "default"
# endif

# ifndef G_LOG_DOMAIN
#  ifdef LOG_DOMAIN
#   define G_LOG_DOMAIN LOG_DOMAIN
#  else
#   define G_LOG_DOMAIN LOG_DEFAULT_DOMAIN
#  endif
# endif

# ifndef LOG_DOMAIN
#  ifdef G_LOG_DOMAIN
#   define LOG_DOMAIN G_LOG_DOMAIN
#  else
#   define LOG_DOMAIN LOG_DEFAULT_DOMAIN
#  endif
# endif

# ifndef API_VERSION
#  define API_VERSION ((const char*)"")
# endif

# include <sys/socket.h>
# include <netinet/in.h>
# include <unistd.h>

# include <glib.h>

# include <metatypes.h>
# include <hashstr.h>
# include <loggers.h>
# include <resolv.h>

# ifdef HAVE_EXTRA_ASSERT
#  define ASSERT_EXTRA(X) g_assert(X)
# else
#  define ASSERT_EXTRA(X)
# endif

# ifdef HAVE_ASSERT_UTILS
#  define UTILS_ASSERT(X) g_assert(X)
# else
#  define UTILS_ASSERT(X)
# endif

/*
 * Some well known service types
 */
# define NAME_SRVTYPE_META0 "meta0"
# define NAME_SRVTYPE_META1 "meta1"
# define NAME_SRVTYPE_META2 "meta2"
# define NAME_SRVTYPE_RAWX  "rawx"
# define NAME_SRVTYPE_SOLR  "solr"

/*
 * Some well known service tags macro names
 */
# define NAME_MACRO_SPACE_NAME "stat.space"
# define NAME_MACRO_SPACE_TYPE "space"

# define NAME_MACRO_CPU_NAME "stat.cpu"
# define NAME_MACRO_CPU_TYPE "cpu"

# define NAME_MACRO_IOIDLE_NAME "stat.io"
# define NAME_MACRO_IOIDLE_TYPE "io"

# define NAME_MACRO_GRIDD_TYPE "gridd.macro"

# define NAME_TAGNAME_RAWX_VOL "tag.vol"
# define NAME_TAGNAME_RAWX_FIRST "tag.first"
# define NAME_TAGNAME_RAWX_LOC "tag.loc"
# define NAME_TAGNAME_REQIDLE "stat.req_idle"

#define ZERO(A) memset((A), 0x00, sizeof(A));

#define TYPE_TO_STRLEN(T)  ((sizeof(T)*2)+1)
#define STRLEN_CHUNKID     TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_CONTAINERID TYPE_TO_STRLEN(container_id_t)
#define STRLEN_CHUNKHASH   TYPE_TO_STRLEN(hash_md5_t)
#define STRLEN_ADDRINFO    sizeof("[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:SSSSS")

/**
 * @defgroup metautils_errors GError features
 * @ingroup metautils_utils
 * @{
 */

/* Some well known codes used by read functions */
# define ERRCODE_PARAM 1
# define ERRCODE_CONN_REFUSED 2
# define ERRCODE_CONN_RESET 3
# define ERRCODE_CONN_CLOSED 4
# define ERRCODE_CONN_TIMEOUT 5
# define ERRCODE_CONN_NOROUTE 6
# define ERRCODE_CONN_NOTCONNECTED 7

# define GSETCODE(e,C,FMT,...) g_error_trace (e, LOG_DOMAIN, (C), __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETERROR(e,FMT,...)  g_error_trace (e, LOG_DOMAIN, 0,   __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETMARK(e) g_error_prefix_place(e, __FILE__, __FUNCTION__, __LINE__);
# define GSETRAW(e,CODE,MSG)  g_error_trace (e, LOG_DOMAIN, CODE, 0,0,0 , MSG)

#define GQ() g_quark_from_static_string(G_LOG_DOMAIN)
#define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)

/**
 */
struct meta1_service_url_s
{
	gint64 seq;        /**<  */
	gchar srvtype[LIMIT_LENGTH_SRVTYPE]; /**<  */
	gchar host[256];   /**<  */
	gchar args[1];     /**<  */
};

/**
 * @param url
 * @return
 */
struct meta1_service_url_s* meta1_unpack_url(const gchar *url);

/**
 * @param u
 */
void meta1_service_url_clean(struct meta1_service_url_s *u);

/**
 * @param uv
 */
void meta1_service_url_vclean(struct meta1_service_url_s **uv);

/**
 * @param u
 * @return
 */
gchar* meta1_pack_url(struct meta1_service_url_s *u);

/**
 * @param u
 * @param dst
 * @return
 */
gboolean meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst);

gboolean meta1_strurl_get_address(const gchar *str, struct addr_info_s *dst);

/**
 * Sets the error structure pointed by the first argument, keeping trace of the
 * previous content of this structure.
 * 
 * @param e
 * @param dom
 * @param code
 * @param fmt
 * @param ...
 */
void g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...);

void g_error_transmit(GError **err, GError *e);

/**
 * @param e
 * @param file
 * @param func
 * @param line
 */
void g_error_prefix_place(GError **e, const gchar *file, const gchar *func,
	int line);


/**
 * @param err
 * @return
 */
gint gerror_get_code(GError * err);


/**
 * @param err
 * @return
 */
const gchar *gerror_get_message(GError * err);

/** @} */

/**
 * @defgroup metautils_l4v L4V codec
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills the four first bytes of the buffer buffer with its own size
 * in bytes minus 4 bytes.
 *
 * @param src the target buffer
 * @param srcSize the size of the buffer, must be >= 4
 * @param error an error structure set in case of error
 *
 * @return 1 in case of success, 0 in case of error
 */
gint l4v_prepend_size(void *src, gsize srcSize, GError ** error);


/**
 * Read the encoded size of the buffer.
 *
 * @param src the buffer that must be inspected
 * @param size the size of the whole buffer, must be >= 4
 * @param error an error structure set in case of error
 *
 * @return 1 if the size have been read and filled in the pointer,
 *         0 in case of error (err is set)
 */
gint l4v_get_size(void *src, gsize * size, GError ** error);


/**
 * Tells whether the size of the buffer is longer or equal to the size
 * encoded in the buffer itself.
 *
 * @param src the inspected buffer
 * @param srcSize the announced size of the buffer
 * @param error an error structure set in case of error
 *
 * @return 1 in case of success and answer is TRUE, 0 for a success
 *         ans FALSE, -1 for a failure (err is set)
 */
gint l4v_is_complete(void *src, gsize srcSize, GError ** error);


/**
 * Get a pointer to the start of the carried memory buffer.
 *
 * dst should be src+4 if the size is sufficient.
 *
 * @param src the source buffer
 * @param srcSize the size of the source buffer, must be > 4
 * @param dst a not-NULL pointer that will store the start of the payload
 *            data.
 * @param dstsize a not-NULL pointer that will hold the size of dst.
 * @param error an error structure set in case of error
 *
 * @return
 */
gint l4v_extract(void *src, gsize srcSize, void **dst, gsize * dstsize, GError ** error);


/**
 * Copy src to dst+4 and prepend dstsize in dst.
 *
 * In theory, src and dst could even overlap.
 *
 * @see l4v_prepend_size()
 * @param src the source buffer
 * @param srcSize the size of the source buffer
 * @param dst the destination buffer
 * @param dstsize the size of the destination buffer.
 * @param error an error structure set in case of error
 *
 * @return 1 in case of success, 0 in case of error (err is set)
 */
gint l4v_fill(void *src, gsize srcSize, void *dst, gsize dstsize, GError ** error);


/**
 * Reads a whole L4V enclosed buffer from the file descriptor fd.
 *
 * @param fd an opened an connected file descriptor.
 * @param ms the maximal time in milliseconds spent in network latencies
 * @param err an error structure set in case of error
 *
 * @return the data read under the form of a GLib byte Array
 */
GByteArray *l4v_read(int fd, gint ms, GError ** err);


/**
 * Reads a whole L4V enclosed buffer from the file descriptor fd.
 *
 * @param fd an opened an connected file descriptor.
 * @param ms1 the maximal time spent to wait the header of the data
 *        (the size on 4 bytes)
 * @param msAll the maximal time spent to wait the body of the data
 * @param err an error structure set in case of error
 *
 * @return the data read under the form of a GLib byte Array
 */
GByteArray *l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err);

/** @} */

/**
 * @defgroup metautils_sockets Sockets utilities
 * @ingroup metautils_utils
 * @{
 */

/**
 * Writes data in a file descriptor with a given maximum amount of time
 * spent in network latencies.
 *
 * This function manages the case if the socket is blocking or not. If
 * fd is a blocking socket, there is n quranty that the sending will
 * be time-bounded.
 *
 * @param fd an opened and connected socket file descriptor
 * @param ms the maximum latency
 * @param buf a pointer to the buffer to be sent
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 *
 * @return the number of bytes spent in case of success, -1 if an
 *         error occured.
 */
gint sock_to_write(int fd, gint ms, void *buf, gsize bufSize, GError ** err);


/**
 * Read bytes from the socket file descriptor, spending at most a given
 * number of milli seconds.
 *
 * This function manages the case if the socket is blocking or not. If
 * fd is a blocking socket, there is n quranty that the sending will
 * be time-bounded.
 *
 * &@param fd an opened and connected socket file descriptor
 * @param ms the maximum latency
 * @param buf a pointer to the buffer to be filled withread data.
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 *
 * @return the positive number of bytes read, or 0 in case of time-out,
 *         or -1 in case of error (an err is set).
 */
gint sock_to_read(int fd, gint ms, void *buf, gsize bufSize, GError ** err);


/**
 * Reads exactly 'bufSize' bytes during at most 'ms' milliseconds
 * and fills the given buffer with the data.
 *
 * @param fd an opened and connected socket 
 * @param ms the maximum latency of the operation
 * @param buf a pointer to the buffer to be filled withread data.
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 * @return
 */
gint sock_to_read_size(int fd, gint ms, void *buf, gsize bufSize, GError ** err);

/**
 * Performs the getsockopt() call to retrieve error associated with the socket 'fd'.
 *
 * @param fd a valid socket
 * @return a errno code
 */
gint sock_get_error(int fd);

/**
 * Set non blocking 
 *
 * @param fd the socket file desciptor to be altered 
 * @param err an error structure set in case of error
 * @return 1 in case of success, 0 in case of error.
 */
gboolean sock_set_non_blocking(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 */
gboolean sock_set_tcpquickack(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_reuseaddr(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_keepalive(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_nodelay(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_cork(int fd, gboolean enabled);

/**
 * @param fd
 * @param onoff
 * @param linger
 * @return
 */
gboolean sock_set_linger(int fd, int onoff, int linger);

/** @} */

/**
 * @defgroup metautils_loggersv1 Logging V1 (DEPRECATED)
 * @ingroup metautils_utils
 * @{
 */

#include <loggers.h>

/** @} */

/* ------------------------------------------------------------------------- */

/**
 * @defgroup metautils_common Miscellanous features
 * @ingroup metautils_utils
 * @{
 */

/**
 * Uses sigprocmask to block a lot of signals
 */
void metautils_ignore_signals(void);

/**
 * Copies in 'd' the part of 's' representing a valid physical namespace.
 *
 * @param d the target buffer to store the physical NS
 * @param s a source string starting with the physical namespace
 * @param dlen the size of the target buffer
 * @return the size of the physical namespace in the source string
 */
gsize metautils_strlcpy_physical_ns(gchar *d, const gchar *s, gsize dlen);

/**
 * @param src
 * @return to be freed with g_free(), not g_strfreev()
 */
gchar ** g_strdupv2(gchar **src);

/**
 * @param timer
 */
#define START_TIMER(timer) g_timer_start(timer)


/**
 * @param timer
 * @param action_str
 */
#define STOP_TIMER(timer, action_str) do { \
	g_timer_stop(timer);\
	DEBUG_DOMAIN("timer", "Action [%s] in thread[%p] took %f sec", action_str, g_thread_self(), g_timer_elapsed(timer, NULL)); \
} while (0)

/**
 * Calls g_strcmp0(a,b) and ignores its third argument.
 *
 * @see g_strcmp0
 */
int metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored);

/**
 * @param value
 * @param def
 * @return
 */
gboolean metautils_cfg_get_bool(const gchar *value, gboolean def);

/**
 * Builds a NULL-terminated array with the pointers extracted from orig.
 *
 * @param orig
 * @return
 */
void** metautils_list_to_array(GSList *orig);

/**
 * @param orig
 * @return
 */
GPtrArray* metautils_list_to_gpa(GSList *orig);

/**
 * @param gpa
 * @return
 */
GSList* metautils_gpa_to_list(GPtrArray *gpa);

/**
 * @param orig
 * @return
 */
GSList* metautils_array_to_list(void **orig);

/**
 * @param start
 * @param end
 * @return
 */
gchar** metautils_decode_lines(const gchar *start, const gchar *end);

/**
 * @param strv
 * @return
 */
GByteArray* metautils_encode_lines(gchar **strv);

/**
 * @param src
 * @param src_size
 * @param dst
 * @param dst_size
 * @param dst_bitlength
 * @return the size of the string written, not including the trailing '\0'
 */
gsize metautils_hash_content_path(const gchar *src, gsize src_size,
	gchar *dst, gsize dst_size, gsize dst_bitlength);


/**
 * Convert an hexa string to its binary form
 *
 * @param src the hexa string to convert
 * @param dst the allocated destination of the binary form
 * @param dst_size
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set);
 */
gboolean hex2bin(const gchar * src, void * dst, gsize dst_size, GError** error);


/**
 * Fills d (which size is dS) with the hexadecimal alpha-numerical representation
 * of the content of s (which size is sS)
 *
 * @param s
 * @param sS
 * @param d
 * @param dS
 */
void buffer2str(const void *s, size_t sS, char *d, size_t dS);


/**
 * Splits the given buffer (considered as a non NULL-terminated) into 
 * newly allocated tokens (wrapping g_strsplit())
 *
 * @param buf
 * @param buflen
 * @param separator
 * @param max_tokens
 * @return
 */
gchar **buffer_split(const void *buf, gsize buflen, const gchar * separator, gint max_tokens);


/**
 * Check a segment of data is filled with 0
 *
 * @param data the segment of data to check
 * @param data_size the size of the segment to check (in bytes)
 * @return TRUE if the segment is filled with 0, FALSE otherwise
 */
gboolean data_is_zeroed(const void *data, gsize data_size);


/**
 * @param s
 * @param l
 * @return
 */
gsize strlen_len(const guint8 * s, gsize l);


/**
 * Fills the hash_path argument with a hash of the given file_name.
 * The hash is a sequence of hash_depth subdirectories, whose each
 * directory's name is hash_size long, 
 *
 * @param file_name
 * @param hash_depth
 * @param hash_size
 * @param hash_path
 */
void build_hash_path(const char *file_name, int hash_depth, int hash_size, char **hash_path);


/**
 * Split a GSList in a list of GSList each containg a max elements
 *
 * @param list a GSList to split
 * @param max the max number of element in each sublist
 *
 * @return a GSList of all splitted lists
 */
GSList *gslist_split(GSList * list, gsize max);


/**
 * Convinient func to use with g_slist_foreach
 * Pass the clean func has data arguement */
void gslist_free_element(gpointer d, gpointer u);


/**
 * Frees a list of lists, at least the list elements structures and also
 * their elements if the destructor callback has been provided.
 * 
 * Assumes the list parameter itself contains lists (a GSList* of GSlist*).
 *
 * @param list_of_lists a single linked list (may be NULL)
 * @param destroy_func a desturctor function pointer
 */
void gslist_chunks_destroy(GSList * list_of_lists, GDestroyNotify destroy_func);


/**
 * agregate the given list of chunk_info_t
 * the chunks with the same position will be grouped in a sublist.
 * The result will then be a list of lists of chunk_info_t with the
 * same position field.
 *
 * @param list
 * @param comparator
 * @return
 */
GSList *g_slist_agregate(GSList * list, GCompareFunc comparator);


/**
 * frees the list of lists and all the sublists
 *
 * @param list2
 */
void g_slist_free_agregated(GSList * list2);


/**
 * Runs all the elements of the sublist, and applies the callback
 * with the given user_data on each element.
 *
 * @param list
 * @param callback
 * @param user_data
 */
void g_slist_foreach_agregated(GSList * list, GFunc callback, gpointer user_data);


/**
 * @param p1
 * @param p2
 */
void g_free1(gpointer p1, gpointer p2);


/**
 * @param p1
 * @param p2
 */
void g_free2(gpointer p1, gpointer p2);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_addrinfo Addrinfo (IP:PORT) features
 * @ingroup metautils_utils
 * @{
 */

/**
 * @param a
 * @param b
 * @return
 */
gboolean addr_info_equal(gconstpointer a, gconstpointer b);

/**
 * @param a
 * @param b
 * @return
 */
gint addr_info_compare(gconstpointer a, gconstpointer b);

/**
 * @param k
 * @return
 */
guint addr_info_hash(gconstpointer k);


/**
 *	Build a new filled addr_info_t struct
 *
 *	@param ip the addr in string format
 *	@param port the port
 *	@param err
 *	@return a new addr_info_t pointer which must be freed with g_free()
 */
addr_info_t *build_addr_info(const gchar * ip, int port, GError ** err);


/**
 * Splits the given IP/PORT couple assuming the following formats:
 * - [MAYBE-AGREGATED-IPv6]:PORT
 * - DOTTED-NUMERICAL-IPv4:PORT
 */
gboolean l4_address_split(const gchar * url, gchar ** host, gchar ** port);


/**
 * Inits the given address with the given texual representation (as accepted by l4_address_split()).
 * @param dst
 * @param url
 * @param err
 * @return
 */
gboolean l4_address_init_with_url(addr_info_t * dst, const gchar * url, GError ** err);


/**
 * Map the addr_info_t structure in the corresponding sockaddr structure.
 *
 * The pointed sockaddr structure will be altered in place and must be
 * large enough to store at least one IPv6 address. We recommand to use a
 * struct sockaddr_storage address (see the POSIX-2001 norm).
 *
 * @see addrinfo_from_sockaddr()
 * @param ai a not-NULL pointer to a valid addr_info_t structure
 * @param sa the sockaddr to be filled with the given addr_info_t address
 * @param saSize the size of the sockaddr address
 *
 * @return 1 if the mapping succeeded, 0 in case of error
 */
gint addrinfo_to_sockaddr(const addr_info_t * ai, struct sockaddr *sa, gsize * saSize);


/**
 * Map the given sockaddr structure in the given addr_info_t structure.
 *
 * @see addrinfo_to_sockaddr()
 * @param ai the strucutre to be filled
 * @param sa the source sockaddr
 * @param saSize the size of the source sockaddr
 *
 * @return 1 if the mapping succeeded, 0 in case of error
 */
gint addrinfo_from_sockaddr(addr_info_t * ai, struct sockaddr *sa, gsize saSize);


/**
 * Opens a non-blocking TCP/IP socket and connects to a remote host
 * identified by the given addr_info_t strucutre.
 *
 * Internally, the function will be mapped to a sockaddr structure used
 * with regular sockets.
 *
 * @param a the.ddress to connect to
 * @param ms the maximum of time spent in network latencies. If this duration
 *           is reached, its is an error.
 * @param err filled with a pointer to an error strucutre if an error occurs
 *
 * @return the opened socket in case of success of -1 in case of error (err
 *         is set)
 */
gint addrinfo_connect(const addr_info_t * a, gint ms, GError ** err);


/**
 * Writes in dst a pretty textual representation of the given addr_info_t.
 *
 * the written bytes will always be NULL terminated as soon as the given
 * size of the buffer is at most 1.
 *
 * @param ai a pointer to the addr_info_t to be printed
 * @param dst the destination buffer
 * @param dstsize the size of the destination buffer
 * @return the number of written bytes (not including the terminal NULL)
 *         or -1 in case of error (0 is not an error)
 */
gsize addr_info_to_string(const addr_info_t * ai, gchar * dst, gsize dstsize);


/**
 * @param ai
 * @param dst
 * @param dstsize
 * @param port
 * @param error
 * @return
 */
gboolean addr_info_get_addr(const addr_info_t * ai, gchar * dst, gsize dstsize, guint16* port, GError** error);


/**
 * Print a list of addr_info_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param list the --maybe NULL-- list of elements to be printed
 * @param header a character string prepended to each line printed
 */
void addr_info_print_all(const gchar * domain, GSList * list, const gchar * header);

/**
 * convert a service string (as returned by meta1) into an addr_info
 *
 * @param service the service str to convert
 */
addr_info_t * addr_info_from_service_str(const gchar *service);


/**
 * @param p
 */
void addr_info_clean(gpointer p);

/**
 * Simple utility function intented to be used with g_slist_foreach().
 * to free whole lists of addr_info_t.
 *
 * @param d assumed to be a pointer to a addr_info_t*, freed if not NULL
 * @param u ignored
 */
void addr_info_gclean(gpointer d, gpointer u);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_chunkinfo ChunkInfo
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a pretty string representation of the chunk information.
 *
 * @param src print 
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint chunk_info_to_string(const chunk_info_t * src, gchar * dst, gsize dstsize);


/**
 * Prints a textual representation of the given chunk_info_t* in the given
 * buffer.
 *
 * The printed text will always be NULL terminated when the destination
 * buffer size is >= 1
 *
 * @param ci the chunk_id_t structure to be printed
 * @param dst the destination buffer
 * @param dstsize the size availble in the destination buffer
 *
 * @return the number of btes written or -1 in case of error
 */
gint chunk_id_to_string(const chunk_id_t * ci, gchar * dst, gsize dstsize);


/**
 * Run the list and print all its elements assumed to be chunk_id_t* pointers.
 *
 * The TRACE log4c log level will be used. Each chunk_id_t will be printed on
 * a separated line.
 *
 * @param domain the domain used with log4c
 * @param header a NULL terminated character string prepended before each
 *               printed chunk_id_t*.
 * @param list the list to be printed.
 */
void chunk_info_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a chunk_info_t*, the second
 * argument is ignored.
 *
 * @param d a pointer assumed to be a chunk_info_t* pointer that will be freed.
 * @param u ignored parameter
 */
void chunk_info_gclean(gpointer d, gpointer u);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_v1 V1 structures (DEPRECATED)
 * @ingroup metautils_utils
 * @deprecated V1 structures should be abandonned and are not supported anymore.
 * @{
 */

/**
 * Fills dst with a pretty string representation of the meta2 information.
 *
 * @param src
 * @param dst
 * @param dstsize
 * @return the number of bytes writen in the given buffer
 * @deprecated
 */
gint meta2_info_to_string(const meta2_info_t * src, gchar * dst, gsize dstsize);


/**
 * Print a list of meta2_info_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 * @deprecated
 */
void meta2_info_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a meta2_info_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a meta2_info_t*, freed if not NULL
 * @param u ignored
 * @deprecated
 */
void meta2_info_gclean(gpointer d, gpointer u);


/**
 * GSList aware sort func to sort meta2_info by ascending score
 *
 * @param a
 * @param b
 * @return
 * @deprecated
 */
gint meta2_info_sort_by_score(gconstpointer a, gconstpointer b);


/**
 * GSList aware compare func
 *
 * @param a
 * @param b
 * @return
 * @deprecated
 */
gint meta2_info_comp(gconstpointer a, gconstpointer b);


/**
 * Fills dst with a pretty string representation of the meta2 stat.
 *
 * @param src
 * @param dst
 * @param dstsize
 * @return the number of bytes writen in the given buffer
 * @deprecated
 */
gint meta2_stat_to_string(const meta2_stat_t * src, gchar * dst, gsize dstsize);


/**
 * Print a list of meta2_stat_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 * @deprecated
 */
void meta2_stat_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a meta2_stat_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a meta2_stat_t*, freed if not NULL
 * @param u ignored
 * @deprecated
 */
void meta2_stat_gclean(gpointer d, gpointer u);


/**
 * Fills dst with a pretty string representation of the volume information.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint volume_info_to_string(const volume_info_t * src, gchar * dst,
		gsize dstsize);


/**
 * Print a list of volume_info_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 */
void volume_info_print_all(const gchar * domain, const gchar * header,
		GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a volmue_info_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a volume_info_t*, freed if not NULL
 * @param u ignored
 */
void volume_info_gclean(gpointer d, gpointer u);


/**
 * GSList aware sort func to sort volume_info by ascending score
 */
gint volume_info_sort_by_score(gconstpointer a, gconstpointer b);


/**
 * GSList aware compare func
 */
gint volume_info_comp(gconstpointer a, gconstpointer b);


/**
 * Fills dst with a pretty string representation of the volume stat.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint volume_stat_to_string(const volume_stat_t * src, gchar * dst, gsize dstsize);


/**
 * Print a list of volume_stat_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 */
void volume_stat_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a volume_stat_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a volume_stat_t*, freed if not NULL
 * @param u ignored
 */
void volume_stat_gclean(gpointer d, gpointer u);


/**
 * Fills dst with a pretty string representation of the meta1 information.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint meta1_info_to_string(const meta1_info_t * src, gchar * dst, gsize dstsize);


/**
 * Print a list of meta1_info_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 */
void meta1_info_print_all(const gchar * domain, const gchar * header,
		GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a meta1_info_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a meta1_info_t*, freed if not NULL
 * @param u ignored
 * @deprecated
 */
void meta1_info_gclean(gpointer d, gpointer u);


/**
 * GSList aware sort func to sort meta1_info by ascending score
 * @param a
 * @param b
 * @return
 * @deprecated
 */
gint meta1_info_sort_by_score(gconstpointer a, gconstpointer b);


/**
 * GSList aware compare func
 * @param a
 * @param b
 * @return
 */
gint meta1_info_comp(gconstpointer a, gconstpointer b);


/**
 * Fills dst with a pretty string representation of the meta1 stat.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint meta1_stat_to_string(const meta1_stat_t * src, gchar * dst, gsize dstsize);


/**
 * Print a list of meta1_stat_t with the log4c library using the TRACE
 * log level.
 *
 * @param domain the domain used with log4c
 * @param header a character string prepended to each line printed
 * @param list the --maybe NULL-- list of elements to be printed
 */
void meta1_stat_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a meta1_stat_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a meta1_stat_t*, freed if not NULL
 * @param u ignored
 */
void meta1_stat_gclean(gpointer d, gpointer u);


/**
 * @param raw
 */
void meta1_raw_container_clean(struct meta1_raw_container_s *raw);


/**
 * @param r
 * @param ignored
 */
void meta1_raw_container_gclean(gpointer r, gpointer ignored);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_pathinfo Path Info
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a pretty string representation of the path information.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint path_info_to_string(const path_info_t * src, gchar * dst, gsize dstsize);


/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a path_info_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a path_info_t*, freed if not NULL
 * @param u ignored
 * @see path_info_clean()
 */
void path_info_gclean(gpointer d, gpointer u);


/**
 * @brief Frees the given structure and the all its internals sub-structures
 * Accepts NULL
 * @see path_info_gclean()
 */
void path_info_clean(path_info_t * pi);


/**
 * Run the given single linked list and print a textual representation
 * of each of its elements, interpreted as path_info_t*.
 */
void path_info_print_all(const gchar * domain, const gchar * header, GSList * list);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_containervenets Container Events
 * @ingroup metautils_utils
 * @{
 */

/**
 * Simple function destined to be passed as a GFunc callback
 * for calls like g_slist_foreach(), etc...
 * The first argument is assumed to be a container_event_t*, the second
 * argument is ignored.
 *
 * @param d assumed to be a pointer to a container_event_t*, freed if not NULL
 * @param u ignored
 * @see container_event_clean()
 */
void container_event_gclean(gpointer d, gpointer u);


/**
 * @brief Frees the given structure and the all its internals sub-structures
 * Accepts NULL
 * @param ce a pointer to a container_event_t
 * @see container_event_gclean()
 */
void container_event_clean(container_event_t * ce);


/**
 * Run the given single linked list and print a textual representation
 * of each of its elements, interpreted as container_event_t*.
 */
void container_event_print_all(const gchar * domain, const gchar * header, GSList * list);


/**
 * Builds a pretty string reprensation of the given container event
 *
 * @param src the container event to pretty print
 * @param dst a pointer to a character array to write the description in
 * @param dstsize the size of the memory pointed by dst
 * @return the number of bytes written in dst
 */
gint container_event_to_string(container_event_t * src, gchar * dst, gsize dstsize);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_m0info META0
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a textual representation (whose maximum length will
 * be dstsize) of the given meta0_info_t structure.
 *
 * The printed characters will always be NULL terminated as soon as the
 * buffer size greater or equal to 1
 *
 * @param m0 a pointer to the meta0_info_t to be printed
 * @param dst a not-NULL pointer to the target buffer
 * @param dstsize the size of the targe buffer
 *
 * @return the size really written or -1 in case of failure.
 */
gsize meta0_info_to_string(const meta0_info_t * m0, gchar * dst, gsize dstsize);


/**
 * @param m0
 */
void meta0_info_clean(meta0_info_t *m0);


/**
 * @param d
 * @param u
 */
void meta0_info_gclean(gpointer d, gpointer u);


/**
 * @param mL
 * @param err
 * @return
 */
GHashTable *meta0_info_list_map_by_addr(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GHashTable *meta0_info_list_map_by_prefix(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GSList *meta0_info_compress_prefixes(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GSList *meta0_info_uncompress_prefixes(GSList * mL, GError ** err);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_cid Container ID 
 * @ingroup metautils_utils
 * @{
 */

/**
 *
 * @param s
 * @param src_size
 * @param dst
 * @param error
 */
gboolean container_id_hex2bin(const gchar * s, gsize src_size, container_id_t * dst, GError ** error);


/**
 * @param k
 * @return
 */
guint container_id_hash(gconstpointer k);


/**
 * @param k1
 * @param k2
 * @return
 */
gboolean container_id_equal(gconstpointer k1, gconstpointer k2);


/**
 * Fills the given buffer with the haxedecimal representatino of the
 * container_id. The destination buffer will always be NULL terminated.
 *
 * @param id the container identifier to be printed
 * @param dst the destination buffer
 * @param dstsize
 * @return 
 */
gsize container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize);


/**
 * Builds the container identifier from the container name
 *
 * If the container name is a null-terminated character array, the NULL
 * character will be hashed as a regular character.
 *
 * @param name the container name
 * @param nameLen the length of the container name.
 * @param id the container_id we put the result in
 *
 * @return NULL if an error occured, or a valid pointer to a container identifier.
 */
void name_to_id(const gchar * name, gsize nameLen, container_id_t * id);


/**
 * Builds the container identifier from the container name
 *
 * If the container name is a null-terminated character array, the NULL
 * character will be hashed as a regular character.
 *
 * @param name the container name
 * @param nameLen the length of the container name.
 * @param vns the name of the associated virtual namespace
 * @param id the container_id we put the result in
 *
 * @return NULL if an error occured, or a valid pointer to a container identifier.
 */
void name_to_id_v2(const gchar * name, gsize nameLen, const gchar *vns, container_id_t * id);


/**
 * @param cid
 * @param ns
 * @param cname
 */
void meta1_name2hash(container_id_t cid, const gchar *ns, const gchar *cname);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautil_kv KeyValue pairs
 * @ingroup metautils_utils
 * @{
 */

/**
 *
 * @param pairs
 * @param copy do a deep copy or not (key and values are copied too)
 * @param err
 * @return a GHashtable of (gchar*,GBytearray*)
 */
GHashTable *key_value_pairs_convert_to_map(GSList * pairs, gboolean copy,
		GError ** err);


/**
 *
 * @param ht
 * @param copy do a deep copy or not (key and values are copied too)
 * @param err
 * @return a GHashtable of (gchar*,GBytearray*)
 */
GSList *key_value_pairs_convert_from_map(GHashTable * ht, gboolean copy, GError ** err);


/**
 * Deep cleaning of the given key_value_pair_t (frees all the structure members and the structure)
 */
void key_value_pair_clean(key_value_pair_t * kv);


/**
 * Call key_value_pair_clean() on the first argument
 */
void key_value_pair_gclean(gpointer p, gpointer u);


/**
 * @param k copied
 * @param v copied
 * @param vs
 * @return
 */
struct key_value_pair_s* key_value_pair_create(const gchar *k,
		const guint8 *v, gsize vs);


/**
 * @return a valid '\0'-terminated character string
 */
gchar* key_value_pair_to_string(key_value_pair_t * kv);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_srvinfo Generic Services
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a pretty string representation of the score.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint score_to_string(const score_t * src, gchar * dst, gsize dstsize);


/*!
 * @param d
 * @param u
 */
void score_gclean(gpointer d, gpointer u);


/**
 * Free a service_info_t pointer
 *
 * @param si the service_info_t pointer to free
 */
void service_info_clean(struct service_info_s *si);

void service_info_cleanv(struct service_info_s **siv, gboolean content_only);

/**
 * Same as service_info_clean() usable for g_slist_foreach()
 *
 * @param si the service_info_t pointer to free
 * @param unused
 */
void service_info_gclean(gpointer si, gpointer unused);


/**
 * Duplicate a service_info_t pointer
 *
 * @param si the service_info_t pointer to duplicate
 *
 * @return an allocated service_info_t duplicates of si or NULL if an error occured
 */
struct service_info_s *service_info_dup(const struct service_info_s *si);


/**
 * Copy a GPtrArray of service_tag_t
 *
 * @param original the GPtrArray to copy
 *
 * @return a new GPtrArray or NULL if an error occured
 */
GPtrArray *service_info_copy_tags(GPtrArray * original);


/**
 * Extract the list of all namespace names involved in a list of services
 *
 * @param services a list of service_info_t to exctract the namespace names from
 * @param copy set to TRUE if you want the names be duplicated
 *
 * @return a list of names or NULL if services was an empty list
 */
GSList* service_info_extract_nsname(GSList *services, gboolean copy);


/**
 * Frees a service_tag_t and all its internal data
 *
 * @param tag the service_tag_t to free
 */
void service_tag_destroy(struct service_tag_s *tag);


/**
 * Same as service_tag_destroy() usable for g_slist_foreach()
 *
 * @param tag the service_tag_t to free
 * @param unused
 */
void service_tag_gclean(gpointer tag, gpointer unused);


/**
 * Set a service_tag_t string value
 *
 * @param tag the service_tag_t to set the value in
 * @param s the string value (duplicated inside)
 */
void service_tag_set_value_string(struct service_tag_s *tag, gchar * s);


/**
 * Get a service_tag_t string value
 *
 * @param tag the service_tag_t to get the value from
 * @param s a pointer to a string to fill with the result
 * @param s_size the size of s string
 * @param error;
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_string(struct service_tag_s *tag, gchar * s, gsize s_size, GError **error);


/**
 * Set a service_tag_t boolean value
 *
 * @param tag the service_tag_t to set the value in
 * @param b the boolean value
 */
void service_tag_set_value_boolean(struct service_tag_s *tag, gboolean b);


/**
 * Get a service_tag_t boolean value
 * 
 * @param tag the service_tag_t to get the value from
 * @param b a pointer to a gboolean to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_boolean(struct service_tag_s *tag, gboolean *b, GError **error);


/**
 * Set a service_tag_t int value
 *
 * @param tag the service_tag_t to set the value in
 * @param i the int value
 */
void service_tag_set_value_i64(struct service_tag_s *tag, gint64 i);


/**
 * Get a service_tag_t int value
 *
 * @param tag the service_tag_t to get the value from
 * @param i a pointer to an int64 to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_i64(struct service_tag_s *tag, gint64* i,
		GError** error);


/**
 * Set a service_tag_t double value
 *
 * @param tag the service_tag_t to set the value in
 * @param r the double value
 */
void service_tag_set_value_float(struct service_tag_s *tag, gdouble r);


/**
 * Get a service_tag_t double value
 *
 * @param tag the service_tag_t to get the value from
 * @param r a pointer to a double to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_float(struct service_tag_s *tag, gdouble *r,
		GError** error);


/**
 * Copy a service_tag_t from src to dst
 *
 * @param dst the service_tag_t to copy to
 * @param src the service_tag_t to copy from
 */
void service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src);


/**
 * Set a service_tag_t macro value
 *
 * @param tag the service_tag_t to set the value in
 * @param type the macro type
 * @param param the macro param
 */
void service_tag_set_value_macro(struct service_tag_s *tag, const gchar * type,
		const gchar * param);


/**
 * Get a service_tag_t macro value
 *
 * @param tag the service_tag_t to get the value from
 * @param type a pointer to a macro type to fill with the result
 * @param type_size the size of the string type
 * @param param a pointer to a macro param to fill with the result
 * @param param_size the size of the param string
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_macro(struct service_tag_s *tag, gchar * type,
		gsize type_size, gchar* param, gsize param_size, GError** error);


/**
 * Duplicate a service_tag_t
 *
 * @param src the service_tag_t to duplicate
 *
 * @return a newly allocated service_tag_t duplicates of src or NULL if an error occured
 */
struct service_tag_s *service_tag_dup(struct service_tag_s *src);


/**
 * Convert a service_tag_t to a string representation
 *
 * @param tag the service_tag_t to convert
 * @param dst the destination string
 * @param dst_size the destinatino string size
 *
 * @return the size of the resulting string or 0 if an error occured
 */
gsize service_tag_to_string(const struct service_tag_s *tag, gchar * dst,
		gsize dst_size);


/**
 * @param si
 * @return
 */
gchar* service_info_to_string(const service_info_t *si);

/**
 * @param si0
 * @param si1
 */
void service_info_swap(struct service_info_s *si0, struct service_info_s *si1);

/**
 * GSList sort callback to sort a list of service_info_t by score
 *
 * @param a a value
 * @param b a value to compare with
 *
 * @return negative value if a < b; zero if a = b; positive value if a > b
 */
gint service_info_sort_by_score(gconstpointer a, gconstpointer b);


/**
 * Compare two service_info_t pointers
 *
 * @param si1 a service_info_t
 * @param si2 a service_info_t to compare with
 * @return TRUE if si1 equals si2 or FALSE if not
 */
gboolean service_info_equal(const struct service_info_s * si1,
		const struct service_info_s * si2);


/**
 * Convert a service_info_t to a legacy volume_info_t
 *
 * @param srv the service_info_t to convert
 * @return a newly allocated volume_info_t or NULL if an error occured
 * @deprecated
 */
volume_info_t *service_info_convert_to_volinfo(struct service_info_s *srv);


/**
 * Convert a service_info_t to a legacy meta0_info_t
 *
 * @param srv the service_info_t to convert
 * @return a newly allocated meta0_info_t or NULL if an error occured
 * @deprecated
 */
meta0_info_t *service_info_convert_to_m0info(struct service_info_s *srv);


/**
 * Convert a service_info_t to a legacy meta2_info_t
 * 
 * @param srv the service_info_t to convert
 * @return a newly allocated meta2_info_t or NULL if an error occured
 * @deprecated
 */
meta2_info_t *service_info_convert_to_m2info(struct service_info_s *srv);


/**
 *  Convert a service_info_t to a legacy meta1_info_t
 *
 * @param srv the service_info_t to convert
 * @return a newly allocated meta1_info_t or NULL if an error occured
 * @deprecated
 */
meta1_info_t *service_info_convert_to_m1info(struct service_info_s *srv);

/**
 * Extract the tag with the given name from a GPtrArray of service_tag_t
 *
 * @param a a GPtrArray of service_tag_t
 * @param n a tag name
 * @return the service_tag_t from array or NULL if an error occured or the tag was not found
 */
struct service_tag_s *service_info_get_tag(GPtrArray * a, const gchar * n);


/**
 * Create a new empty service_tag_t with the given name and store it in a GPtrArray
 *
 * @param a a GPtrArray of service_tag_t
 * @param name a tag name
 * @return the newly allocated service_tag_t or NULL if an error occured
 */
struct service_tag_s *service_info_ensure_tag(GPtrArray * a, const gchar * name);


/**
 * Remove a service_tag_t with the given name from a GPtrArray
 *
 * @param a a GPtrArray of service_tag_t
 * @param name a tag name
 */
void service_info_remove_tag(GPtrArray * a, const gchar * name);


/**
 * Set a service_info_t addr
 * 
 * @param si the service_info_t to set the addr in
 * @param addr the service addr in string format
 * @param port the service port
 * @param error
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_info_set_address(struct service_info_s *si, const gchar * addr, int port, GError ** error);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_nsinfo NsInfo
 * @ingroup metautils_utils
 * @{
 */

/**
 * Copy a namespace_info into another namespace_info
 *
 * The option hashtable is not copied. The old table's reference
 * count is decremented (then the table will e destroyed if it falls
 * to zero), and the table of the new namespace_info_t will be
 * referenced in the destination structure.
 *
 * @param src the source namespace_info we copy from
 * @param dst the destination namespace_info we copy to
 * @param error
 * @return FALSE if an error occured, TRUE otherwise
 */
gboolean namespace_info_copy(namespace_info_t* src, namespace_info_t* dst, GError **error);


/**
 * Makes a deep copy of the input namespace_info_t.
 *
 * Contrary to namespace_info_copy(), the options table will be
 * newly allocated and filled with newly allocated values.
 *
 * @param src the namespace_info_t to be dupplicated
 * @param error
 *
 * @return NULL in case of error, or a valid namespace_info_t
 */
namespace_info_t* namespace_info_dup(namespace_info_t* src, GError **error);


/**
 * Clear a namespace_info content
 *
 * @param ns_info the namespace_info to clear
 */
void namespace_info_clear(namespace_info_t* ns_info);


/**
 * Free a namespace_info pointer
 *
 * @param ns_info the namespace_info to free
 */
void namespace_info_free(namespace_info_t* ns_info);


/**
 * Calls namespace_info_free() on p1 and ignores p2.
 *
 * Mainly used with g*list_foreach() functions of the GLib2
 * to clean at once whole lists of namespace_info_s structures.
 */
void namespace_info_gclean(gpointer p1, gpointer p2);


/** 
 * Map the given list of namespace_info_t in a GHashTable
 * where the values are the list elements (not a copy!)
 * and where the keys are the "name" fields the the values.
 */
GHashTable* namespace_info_list2map(GSList *list_nsinfo, gboolean auto_free);


/**
 * Return the list of the namespace names contained in
 * the namespace_info_s elements of the input list.
 * If copy is TRUE, then the returned list contains newly allocated
 * string elements, that should be freed with g_free().
 *
 * The sequence order of the result list does not reflect the
 * sequence order of the input list, and the duplicated entries.
 */
GSList* namespace_info_extract_name(GSList *list_nsinfo, gboolean copy);


/**
 * Get the data_security definition from the specified key
 */
gchar * namespace_info_get_data_security(namespace_info_t *ni, const gchar *data_sec_key);

/**
 * Get the data_treatments definition from the specified key
 */
gchar * namespace_info_get_data_treatments(namespace_info_t *ni, const gchar *data_treat_key);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_metadata Metadata
 * @ingroup metautils_utils
 * These functions handle GHashTable of (gchar*,gchar*)
 * @{
 */

/**
 * @return
 */
GHashTable* metadata_create_empty(void);


/**
 * @param gba
 * @param error
 * @return
 */
GHashTable* metadata_unpack_gba(GByteArray *gba, GError **error);


/**
 * @param data
 * @param size
 * @param error
 * @return
 */
GHashTable* metadata_unpack_buffer(const guint8 *data, gsize size, GError **error);


/**
 * @param data
 * @param error
 * @return
 */
GHashTable* metadata_unpack_string(const gchar *data, GError **error);


/**
 * @param unpacked
 * @param error
 * @return
 */
GByteArray* metadata_pack(GHashTable *unpacked, GError **error);


/**
 * @param unpacked
 * @param prefix
 * @param error
 * @return
 */
GHashTable* metadata_remove_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error);


/**
 * @param unpacked
 * @param prefix
 * @param error
 * @return
 */
GHashTable* metadata_extract_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error);


/**
 * @param base
 * @param complement
 */
void metadata_merge(GHashTable *base, GHashTable *complement);


/**
 * @param md
 * @param key
 * @param t
 */
void metadata_add_time(GHashTable *md, const gchar *key, GTimeVal *t); 


/**
 * @param md
 * @param key
 * @param fmt
 * @param ...
 */
void metadata_add_printf(GHashTable *md, const gchar *key, const gchar *fmt, ...);

/** @} */


/* ------------------------------------------------------------------------------ */


/**
 * @defgroup metautils_integrity Integrity Loop
 * @ingroup metautils_utils
 * @{
 */

/**
 * Free and clear the content of a chunk_textinfo (not the pointer itself)
 *
 * @param cti an instance of struct chunk_textinfo_s
 */
void chunk_textinfo_free_content(struct chunk_textinfo_s *cti);


/**
 * Free and clear the content of a content_textinfo (not the pointer itself)
 *
 * @param cti an instance of struct content_textinfo_s
 */
void content_textinfo_free_content(struct content_textinfo_s *cti);


/**
 * Test if the chunk given in args is the last of the chunk sequence of the given content
 *
 * @param chunk the chunk to check
 * @param content the content this chunk belongs to
 * 
 * @return 1 if the chunk is the last one, 0 otherwise
 */
int chunk_is_last(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content);


/**
 * Convert a chunk info in text format to the raw format
 *
 * @param text_chunk the chunk in text format
 * @param raw_chunk the preallocated chunk in raw format
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean convert_chunk_text_to_raw(const struct chunk_textinfo_s* text_chunk, struct meta2_raw_chunk_s* raw_chunk, GError** error);


/**
 * Convert a chunk info in raw format to the text format
 *
 * @param raw_content a content in raw format containing the chunk to convert (and only this chunk)
 * @param text_chunk the preallocated chunk in text format
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean convert_chunk_raw_to_text(const struct meta2_raw_content_s* raw_content, struct chunk_textinfo_s* text_chunk, GError** error);


/**
 * Convert a content info in text format to the raw format
 *
 * @param text_content the content in text format
 * @param raw_content the preallocated content in raw format
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean convert_content_text_to_raw(const struct content_textinfo_s* text_content, struct meta2_raw_content_s* raw_content, GError** error);


/**
 * Convert a content info in text format to the raw format
 *
 * @param raw_content the preallocated content in raw format
 * @param text_content the content in text format
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean convert_content_raw_to_text(const struct meta2_raw_content_s* raw_content, struct content_textinfo_s* text_content, GError** error);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_meta2 Meta2 
 * @ingroup metautils_utils
 * @{
 */

/**
 * Allocates a new content structure, and fills the common fields with
 * a copy of the pointed parameters
 *
 * @param container_id
 * @param size
 * @param nb_chunks
 * @param flags
 * @param path
 * @param path_len
 * @return
 * @deprecated
 */
struct meta2_raw_content_s *meta2_maintenance_create_content(
		const container_id_t container_id, gint64 size, guint32 nb_chunks,
		guint32 flags, const gchar * path, gsize path_len);


/**
 * prepend (order does not matter) to the list a copy of the given
 * chunk
 *
 * @param content
 * @param chunk
 * @deprecated
 */
void meta2_maintenance_add_chunk(struct meta2_raw_content_s *content,
		const struct meta2_raw_chunk_s *chunk);


/**
 * Frees the memory structures : the content pointed by the argument
 * and all the chunks listed in
 *
 * @param content
 * @deprecated
 */
void meta2_maintenance_destroy_content(struct meta2_raw_content_s *content);


/*!
 *
 * @param content
 * @deprecated
 */
void meta2_maintenance_increment_chunks_count(struct meta2_raw_content_s *content);


/**
 * @param content
 * @deprecated
 */
void meta2_raw_content_clean(meta2_raw_content_t *content);


/**
 * @param p
 * @param ignored
 * @deprecated
 */
void meta2_raw_content_gclean(gpointer p, gpointer ignored);


/**
 * @param chunk
 * @return
 */
meta2_raw_chunk_t* meta2_raw_chunk_dup(meta2_raw_chunk_t *chunk);


/**
 * @param chunk
 */
void meta2_raw_chunk_clean(meta2_raw_chunk_t *chunk);


/**
 * @param p
 * @param ignored
 */
void meta2_raw_chunk_gclean(gpointer p, gpointer ignored);


/**
 * @param r1
 * @param r2
 * @return
 */
gint meta2_raw_chunk_cmp(const meta2_raw_chunk_t *r1, const meta2_raw_chunk_t *r2);


/**
 * @param header
 * @return
 */
gchar* meta2_raw_chunk_to_string(const meta2_raw_chunk_t *header);


/**
 * @param chunk_id
 * @param hash
 * @param flags
 * @param size
 * @param position
 * @return
 */
struct meta2_raw_chunk_s * meta2_maintenance_create_chunk(
		const chunk_id_t * chunk_id, const chunk_hash_t hash,
		guint32 flags, gint64 size, guint32 position);


/**
 * @param chunk
 */
void meta2_maintenance_destroy_chunk(struct meta2_raw_chunk_s *chunk);


/**
 * @param p1
 * @param p2
 */
void meta2_maintenance_chunk_gclean(gpointer p1, gpointer p2);


/**
 * @param prop
 */
void meta2_property_clean(meta2_property_t *prop);


/**
 * @param prop
 * @param ignored
 */
void meta2_property_gclean(gpointer prop, gpointer ignored);


/**
 * @param p1
 * @param p2
 * @return
 */
gint meta2_property_cmp(const meta2_property_t *p1, const meta2_property_t *p2);


/**
 * @param prop
 * @return
 */
gchar* meta2_property_to_string(const meta2_property_t *prop);


/**
 * @param orig
 * @return
 */
meta2_property_t* meta2_property_dup(meta2_property_t *orig);


/**
 * @param content
 */
void meta2_raw_content_header_clean(meta2_raw_content_header_t *content);


/**
 * @param p
 * @param ignored
 */
void meta2_raw_content_header_gclean(gpointer p, gpointer ignored);


/**
 * @param r1
 * @param r2
 * @return
 */
gint meta2_raw_content_header_cmp(const meta2_raw_content_header_t *r1, const meta2_raw_content_header_t *r2);


/**
 * @param header
 * @return
 */
gchar* meta2_raw_content_header_to_string(const meta2_raw_content_header_t *header);


/**
 * @param prop
 */
void meta2_raw_content_v2_clean(meta2_raw_content_v2_t *prop);


/**
 * @param prop
 * @param ignored
 */
void meta2_raw_content_v2_gclean(gpointer prop, gpointer ignored);


/**
 * @param content
 * @return
 */
gchar* meta2_raw_content_v2_to_string(const meta2_raw_content_v2_t *content);


/**
 * @param v1
 * @param err
 * @return
 */
meta2_raw_content_v2_t* meta2_raw_content_v1_get_v2(meta2_raw_content_t *v1,
		GError **err);


/**
 * @param v2
 * @param err
 * @return
 */
meta2_raw_content_t* meta2_raw_content_v2_get_v1(meta2_raw_content_v2_t *v2,
		GError **err);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_utils_gba GByteArray
 * @ingroup metautils_utils
 * @brief GByteArray utils
 * @{
 */

/**
 * @param cid
 * @return
 */
GByteArray* metautils_gba_from_cid(const container_id_t cid);


/**
 * @param gba
 * @return
 */
GByteArray* metautils_gba_dup(GByteArray *gba);


/**
 * @param str
 * @return
 */
GByteArray* metautils_gba_from_string(const gchar *str);


/**
 * @param gba
 * @param dst
 * @param dst_size
 * @return
 */
gsize metautils_gba_data_to_string(GByteArray *gba, gchar *dst,
		gsize dst_size);


/**
 * @param a
 * @param b
 * @return 0 if a differs from b, something true elsewhere
 */
int metautils_gba_cmp(GByteArray *a, GByteArray *b);


/**
 * @param gba
 * @return the internal size of gba or 0 if gba is invalid
 */
gsize metautils_gba_len(const GByteArray *gba);


/** Calls g_byte_array_free() on GByteArray in GLib containers
 *
 * Factored code
 * @param p a GByteArray
 */
void metautils_gba_clean(gpointer p);


/** Calls g_byte_array_free() on GByteArray in GLib associative containers
 *
 * @param p1 a GByteArray
 * @param p2 ignored
 */
void meatutils_gba_gclean(gpointer p1, gpointer p2);


/** Factored code
 *
 * @see g_byte_array_unref()
 * @param p a GByteArray
 */
void metautils_gba_unref(gpointer p);


/**
 * @param p0
 * @param p1 ignored
 */
void metautils_gba_gunref(gpointer p0, gpointer p1);

/**
 * @param gstr
 * @param gba
 * @return
 */
GString* metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba);

/** @} */


/* ------------------------------------------------------------------------- */


/**
 * @defgroup metautils_utils_acl ACL 
 * @ingroup metautils_utils
 * @brief ACL utils
 * @details Handles access control lists got from the conscience.
 * @{
 */

/**
 * @param addr
 * @param acl
 * @return
 */
gboolean authorized_personal_only(const gchar* addr, GSList* acl);


/**
 * @param acl_byte
 * @param authorize
 * @return
 */
GSList* parse_acl(const GByteArray* acl_byte, gboolean authorize);


/**
 * @param file_path
 * @param error
 * @return
 */
GSList* parse_acl_conf_file(const gchar* file_path, GError **error);


/**
 * @param addr_rule
 * @return
 */
gchar* access_rule_to_string(const addr_rule_t* addr_rule);


/**
 * @param data
 */
void addr_rule_g_free(gpointer data);

/*
 * Extract the storage policy from a content sys-metadata
 * @param sys_metadata the metadata to process
 * @param storage_policy a pointer to the result
 * @result a gerror if an error occured, NULL otherwise
 *
 */
GError* storage_policy_from_metadata(GByteArray *sys_metadata, gchar **storage_policy);

/*
 * Extract the storage policy from a content sys-metadata
 * @param sys_metadata the metadata to process
 * @param storage_policy a pointer to the result
 * @result the matching storage policy if specified, NULL otherwise
 *
 */
char* storage_policy_from_mdsys_str(const char *mdsys);

/*
 * Calculate the distance between two string representing rawx locations
 *
 *
 */
guint distance_between_location(const gchar *loc1, const gchar *loc2);

/*
 * Extract the rawx location from service info tag
 *
 *
 */
gchar* get_rawx_location(service_info_t* rawx);

/**
 *
 * @param si
 * @return
 */
gchar* metautils_rawx_get_volume(struct service_info_s *si);

/** @} */

/** @} */

#endif /*__METAUTILS__H__*/
