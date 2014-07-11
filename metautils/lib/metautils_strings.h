#ifndef __REDCURRANT__hc_strings__h
# define __REDCURRANT__hc_strings__h 1

#include <glib.h>

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

void metautils_str_reuse(gchar **dst, gchar *src);

void metautils_str_clean(gchar **s);

void metautils_str_replace(gchar **dst, const gchar *src);

const char * metautils_lstrip(register const char *s, register char c);

void metautils_rstrip(register gchar *src, register gchar c);

void metautils_str_upper(register gchar *s);

void metautils_str_lower(register gchar *s);

/* Returns FALSE if 's' is not 'slen' long and contains a non-hexa character. */
gboolean metautils_str_ishexa(const gchar *s, gsize slen);

/**
 * @param s
 * @param l
 * @return
 */
gsize strlen_len(const guint8 * s, gsize l);

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
 * Fills the hash_path argument with a hash of the given file_name.
 * The hash is a sequence of hash_depth subdirectories, whose each
 * directory's name is hash_size long.
 *
 * @param file_name
 * @param hash_depth
 * @param hash_size
 * @param hash_path
 */
void build_hash_path(const char *file_name, int hash_depth, int hash_size,
		char **hash_path);

/**
 * Calls g_strcmp0(a,b) and ignores its third argument.
 * @see g_strcmp0() from the GLib2
 * @param a
 * @param b
 * @param ignored
 * @return
 */
int metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored);

/** Returns the boolean value of the textual and human readable boolean
 * string (yes, true, on, yes, 1) */
gboolean metautils_cfg_get_bool(const gchar *value, gboolean def);

/** Fills 'buf' with buflen random bytes */
void metautils_randomize_buffer(guint8 *bufn, gsize buflen);

/** Frees the first argument and ignores the second */
void g_free1(gpointer p1, gpointer p2);

/** Frees the second argument and ignores the first */
void g_free2(gpointer p1, gpointer p2);

static inline const gchar *
none(const gchar *src)
{
	return src ? src : "null";
}

#endif // __REDCURRANT__hc_strings__h
