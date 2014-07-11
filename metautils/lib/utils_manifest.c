#ifndef  G_LOG_DOMAIN
# define G_LOG_DOMAIN "manifest"
#endif

#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "metautils_syscall.h"
#include "metautils_sockets.h"
#include "metautils_errors.h"
#include "metautils_manifest.h"

#define STR_SKIP_SPACES(s) do {\
	register gchar c;\
	for (; (c = *s) && g_ascii_isspace(c) ;++s);\
} while (0)

#define STR_TRIM_TRAILING_SPACES(s) do {\
	register gchar c, *end;\
	for (end = s + strlen(s) - 1; end > s && (c = *end) && g_ascii_isspace(c) ;--end) *end = '\0';\
} while (0)

/**
 * @brief Concatenates the key/value pairs in a human readable single buffer
 * 
 * Properties keys provided: "ns" (mapped in GS_MANIFEST_KEY_NS), "name"
 * (mapped in GS_MANIFEST_KEY_NAME) and "type" (mapped in GS_MANIFEST_KEY_TYPE).
 *
 * ARGUMENTS NOT CHECKED
 */
static GByteArray *
gs_manifest_pack(const gchar *prefix, GHashTable *props)
{
	void concat(GByteArray *gba, const gchar *k, const gchar *v) {
		gchar *s = g_strconcat(prefix ? prefix : "", k, "=", v, "\n", NULL);
		g_byte_array_append(gba, (guint8*)s, strlen(s));
		g_free(s);
	}

	GByteArray *gba = g_byte_array_new();
	concat(gba, GS_MANIFEST_KEY_NS, g_hash_table_lookup(props, "ns"));
	concat(gba, GS_MANIFEST_KEY_TYPE, g_hash_table_lookup(props, "type"));
	concat(gba, GS_MANIFEST_KEY_NAME, g_hash_table_lookup(props, "name"));

	/* ensure a trailing '\0' */
	g_byte_array_append(gba, (guint8*)"", 1);
	g_byte_array_set_size(gba, gba->len - 1);

	return gba;
}

/**
 * Properties keys returned in case of success: "ns" "name" "type"
 *
 * ARGUMENTS NOT CHECKED
 */
static GHashTable*
gs_manifest_load(const gchar *path, const gchar *prefix, GError **error)
{
	gchar line[512];
	size_t prefix_len;
	FILE *path_in;
	GHashTable *props;

	if (!(path_in = fopen(path, "r"))) {
		if (error)
			*error = NEWERROR(errno, "fopen error (%s)", strerror(errno));
		return NULL;
	}

	prefix_len = prefix ? strlen(prefix) : 0;
	props = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	for (;;) {
		gchar **tokens, *key, *value;
		char *str;

		str = fgets(line, sizeof(line), path_in);
		if (!str)
			break;

		if (prefix && *prefix && !g_str_has_prefix(str, prefix))
			continue;

		tokens = g_strsplit(str+prefix_len, "=", 2);
		if (!tokens)
			continue;

		key = tokens[0];
		value = key ? tokens[1] : NULL;
		if (key && value) {
			STR_SKIP_SPACES(key);
			STR_TRIM_TRAILING_SPACES(key);
			STR_SKIP_SPACES(value);
			STR_TRIM_TRAILING_SPACES(value);
			if (*key != '#') { /* not commented */
				if (!g_ascii_strcasecmp(key, GS_MANIFEST_KEY_NS)) 
					g_hash_table_insert(props,
							g_strdup("ns"),
							g_strdup(value));
				else if (!g_ascii_strcasecmp(key, GS_MANIFEST_KEY_TYPE)) 
					g_hash_table_insert(props,
							g_strdup("type"),
							g_strdup(value));
				else if (!g_ascii_strcasecmp(key, GS_MANIFEST_KEY_NAME)) 
					g_hash_table_insert(props,
							g_strdup("name"),
							g_strdup(value));
				/* else ... ignored! */
			}
		}
		g_strfreev(tokens);
	}

	if (ferror(path_in)) {
		if (error)
			*error = NEWERROR(EIO, "fread error");
		return NULL;
	}

	fclose(path_in);

	if (g_hash_table_size(props) == 3) 
		return props;

	g_hash_table_destroy(props);
	if (error)
		*error = NEWERROR(EAGAIN, "uncomplete manifest");
	return NULL;
}

/**
 * @brief Checks the manifest's properties against the given properties.
 *
 * Both must contain values for the keys "ns", "type" and "name".
 * @param path the path of the manifest
 * @param prefix
 * @param props
 * @param error
 */
static int
gs_manifest_check(const gchar *path, const gchar *prefix, GHashTable *props, GError **error)
{
	GHashTable *ht_manifest;
	GHashTableIter iter;
	gpointer k, v0, v1;

	/* unreadable/partial manifest */
	ht_manifest = gs_manifest_load(path, prefix, error);
	if (!ht_manifest)
		return -1;

	g_hash_table_iter_init(&iter, ht_manifest);
	while (g_hash_table_iter_next(&iter, &k, &v0)) {
		v1 = g_hash_table_lookup(props, k);
		if (!v1) {
			/* Partial manifest */
			if (error)
				*error = NEWERROR(EINVAL, "Missing property (%s)", (gchar*)k);
			g_hash_table_destroy(ht_manifest);
			return -1;
		}
		if (g_ascii_strcasecmp((gchar*)v1, (gchar*)v0)) {
			/* Different manifest */
			if (error)
				*error = NEWERROR(0, "Manifest owned by someone else"
						" ('%s' vs. '%s')", (gchar*)v1, (gchar*)v0);
			g_hash_table_destroy(ht_manifest);
			return 1;
		}
	}

	/* iso-manifest */
	g_hash_table_destroy(ht_manifest);
	return 0;
}

int
gs_manifest_testandset(const gchar *path, const gchar *prefix, GError **error, ...)
{
	int fd, errsav;
	va_list args;
	GHashTable *ht;

	/* Build a hash with the additional parameters */
	va_start(args, error);
	ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	for (;;) {
		gchar *k, *v;
		k = v = NULL;
		if (!(k = va_arg(args, gchar*)))
			break;
		if (!(v = va_arg(args, gchar*)))
			break;
		if (!g_ascii_strcasecmp(k, "ns"))
			g_hash_table_insert(ht, g_strdup("ns"), g_strdup(v));
		else if (!g_ascii_strcasecmp(k, "name"))
			g_hash_table_insert(ht, g_strdup("name"), g_strdup(v));
		else if (!g_ascii_strcasecmp(k, "type"))
			g_hash_table_insert(ht, g_strdup("type"), g_strdup(v));
		else {
			g_hash_table_destroy(ht);
			if (error)
				*error = NEWERROR(EINVAL, "Invalid property name '%s'", k);
			errno = EINVAL;
			return 0;
		}
	}
	va_end(args);
	if (3 != g_hash_table_size(ht)) {
		if (error)
			*error = NEWERROR(EINVAL, "Missing parameter, expected values for keys"
				" 'ns', 'url' and 'type'");
		errno = EINVAL;
		return 0;
	}

	/* Atomically check/create the file */
	fd = metautils_syscall_open(path, O_WRONLY|O_CREAT|O_EXCL, 0444);
	if (-1 == fd) {
		if (EEXIST != errno) {
			errsav = errno;
			if (error)
				*error = NEWERROR(errsav, "open error (%s)", strerror(errsav));
			errno = errsav;
			return 0;
		}
		if (0 != gs_manifest_check(path, prefix, ht, error))
			return 0;

		return 1;
	}

	/* Alright, this is the first time, the file is being filled */
	size_t written;
	ssize_t wrc;
	GByteArray *gba;

	gba = gs_manifest_pack(prefix, ht);
	for (written=0; written < gba->len; ) {
		wrc = metautils_syscall_write(fd, gba->data + written, gba->len - written);
		if (wrc < 0) {
			errsav = errno;
			if (error)
				*error = NEWERROR(errsav, "write error (%s)", strerror(errsav));
			errno = errsav;
			goto label_unlink;
		}
		written += wrc;
	}
	g_byte_array_free(gba, TRUE);
	metautils_pclose(&fd);

	/* Success */
	return 1;

label_unlink:
	errsav = errno;
	metautils_syscall_unlink(path);
	metautils_pclose(&fd);
	errno = errsav;
	return 0;
}

GHashTable*
gs_manifest_read(const gchar *path, const gchar *prefix, GError **error)
{
	if (!path || !*path) {
		if (error)
			*error = NEWERROR(EINVAL, "Invalid path");
		return NULL;
	}
	return gs_manifest_load(path, prefix, error);
}

