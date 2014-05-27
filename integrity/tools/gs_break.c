#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs-rawx-list"
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include "../lib/chunk_db.h"

static gboolean flag_auto_enabled = FALSE;
static gint64 auto_bitlength = 17;
static gint64 auto_hoffset = 0;
static gint64 auto_hlength = 0;

static gchar ns_name[LIMIT_LENGTH_NSNAME];
static gchar container_name[LIMIT_LENGTH_CONTAINERNAME];
static gchar content_path[LIMIT_LENGTH_CONTENTPATH];
static addr_info_t fake_address;

/* ------------------------------------------------------------------------- */

static void
main_action(void)
{
	int rc;
	container_id_t cid;
	GError *local_err;
	gchar str_cid[STRLEN_CONTAINERID+1];

	local_err = NULL;
	meta1_name2hash(cid, ns_name, container_name);
	container_id_to_string(cid, str_cid, sizeof(str_cid));
 
	if (*content_path) {
		rc = store_erroneous_content(ns_name, cid, &fake_address, &local_err, content_path, "");
		if (!rc) {
			g_print("failed: %s/%s/%s\n", ns_name, container_name, content_path);
			GRID_ERROR("failed: %s/%s/%s : %s", ns_name,
                                        container_name, content_path,
                                        gerror_get_message(local_err));
		}
		else
			g_print("success: %s/%s/%s\n", ns_name, container_name, content_path);
	}
	else {
		rc = store_erroneous_container(ns_name, cid, &fake_address, &local_err);
		if (!rc) {
			g_print("failed: %s/%s/*\n", ns_name, container_name);
			GRID_ERROR("failed: %s/%s/* : %s", ns_name, container_name,
				gerror_get_message(local_err));
		}
		else
			g_print("success: %s/%s/*\n", ns_name, container_name);
	}

	GRID_DEBUG("Done!");
}

/**
 * @todo grid URL not parsed
 */
static gboolean
parse_grid_url(const gchar *url, GError **error)
{
	gsize length;
	gchar **tokens;

	tokens = g_strsplit(url, "/", 0);
	if (!tokens) {
		GSETERROR(error, "split error : %s", strerror(errno));
		return FALSE;
	}
	else {
		length = g_strv_length(tokens);
		(void) length;
		/* TODO FIXME grid url not parsed */
		g_strfreev(tokens);
	}

	GSETERROR(error, "NOT YET IMPLEMENTED");
	return FALSE;
}

static gboolean
gridcluster_hashcontent_from_nsinfo(namespace_info_t *nsinfo, 
	const gchar *cname, gchar *dst, gsize dst_size, GError **error)
{
	gsize offset, size, bitlength;
	gsize cname_len;

	cname_len = strlen(cname);

	GRID_DEBUG("Hashing NS=[%s] PATH=[%s]", nsinfo->name, cname);
	
	if (auto_hoffset<=0 && auto_hlength<=0) {
		/* Get it from the namspace */
		offset = namespace_get_autocontainer_src_offset(nsinfo);
		size = namespace_get_autocontainer_src_size(nsinfo);
	}
	else {
		/* Get the explicit values configured */
		offset = auto_hoffset;
		size = auto_hlength;
	}

	if (auto_bitlength <= 0)
		bitlength = namespace_get_autocontainer_dst_bits(nsinfo);
	else
		bitlength = auto_bitlength;

	/* Sanity checks */
	if (offset <= 0)
		offset = 0;
	if (size <= 0)
		size = cname_len;
	if (offset >= cname_len) {
		GSETERROR(error, "Invalid hash offset (%d), exceeding the path length (%d)",
			offset, cname_len);
		return FALSE;
	}
	if (size > cname_len) {
		GSETERROR(error, "Invalid hash size (%d), exceeding the path length (%d)",
			size, cname_len);
		return FALSE;
	}
	if (size+offset > cname_len) {
		GSETERROR(error, "Invalid hash offset/size (%d/%d), exceeding the path length (%d)",
			offset, size, cname_len);
		return FALSE;
	}

	/* Hash itself */
	metautils_hash_content_path(cname+offset, cname_len-size, dst, dst_size, bitlength);
	return TRUE;
}

static gboolean
gridcluster_hashcontent_from_nsname(const gchar *ns,
	const gchar *cname, gchar *dst, gsize dst_size, GError **error)
{
	gboolean rc;
	namespace_info_t *nsinfo;

	GRID_DEBUG("Resolving NS=[%s]", ns);

	if (!(nsinfo = get_namespace_info(ns, error))) {
		GSETERROR(error, "Namespace [%s] not resolved", ns);
		return FALSE;
	}

	rc = gridcluster_hashcontent_from_nsinfo(nsinfo, cname, dst, dst_size, error);
	namespace_info_free(nsinfo);

	return rc;
}

/* ------------------------------------------------------------------------- */

static gboolean
main_configure(int argc, char **args)
{
	gboolean rc;
	GError *error = NULL;

	if (!argc) {
		GRID_ERROR("No Grid Url provided");
		return FALSE;
	}

	switch (argc) {
	
	case 1:
		GRID_DEBUG("Grid URL configured : [%s]", args[0]);
		if (!parse_grid_url(args[0], &error)) {
			GRID_ERROR("Invalid Grid URL : %s", gerror_get_message(error));
			g_clear_error(&error);
			return FALSE;
		}
		break;
	
	case 2:
		if (flag_auto_enabled) {
			GRID_DEBUG("Couple provided NS=[%s] PATH=[%s]", args[0], args[1]);
			error = NULL;
			rc = gridcluster_hashcontent_from_nsname(args[0], args[1],
				container_name, sizeof(container_name), &error);
			if (!rc) {
				GRID_ERROR("Cannot hash the content to get the container name : %s",
					gerror_get_message(error));
				g_clear_error(&error);
				return FALSE;
			}
			g_strlcpy(content_path, args[1], sizeof(content_path)-1);
			GRID_DEBUG("Container automatically hashed PATH[%s] -> CONTAINER[%s]",
				content_path, container_name);
		}
		else {
			GRID_DEBUG("Couple provided NS=[%s] CONTAINER=[%s]", args[0], args[1]);
			g_strlcpy(container_name, args[1], sizeof(container_name)-1);
		}
		g_strlcpy(ns_name, args[0], sizeof(ns_name)-1);
		break;
	
	case 3:
		GRID_DEBUG("Triplet provided NS=[%s] CONTAINER=[%s] PATH=[%s]",
			args[0], args[1], args[2]);
		g_strlcpy(content_path, args[2], sizeof(content_path)-1);
		g_strlcpy(container_name, args[1], sizeof(container_name)-1);
		g_strlcpy(ns_name, args[0], sizeof(ns_name)-1);
		break;

	default:
		GRID_ERROR("Wrong argument number, {1,2,3} expected, %d provided", argc);
		return FALSE;
	}
	
	GRID_DEBUG("Breaking [%s] [%s] [%s]", ns_name, container_name, content_path);
	return TRUE;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	/* Nothing to free */
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"AutoContainerEnable", OT_BOOL, {.b=&flag_auto_enabled},
			"Perform an automatical hash of the content"},
		{"AutoContainerHashBits", OT_INT64, {.i64=&auto_bitlength},
			"Sets the auto-hash lengh in bits"},
		{"AutoContainerHashOffset", OT_INT64, {.i64=&auto_hoffset},
			"Sets the the offset in the content name used in the auto-hash computation"},
		{"AutoContainerHashSize", OT_INT64, {.i64=&auto_hlength},
			"Sets the the number of bytes in the content name used in the auto-hash computation"},
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	bzero(&fake_address, sizeof(fake_address));
	bzero(ns_name, sizeof(ns_name));
	bzero(container_name, sizeof(container_name));
	bzero(content_path, sizeof(content_path));
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] =
		"\tFormat 1: NS CONTAINER CONTENT\n"
		"\tFormat 2: NS CONTAINER\n"
		"\tFormat 3: NS/CONTAINER/CONTENT\n"
		;
	return xtra_usage;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

