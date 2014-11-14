#ifndef HC_policycheck_repair_h
# define HC_policycheck_repair_h 1

#include <glib.h>
#include <meta2v2/meta2_utils.h>

struct hc_url_s;
struct hc_resolver_s;
struct grid_lbpool_s;
struct namespace_info_s;
struct m2v2_check_s;

/** Activate check only (aka dryrun) mode. */
#define POLCHK_FLAG_CHECKONLY			0x01
/** Skip check for chunk md5. */
#define POLCHK_FLAG_NOMD5				0x02
/** Consider unreachable rawx as broken. */
#define POLCHK_FLAG_FORCE_RAWX_REBUILD	0x04

struct policy_check_s
{
	struct hc_url_s *url;
	struct hc_resolver_s *resolver;
	struct grid_lbpool_s *lbpool;
	struct namespace_info_s *nsinfo;
	guint32 flags;

	struct m2v2_check_s *check;
	gchar **m2urlv;
};

struct chunk_location_s
{
	m2v2_chunk_pair_t *chunk_pair;
	gchar *location;
};

GError* policy_check_and_repair(struct policy_check_s *pc);

GError* policy_load_beans(struct policy_check_s *pc);

/**
 * Check and try to repair a content.
 *
 * This function loads namespace info and initializes a load balancer and
 * a resolver, so it's not efficient. If you need to repair a lot of contents,
 * you'd better initialize struct policy_check_s and call
 * policy_load_beans() and policy_check_and_repair() yourself.
 *
 * @param url URL to the content
 * @param flags check flags (set to 0 if not needed)
 * @param err A place where to put errors
 * @return The number of problems detected on the content
 */
gint check_and_repair_content(struct hc_url_s *url,
		guint32 flags, GError **error);

/**
 * Same as check_and_repair_content() with a different signature.
 */
gint check_and_repair_content2(const gchar *ns,
		const gchar *container_id, const gchar *content_name,
		const gchar *content_version, guint32 flags, GError **error);

/**
 * Same as check_and_repair_content2() with a different signature and
 * flags forced to POLCHK_FLAG_FORCE_RAWX_REBUILD and POLCHK_FLAG_NOMD5.
 */
gint rebuild_broken_chunks_for_content(const gchar *ns,
		const gchar *container_id, const gchar *content_name,
		const gchar *content_version, gboolean check_only, GError **error);

#endif
