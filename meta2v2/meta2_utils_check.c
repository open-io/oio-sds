#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.check"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <librain.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#define M2CHK_FLAG_CLEAN_NSINFO 0x01
#define M2CHK_FLAG_CLEAN_LBPOOL 0x02

typedef struct header_check_s
{
	struct m2v2_check_s *check;
	struct bean_ALIASES_s *alias;
	struct bean_CONTENTS_HEADERS_s *header;
	struct storage_policy_s *stgpol;
	GArray *chunks; // (chunk_pair_t)
	GArray *unavail_chunks; // (chunk_pair_t)
} header_check_t;


typedef gboolean (*on_chunk_f) (header_check_t *hc,
		chunk_pair_t *pair, gpointer ctx);

typedef void (*on_end_f) (header_check_t *hc, gpointer ctx);

typedef struct single_check_s
{
	gpointer ctx;
	on_chunk_f on_chunk;
	on_end_f on_end;
} single_check_t;


// -------------------------------------------------------------------------
// Performs a set of checks on the sequence of chunk_pair_s (ordered by
// ascending position).
//
// All the checks may have an arbitrary context, helping them to
// accumulate a state between the calls.
// -------------------------------------------------------------------------

static inline gboolean
_check_is_not_last(single_check_t *check)
{
	return check->on_chunk || check->on_end;
}

static inline void
_check_one_chunk(header_check_t *hc, single_check_t *pcheck, chunk_pair_t *pair)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, hc);
	for (; _check_is_not_last(pcheck) ;++pcheck) {
		if (!pcheck->on_chunk)
			continue;
		if (!pcheck->on_chunk(hc, pair, pcheck->ctx))
			break;
	}
}

static inline void
_perform_last_check(header_check_t *hc, single_check_t *pcheck)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, hc);
	for (; _check_is_not_last(pcheck) ;++pcheck) {
		if (pcheck->on_end)
			pcheck->on_end(hc, pcheck->ctx);
	}
}

static inline void
_check_chunks_sequence(header_check_t *hc, single_check_t *checks)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, hc, checks);
	GArray *ga = hc->chunks;
	for (guint i=0; i < ga->len ;++i)
		_check_one_chunk(hc, checks, &g_array_index(ga, chunk_pair_t, i));
	_perform_last_check(hc, checks);
}

static inline struct m2v2_check_error_s *
m2v2_check_append_flaw(header_check_t *hc, int type, GError *error)
{
	if (!hc->check->flaws)
		hc->check->flaws = g_ptr_array_new();
	struct m2v2_check_error_s *flaw = g_malloc0(sizeof(struct m2v2_check_error_s));
	flaw->type = type;
	flaw->original_error = error ? error : NEWERROR(0, "Unknown error");
	flaw->alias = hc->alias;
	flaw->header = hc->header;
	g_ptr_array_add(hc->check->flaws, flaw);
	return flaw;
}

static inline int
_compare_int(register int p0, register int p1)
{
	return (p0 < p1) ? -1 : ((p0 > p1) ? 1 : 0);
}

gint
compare_pairs_positions(chunk_pair_t *c0, chunk_pair_t *c1)
{
	register int cmp;
	if (0 != (cmp = _compare_int(c0->position.meta, c1->position.meta)))
		return cmp;
	if (0 != (cmp = _compare_int(c0->position.parity, c1->position.parity)))
		return cmp;
	return _compare_int(c0->position.rain, c1->position.rain);
}

static void
_flaw_free(struct m2v2_check_error_s *flaw)
{
	if (flaw->original_error)
		g_clear_error(&(flaw->original_error));
	switch (flaw->type) {

		// DUPLI
		case M2CHK_CHUNK_DUPLI_SIZE:
			g_array_free(flaw->param.chunk_dupli_sizes.pairs, TRUE);
			break;
		case M2CHK_CHUNK_DUPLI_HASH:
			g_array_free(flaw->param.chunk_dupli_hashes.pairs, TRUE);
			break;
		case M2CHK_CHUNK_DUPLI_TOOMUCH:
			g_array_free(flaw->param.chunk_dupli_toomuch.pairs, TRUE);
			break;
		case M2CHK_CHUNK_DUPLI_TOOFEW:
			g_array_free(flaw->param.chunk_dupli_toofew.pairs, TRUE);
			break;
		case M2CHK_CHUNK_DUPLI_BAD_DISTANCE:
			g_array_free(flaw->param.chunk_dupli_dist.pairs, TRUE);
			break;

		// RAIN
		case M2CHK_CHUNK_RAIN_TOOMUCH:
			g_array_free(flaw->param.rain_toomuch.pairs_data, TRUE);
			g_array_free(flaw->param.rain_toomuch.pairs_parity, TRUE);
			break;
		case M2CHK_CHUNK_RAIN_TOOFEW:
			g_array_free(flaw->param.rain_toofew.pairs_data, TRUE);
			g_array_free(flaw->param.rain_toofew.pairs_parity, TRUE);
			g_array_free(flaw->param.rain_toofew.pairs_unavailable, TRUE);
			break;
		case M2CHK_CHUNK_RAIN_LOST:
			g_array_free(flaw->param.rain_lost.pairs_data, TRUE);
			g_array_free(flaw->param.rain_lost.pairs_parity, TRUE);
			break;
		case M2CHK_CHUNK_RAIN_BAD_DISTANCE:
			g_array_free(flaw->param.rain_dist.pairs_data, TRUE);
			g_array_free(flaw->param.rain_dist.pairs_parity, TRUE);
			break;

		// MISC
		case M2CHK_CONTENT_STGCLASS:
			g_array_free(flaw->param.stgclass.bad_pairs, TRUE);
			g_array_free(flaw->param.stgclass.all_pairs, TRUE);
			break;

		default:
			break;
	}
	g_free(flaw);
}

static GArray *
_pairs_copy(GPtrArray *src)
{
	GArray *res = g_array_new(FALSE, FALSE, sizeof(m2v2_chunk_pair_t));
	if (src && src->len) {
		for (guint i=0; i<src->len ;++i) {
			m2v2_chunk_pair_t pair;
			pair.chunk = ((chunk_pair_t*)g_ptr_array_index(src, i))->chunk;
			pair.content = ((chunk_pair_t*)g_ptr_array_index(src, i))->content;
			g_array_append_vals(res, &pair, 1);
		}
	}
	return res;
}

static GArray *
_pairs_copy2(GArray *src)
{
	GArray *res = g_array_new(FALSE, FALSE, sizeof(m2v2_chunk_pair_t));
	if (src && src->len) {
		for (guint i=0; i<src->len ;++i) {
			m2v2_chunk_pair_t pair;
			pair.chunk = (&g_array_index(src, chunk_pair_t, i))->chunk;
			pair.content = (&g_array_index(src, chunk_pair_t, i))->content;
			g_array_append_vals(res, &pair, 1);
		}
	}
	return res;
}

char *
extract_url_from_chunk(struct bean_CHUNKS_s *chunk)
{
	GString *chunk_url = CHUNKS_get_id(chunk);
	gchar *start, *end;

	start = strstr(chunk_url->str, "://");
	if (start)
		start += 3;
	else
		start = chunk_url->str;

	end = strchr(start, '/');
	if (!end)
		return g_strdup(start);
	else
		return g_strndup(start, end-start);
}

char *
location_from_chunk(struct bean_CHUNKS_s *chunk, struct grid_lbpool_s *glp)
{
	char * url = NULL;
	char * loc = NULL;
	struct service_info_s *rawx = NULL;
	url = extract_url_from_chunk(chunk);
	rawx = grid_lbpool_get_service_from_url(glp, "rawx", url);
	if (!rawx) {
		GRID_ERROR("Rawx not declared [%s]", url);
		g_free(url);
		return NULL;
	}

	loc = metautils_rawx_get_location(rawx);
	service_info_clean(rawx);
	g_free(url);

	return loc;
}

static void
_extract_location_from_services(header_check_t *hc, GPtrArray *dst, GPtrArray *gpa)
{
	struct chunk_pair_s *pair;
	char *loc = NULL;
	struct m2v2_check_error_s *flaw;

	for (guint i=0; i < gpa->len ;++i) {
		pair = g_ptr_array_index(gpa, i);
		loc = location_from_chunk(pair->chunk, hc->check->lbpool);
		if (!loc) {
			flaw = m2v2_check_append_flaw(hc, M2CHK_RAWX_UNKNOWN,
					NEWERROR(0, "RAWX [%s] not declared", CHUNKS_get_id(pair->chunk)->str));
			flaw->param.rawx_unknown.pair.chunk = pair->chunk;
			flaw->param.rawx_unknown.pair.content = pair->content;
		} else {
			g_ptr_array_add(dst, loc);
		}
		loc = NULL;
	}
}

static void
_free_strv2(GPtrArray *v2)
{
	if (!v2)
		return;
	g_ptr_array_add(v2, NULL);
	g_strfreev((gchar**) g_ptr_array_free(v2, FALSE));
}

static GError *
_check_distances(GPtrArray *locations, guint distance_requested)
{
	for (guint i=1; i < locations->len ;++i) {
		for (guint j=0; j < i; ++j) {
			guint distance = distance_between_location(
					locations->pdata[j], locations->pdata[i]);
			if (distance_requested > distance) {
				return NEWERROR(0, "Distance not respected (%u < %u)",
						distance, distance_requested);
			}
		}
	}
	return NULL;
}


// -------------------------------------------------------------------------
// XXX COMMON tests to all data_security policies XXX
// -------------------------------------------------------------------------

struct ctx_stgclass_s
{
	const struct storage_class_s *stgclass;
	GPtrArray *bad_pairs; // chunk_pair_t*
};

static gboolean
hook_CHUNK_stgclass(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_stgclass_s *ctx = u;

	// Lazy init
	if (!ctx->stgclass)
		ctx->stgclass = storage_policy_get_storage_class(hc->stgpol);
	if (!ctx->bad_pairs)
		ctx->bad_pairs = g_ptr_array_new();

	// Perform the check
	gchar *url = extract_url_from_chunk(pair->chunk);
	struct service_info_s *rawx = grid_lbpool_get_service_from_url(
			hc->check->lbpool, "rawx", url);
	if (rawx != NULL) {
		const gchar *stgclass = service_info_get_stgclass(rawx, "DUMMY");
		if (!storage_class_is_satisfied2(ctx->stgclass, stgclass, FALSE)) {
			g_ptr_array_add(ctx->bad_pairs, pair);
		}
		service_info_clean(rawx);
		rawx = NULL;
	}
	g_free(url);

	return TRUE;
}

static void
hook_END_stgclass(header_check_t *hc, void *u)
{
	struct ctx_stgclass_s *ctx = u;
	struct m2v2_check_error_s *flaw;

	if (ctx->bad_pairs != NULL) {
		if (ctx->bad_pairs->len > 0) {
			flaw = m2v2_check_append_flaw(hc, M2CHK_CONTENT_STGCLASS,
					NEWERROR(0,
						"Invalid storage class found: expected[%s], %d chunks have another",
						storage_class_get_name(ctx->stgclass), ctx->bad_pairs->len));
			flaw->param.stgclass.bad_pairs = _pairs_copy(ctx->bad_pairs);
			flaw->param.stgclass.all_pairs = _pairs_copy2(hc->chunks);
		}

		g_ptr_array_free(ctx->bad_pairs, TRUE);
	}
}


// -------------------------------------------------------------------------
// XXX DUPLICATED XXX
// -------------------------------------------------------------------------

// Collect all the chunks with the same position and perform some checks,
// e.g. check they have the same hash, the same size. Also check they are
// enough.
struct ctx_dupli_stgpol_s
{
	chunk_pair_t *last;
	GPtrArray *pairs;
	guint distance;
	guint replicas;
};

static void
_alert_for_invalid_dupli_stgpol(header_check_t *hc,
		struct ctx_dupli_stgpol_s *ctx)
{
	struct m2v2_check_error_s *flaw;

	if (ctx->pairs == NULL || ctx->pairs->len <= 0) {
		return;
	}

	// Check sizes
	if (ctx->pairs->len && 0 < CONTENTS_HEADERS_get_size(hc->header)) {
		gboolean match = FALSE;
		for (guint i=1; !match && i < ctx->pairs->len ;++i) {
			gint64 s0, s1;
			s0 = CHUNKS_get_size(((chunk_pair_t*)(ctx->pairs->pdata[0]))->chunk);
			s1 = CHUNKS_get_size(((chunk_pair_t*)(ctx->pairs->pdata[i]))->chunk);
			if (s0 != s1)
				match = TRUE;
		}
		if (match) {
			flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_DUPLI_SIZE,
					NEWERROR(0, "HASH mismatch at position [%d]",
						ctx->last->position.meta));
			flaw->param.chunk_dupli_sizes.pairs = _pairs_copy(ctx->pairs);
		}
	}

	// Check hashes
	if (ctx->pairs->len && 0 < CONTENTS_HEADERS_get_size(hc->header)) {
		gboolean match = FALSE;
		GByteArray *h0, *h1;
		for (guint i=1; !match && i < ctx->pairs->len ;++i) {
			h0 = CHUNKS_get_hash(((chunk_pair_t*)(ctx->pairs->pdata[0]))->chunk);
			h1 = CHUNKS_get_hash(((chunk_pair_t*)(ctx->pairs->pdata[i]))->chunk);
			if (0 != metautils_gba_cmp(h0, h1))
					match = TRUE;
		}
		if (match) {
			flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_DUPLI_HASH,
					NEWERROR(0, "HASH mismatch at position [%d]",
						ctx->last->position.meta));
			flaw->param.chunk_dupli_hashes.pairs = _pairs_copy(ctx->pairs);
		}
	}

	// Check replicas count
	if (ctx->pairs->len < ctx->replicas && 0 < CONTENTS_HEADERS_get_size(hc->header)) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_DUPLI_TOOFEW,
				NEWERROR(0, "Too few chunks [%u] at position [%u]",
				ctx->pairs->len, ctx->last->position.meta));
		flaw->param.chunk_dupli_toofew.pairs = _pairs_copy(ctx->pairs);
		flaw->param.chunk_dupli_toofew.count = ctx->replicas - ctx->pairs->len;
		flaw->param.chunk_dupli_toofew.dist = ctx->distance;
	}
	else if (ctx->pairs->len > ctx->replicas) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_DUPLI_TOOMUCH,
				NEWERROR(0, "Too many chunks [%u] at position [%u]",
				ctx->pairs->len, ctx->last->position.meta));
		flaw->param.chunk_dupli_toomuch.pairs = _pairs_copy(ctx->pairs);
		flaw->param.chunk_dupli_toomuch.count = ctx->pairs->len - ctx->replicas;
	}

	// Check the distance is respected
	GPtrArray *locations = g_ptr_array_new();
	_extract_location_from_services(hc, locations, ctx->pairs);
	GError *err = _check_distances(locations, ctx->distance);
	_free_strv2(locations);
	if (err) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_DUPLI_BAD_DISTANCE, err);
		flaw->param.chunk_dupli_dist.pairs = _pairs_copy(ctx->pairs);
	}
}

static gboolean
hook_CHUNK_dupli_stgpol(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_dupli_stgpol_s *ctx = u;

	// Lazy initiation
	if (!ctx->pairs)
		ctx->pairs = g_ptr_array_new();

	if (ctx->last && (pair->position.meta != ctx->last->position.meta)) {
		// Maybe alert for gaps
		if (ctx->last->position.meta + 1 != pair->position.meta) {
			gint first, last;
			first = ctx->last->position.meta + 1;
			last = pair->position.meta - 1;

			struct m2v2_check_error_s *flaw = m2v2_check_append_flaw(hc,
					M2CHK_CHUNK_DUPLI_GAP, NEWERROR(0,
						"No chunk between [%d] and [%d]", first, last));
			flaw->param.dupli_gap.first_missing = first;
			flaw->param.dupli_gap.last_missing = last;
		}

		// Now check the agregate consistency
		_alert_for_invalid_dupli_stgpol(hc, ctx);
		g_ptr_array_set_size(ctx->pairs, 0);
	}

	g_ptr_array_add(ctx->pairs, pair);
	ctx->last = pair;
	return TRUE;
}

static void
hook_END_dupli_stgpol(header_check_t *hc, void *u)
{
	struct ctx_dupli_stgpol_s *ctx = u;

	if (!ctx->pairs && CONTENTS_HEADERS_get_size(hc->header) > 0) {
		struct m2v2_check_error_s *flaw = m2v2_check_append_flaw(hc,
				M2CHK_CHUNK_DUPLI_GAP, NEWERROR(0, "No chunk at position 0"));
		flaw->param.dupli_gap.first_missing = 0;
		flaw->param.dupli_gap.last_missing = 0;
	}
	else {
		_alert_for_invalid_dupli_stgpol(hc, ctx);
		g_ptr_array_free(ctx->pairs, TRUE);
	}
}

// Compute the total size of the whole content, and raise a flaw if it
// differs from the size declared in the content_header.
struct ctx_total_size_s
{
	chunk_pair_t *last;
	gint64 size_last;
	gint64 size_total;
};

static gboolean
hook_CHUNK_dupli_total_size(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_total_size_s *ctx = u;
	(void) hc;

	if (!ctx->last || 0 != compare_pairs_positions(ctx->last, pair)) {
		ctx->last = pair;
		ctx->size_last = CHUNKS_get_size(pair->chunk);
		ctx->size_total += ctx->size_last;
	}

	return TRUE;
}

static void
hook_END_dupli_total_size(header_check_t *hc, void *u)
{
	struct ctx_total_size_s *ctx = u;
	gint64 size_real = CONTENTS_HEADERS_get_size(hc->header);
	if (ctx->size_total != size_real) {
		m2v2_check_append_flaw(hc, M2CHK_CONTENT_SIZE_MISMATCH,
				NEWERROR(0, "Header size "
				"[%"G_GINT64_FORMAT"] mismatch with concat size"
				"[%"G_GINT64_FORMAT"]", size_real, ctx->size_total));
	}
}

// Check there are on chunks with well formatted positions
static gboolean
hook_CHUNK_dupli_no_rained(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_seq_hash_s *ctx = u;
	(void) hc;
	(void) ctx;
	if (pair->position.rain != -1) {
		struct m2v2_check_error_s *flaw = m2v2_check_append_flaw(hc,
				M2CHK_CHUNK_DUPLI_BADPOS, NEWERROR(0,
					"RAIN chunk present at position [%u,%u]",
					pair->position.meta, pair->position.rain));
		flaw->param.dupli_badpos.pair.chunk = pair->chunk;
		flaw->param.dupli_badpos.pair.content = pair->content;
		return FALSE;
	}

	return TRUE;
}

// Perform all the checks belonging to a dupplicated content.
static void
_check_dupli_alias(header_check_t *hc, guint replicas, guint distance)
{
	struct ctx_stgclass_s ctx_stgclass = { NULL, NULL };
	struct ctx_dupli_stgpol_s ctx_dupli_stgpol = { NULL, NULL,
		.distance=distance, .replicas=replicas };
	struct ctx_total_size_s ctx_total_size = { NULL, 0, 0 };

	GRID_TRACE2("%s(%p,%u,%u)", __FUNCTION__, hc, replicas, distance);

	/* Prohibes checks for empty content */
	if (CONTENTS_HEADERS_get_size(hc->header) > 0)  {
		single_check_t checks[] = {
			{ NULL, hook_CHUNK_dupli_no_rained, NULL },
			{ &ctx_stgclass, hook_CHUNK_stgclass, hook_END_stgclass },
			{ &ctx_dupli_stgpol, hook_CHUNK_dupli_stgpol, hook_END_dupli_stgpol },
			{ &ctx_total_size, hook_CHUNK_dupli_total_size, hook_END_dupli_total_size },
			{ NULL, NULL, NULL } // End beacon
		};
		_check_chunks_sequence(hc, checks);
	}
}


// -------------------------------------------------------------------------
// XXX RAIN XXX
// -------------------------------------------------------------------------

// Collect all the chunks belonging to the same meta-chunk, and compute
// some checks on it. E.g. on their number (data, parity, total).
struct ctx_rain_stgpol_s
{
	gint64 size_total;
	chunk_pair_t *last;
	GPtrArray *chunks_data;
	GPtrArray *chunks_parity;
	guint k, m, distance;
	const gchar *algo;
};

static inline void
_alert_for_invalid_rain_stgpol(header_check_t *hc, struct ctx_rain_stgpol_s *ctx)
{
	struct m2v2_check_error_s *flaw;
	guint lenp = ctx->chunks_parity->len;
	guint lend = ctx->chunks_data->len;
	guint actual_k = ctx->k;
	gint64 size_real = CONTENTS_HEADERS_get_size(hc->header);
	gint64 ns_chunk_size = namespace_chunk_size(hc->check->ns_info,
			hc_url_get(hc->check->url, HCURL_NS));
	gint64 metachunk_size = ns_chunk_size;

	GRID_TRACE2("%s(%p,%u,%u)", __FUNCTION__, hc, lend, lenp);

	if (size_real == 0) {
		GRID_DEBUG("Content is empty, skipping RAIN tests");
		return;
	}

	// Check the count is respected
	if (lenp + lend == 0 || ctx->last == NULL) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_LOST, NEWERROR(0,
					"No chunks at all!"));
		// Create empty arrays
		flaw->param.rain_lost.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_lost.pairs_parity = _pairs_copy(ctx->chunks_parity);
		return;
	}

	// For last position of the content, actual_k may be smaller than k,
	// depending on the RAIN algorithm and the metachunk size
	if (ctx->last->position.meta == (size_real / ns_chunk_size)) {
		// This won't work if we allow first chunks to be smaller than
		// namespace chunk size, but it's the only way to get metachunk size
		metachunk_size = (size_real % ns_chunk_size);
		gint64 rain_chunk_size = get_chunk_size(metachunk_size,
				ctx->k, ctx->m, ctx->algo);
		actual_k = 1 + ((metachunk_size - 1) / rain_chunk_size);
		GRID_TRACE("metachunk size: %ld, rain chunk size: %ld, k: %u, actual_k: %u",
				metachunk_size, rain_chunk_size, ctx->k, actual_k);
	}

	if (lenp + lend > actual_k + ctx->m) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_TOOMUCH, NEWERROR(0,
				"Too many chunks at [%u] (expected %u+%u, got %u+%u)",
				ctx->last->position.meta, actual_k, ctx->m, lend, lenp));
		flaw->param.rain_toomuch.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_toomuch.pairs_parity = _pairs_copy(ctx->chunks_parity);
	}
	else if (lenp + lend < actual_k) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_LOST, NEWERROR(0,
				"Missing too many chunks at [%u] (expected %u+%u, got %u+%u)",
				ctx->last->position.meta, actual_k, ctx->m, lend, lenp));
		flaw->param.rain_lost.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_lost.pairs_parity = _pairs_copy(ctx->chunks_parity);
	}
	// The 2 following flaws may happen at the same time,
	// but fixing one of them will fix both.
	else if (ctx->m != lenp) {
		gint delta = (int)ctx->m - (int)lenp;
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_TOOFEW, NEWERROR(0,
					"Missing [%d] parity chunks at [%u]", delta, ctx->last->position.meta));
		flaw->param.rain_toofew.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_toofew.pairs_parity = _pairs_copy(ctx->chunks_parity);
		flaw->param.rain_toofew.pairs_unavailable = _pairs_copy2(hc->unavail_chunks);
		flaw->param.rain_toofew.metachunk_pos = ctx->last->position.meta;
	} /* TODO: case ((k - 1) * chunk-size) >= metachunk_size not threated as an error */
	/* FIXME: FALSE block reconstruction from hc_policycheck_v2 */
	else if (actual_k != lend) {
		gint delta = actual_k - (int)lend;
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_TOOFEW, NEWERROR(0,
					"Missing [%d] data chunks at [%u] (expected %u, got %u)",
					delta, ctx->last->position.meta, actual_k, lend));
		flaw->param.rain_toofew.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_toofew.pairs_parity = _pairs_copy(ctx->chunks_parity);
		flaw->param.rain_toofew.pairs_unavailable = _pairs_copy2(hc->unavail_chunks);
		flaw->param.rain_toofew.metachunk_pos = ctx->last->position.meta;
	}

	// Check the distance is respected
	GPtrArray *locations = g_ptr_array_new();
	_extract_location_from_services(hc, locations, ctx->chunks_data);
	_extract_location_from_services(hc, locations, ctx->chunks_parity);
	GError *err = _check_distances(locations, ctx->distance);
	_free_strv2(locations);
	if (err) {
		flaw = m2v2_check_append_flaw(hc, M2CHK_CHUNK_RAIN_BAD_DISTANCE, err);
		flaw->param.rain_dist.pairs_data = _pairs_copy(ctx->chunks_data);
		flaw->param.rain_dist.pairs_parity = _pairs_copy(ctx->chunks_parity);
	}
}

static gboolean
hook_CHUNK_rain_stgpol(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_rain_stgpol_s *ctx = u;

	// Lazy initiation
	if (!ctx->chunks_data)
		ctx->chunks_data = g_ptr_array_new();
	if (!ctx->chunks_parity)
		ctx->chunks_parity = g_ptr_array_new();

	if (ctx->last && (pair->position.meta != ctx->last->position.meta)) {
		// TODO alert for gaps

		// Now alert for an invalid storage policy
		_alert_for_invalid_rain_stgpol(hc, ctx);
		g_ptr_array_set_size(ctx->chunks_data, 0);
		g_ptr_array_set_size(ctx->chunks_parity, 0);
	}

	if (pair->position.parity)
		g_ptr_array_add(ctx->chunks_parity, pair);
	else {
		ctx->size_total += CHUNKS_get_size(pair->chunk);
		g_ptr_array_add(ctx->chunks_data, pair);
	}
	ctx->last = pair;
	return TRUE;
}

static void
hook_END_rain_stgpol(header_check_t *hc, void *u)
{
	struct ctx_rain_stgpol_s *ctx = u;

	// If these are not set, there is probably a big problem
	if (!ctx->chunks_data)
		ctx->chunks_data = g_ptr_array_new();
	if (!ctx->chunks_parity)
		ctx->chunks_parity = g_ptr_array_new();

	// Perform the last check
	_alert_for_invalid_rain_stgpol(hc, ctx);

	// Check for the total size
	gint64 size_real = CONTENTS_HEADERS_get_size(hc->header);
	if (ctx->size_total != size_real) {
		GRID_WARN("Header size "
				"[%"G_GINT64_FORMAT"] mismatch with concat size "
				"[%"G_GINT64_FORMAT"]", size_real, ctx->size_total);
	}

	// Cleanup
	if (ctx->chunks_data)
		g_ptr_array_free(ctx->chunks_data, TRUE);
	if (ctx->chunks_parity)
		g_ptr_array_free(ctx->chunks_parity, TRUE);
}

// Filter out chunks with a non-RAIN position. They are immediately
// discarded so that they do not participate to othger checks.
struct ctx_rain_only_s
{
	guint k, m;
};

static gboolean
hook_CHUNK_rain_only(header_check_t *hc, chunk_pair_t *pair, void *u)
{
	struct ctx_rain_only_s *ctx = u;
	(void) hc;

	if (pair->position.rain < 0)
		return FALSE;

	if ((guint)(pair->position.rain) > ctx->k + ctx->m) {
		struct m2v2_check_error_s *flaw = m2v2_check_append_flaw(hc,
				M2CHK_CHUNK_RAIN_BADPOS, NEWERROR(0,
					"Chunk [%u.%u] exceeding the max number [%u+%u]",
					pair->position.meta, pair->position.rain, ctx->k, ctx->m));
		flaw->param.rain_badpos.pair.chunk = pair->chunk;
		flaw->param.rain_badpos.pair.content = pair->content;
	}
	return TRUE;
}

// Perform all the checks related to RAIN'ed chunks
static void
_check_rained_alias(header_check_t *hc, guint k, guint m, guint distance,
		const gchar *algo)
{
	struct ctx_stgclass_s ctx_stgclass = { NULL, NULL };
	struct ctx_rain_only_s ctx_rain_only = {
		.k = k, .m = m };
	struct ctx_rain_stgpol_s ctx_rain_stgpol = { 0, NULL, NULL,
		.k = k, .m = m, .distance = distance, .algo = algo };

	GRID_TRACE2("%s(%p,%u,%u,%u)", __FUNCTION__, hc, k, m, distance);

	single_check_t checks[] = {
		{ &ctx_rain_only, hook_CHUNK_rain_only, NULL },
		{ &ctx_stgclass, hook_CHUNK_stgclass, hook_END_stgclass },
		{ &ctx_rain_stgpol, hook_CHUNK_rain_stgpol, hook_END_rain_stgpol },
		{ NULL, NULL, NULL }
	};

	_check_chunks_sequence(hc, checks);
}


// -------------------------------------------------------------------------
// XXX Internals XXX
// -------------------------------------------------------------------------

static struct bean_CONTENTS_HEADERS_s*
_get_header(struct m2v2_check_s *check, GByteArray *id0)
{
	for (guint i=0; i < check->headers->len ;++i) {
		struct bean_CONTENTS_HEADERS_s *hdr = g_ptr_array_index(check->headers, i);
		GByteArray *id1 = CONTENTS_HEADERS_get_id(hdr);
		if (!metautils_gba_cmp(id0, id1))
			return hdr;
	}
	return NULL;
}

static struct bean_CHUNKS_s *
_get_chunk(GPtrArray *chunks, GString *id0)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, chunks, id0);
	for (guint i=0; i < chunks->len ;++i) {
		struct bean_CHUNKS_s *chunk = g_ptr_array_index(chunks, i);
		GString *id1 = CHUNKS_get_id(chunk);
		if (g_string_equal(id0, id1))
			return chunk;
	}
	return NULL;
}

void
init_chunk_pair(GPtrArray *chunks, chunk_pair_t *pair, struct bean_CONTENTS_s *c0)
{
	GString *pos = c0 ? CONTENTS_get_position(c0) : NULL;

	memset(pair, 0, sizeof(chunk_pair_t));
	pair->content = c0;
	pair->chunk = _get_chunk(chunks, CONTENTS_get_chunk_id(c0));
	pair->position.meta = pair->position.rain = -1;

	m2v2_parse_chunk_position(pos->str, &(pair->position.meta),
			&(pair->position.parity), &(pair->position.rain));
}

static GError*
_load_storage_policy(header_check_t *hc)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, hc);

	GString *gpol = CONTENTS_HEADERS_get_policy(hc->header);
	if (!gpol)
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Storage Policy undefined");
	DEBUG("Checking existence of stgpol : [%s]", gpol->str);

	hc->stgpol = storage_policy_init(hc->check->ns_info, gpol->str);
	if (!hc->stgpol)
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Storage Policy unknown [%s]",
				gpol->str);
	return NULL;
}

static GError *
_load_header_chunks(header_check_t *hc)
{
	struct bean_CONTENTS_s *c0;
	chunk_pair_t pair;
	GByteArray *id0, *id1;

	GRID_TRACE2("%s(%p)", __FUNCTION__, hc);
	GPtrArray *gpa = hc->check->contents;
	id0 = CONTENTS_HEADERS_get_id(hc->header);
	for (guint i=0; i < gpa->len ;++i) {
		c0 = g_ptr_array_index(gpa, i);
		id1 = CONTENTS_get_content_id(c0);
		if (!metautils_gba_cmp(id0, id1)) {
			// Look for a matching and available chunk
			init_chunk_pair(hc->check->chunks, &pair, c0);
			if (pair.chunk != NULL) {
				g_array_append_vals(hc->chunks, &pair, 1);
			} else {
				// Look for a matching but unavailable chunk
				init_chunk_pair(hc->check->unavail_chunks, &pair, c0);
				if (pair.chunk != NULL)
					g_array_append_vals(hc->unavail_chunks, &pair, 1);
			}
		}
	}
	g_array_sort(hc->chunks, (GCompareFunc) compare_pairs_positions);
	return NULL;
}

static void
_check_header(header_check_t *hc)
{
	const struct data_security_s *ds;
	guint rain_k, rain_m, replicas, distance;
	const gchar *algo = NULL;

	inline guint _get_int_param(const gchar *key, guint def) {
		const char *vstr = data_security_get_param(ds, key);
		if (!vstr)
			return def;
		return atoi(vstr);
	}

	GRID_TRACE2("%s(%p)", __FUNCTION__, hc);
	ds = storage_policy_get_data_security(hc->stgpol);
	switch (data_security_get_type(ds)) {
		case DUPLI:
			distance = _get_int_param(DS_KEY_DISTANCE, 1);
			replicas = _get_int_param(DS_KEY_COPY_COUNT, 1);
			return _check_dupli_alias(hc, replicas, distance);
		case RAIN:
			distance = _get_int_param(DS_KEY_DISTANCE, 1);
			rain_k = _get_int_param(DS_KEY_K, 3);
			rain_m = _get_int_param(DS_KEY_M, 2);
			algo = data_security_get_param(ds, DS_KEY_ALGO);
			return _check_rained_alias(hc, rain_k, rain_m, distance, algo);
		case DS_NONE:
			return _check_dupli_alias(hc, 1, 1);
	}
}

static GError *
_check_alias(struct m2v2_check_s *check, struct bean_ALIASES_s *alias)
{
	GError *e = NULL;
	header_check_t hc;

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, check, alias);
	memset(&hc, 0, sizeof(header_check_t));
	hc.check = check;
	hc.alias = alias;
	hc.chunks = g_array_new(FALSE, FALSE, sizeof(chunk_pair_t));
	hc.unavail_chunks = g_array_new(FALSE, FALSE, sizeof(chunk_pair_t));

	hc.header = _get_header(check, ALIASES_get_content_id(alias));
	if (!hc.header)
		e = NEWERROR(CODE_CONTENT_CORRUPTED, "Missing HEADER");
	if (!e)
		e = _load_storage_policy(&hc);
	if (!e)
		e = _load_header_chunks(&hc);
	if (!e)
		_check_header(&hc);

	if (hc.stgpol)
		storage_policy_clean(hc.stgpol);
	g_array_free(hc.chunks, TRUE);
	g_array_free(hc.unavail_chunks, TRUE);

	return e;
}

static void
_init_m2v2_check(struct m2v2_check_s *check, struct hc_url_s *url,
		struct check_args_s *args)
{
	memset(check, 0, sizeof(struct m2v2_check_s));
	check->url = hc_url_dup(url);
	check->aliases = g_ptr_array_new();
	check->headers = g_ptr_array_new();
	check->contents = g_ptr_array_new();
	check->chunks = g_ptr_array_new();
	check->props = g_ptr_array_new();
	check->flaws = g_ptr_array_new();
	check->unavail_chunks = g_ptr_array_new();

	check->flags |= M2CHK_FLAG_CLEAN_NSINFO;
	if (args && args->ns_info)
		check->ns_info = namespace_info_dup(args->ns_info, NULL);
	else {
		check->ns_info = get_namespace_info(hc_url_get(check->url,
					HCURL_NSPHYS), NULL);
	}

	if (args && args->lbpool)
		check->lbpool = args->lbpool;
	else {
		check->flags |= M2CHK_FLAG_CLEAN_LBPOOL;
		check->lbpool = grid_lbpool_create(hc_url_get(check->url, HCURL_NSPHYS));
		grid_lbpool_reconfigure(check->lbpool, check->ns_info);
		GError *err = gridcluster_reload_lbpool(check->lbpool);
		if (err != NULL) {
			GRID_ERROR("Failed to reload the LB pool : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
	}
}

static void
_clean_m2v2_check(struct m2v2_check_s *check)
{
	if (check->flaws) {
		while (check->flaws->len > 0) {
			struct m2v2_check_error_s *flaw = g_ptr_array_index(check->flaws, 0);
			g_ptr_array_remove_index_fast(check->flaws, 0);
			_flaw_free(flaw);
		}
		g_ptr_array_free(check->flaws, TRUE);
		check->flaws = NULL;
	}

	if (check->ns_info && (check->flags & M2CHK_FLAG_CLEAN_NSINFO)) {
		namespace_info_free(check->ns_info);
		check->ns_info = NULL;
	}

	if (check->lbpool && (check->flags & M2CHK_FLAG_CLEAN_LBPOOL)) {
		grid_lbpool_destroy(check->lbpool);
		check->lbpool = NULL;
	}

	_bean_cleanv2(check->aliases);
	_bean_cleanv2(check->headers);
	_bean_cleanv2(check->contents);
	_bean_cleanv2(check->chunks);
	_bean_cleanv2(check->props);
	_bean_cleanv2(check->unavail_chunks);
	hc_url_clean(check->url);
}

static void
_hook_dispatch_beans(gpointer c, gpointer bean)
{
	struct m2v2_check_s *check = c;

	if (DESCR(bean) == &descr_struct_CHUNKS)
		g_ptr_array_add(check->chunks, _bean_dup(bean));
	else if (DESCR(bean) == &descr_struct_CONTENTS)
		g_ptr_array_add(check->contents, _bean_dup(bean));
	else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
		g_ptr_array_add(check->headers, _bean_dup(bean));
	else if (DESCR(bean) == &descr_struct_ALIASES)
		g_ptr_array_add(check->aliases, _bean_dup(bean));
}

/* ------------------------------------------------------------------------- */

struct m2v2_check_s*
m2v2_check_create(struct hc_url_s *url, struct check_args_s *args)
{
	g_assert(url != NULL);
	struct m2v2_check_s *check = g_malloc0(sizeof(struct m2v2_check_s));
	_init_m2v2_check(check, url, args);
	return check;
}

void
m2v2_check_destroy(struct m2v2_check_s *check)
{
	if (!check)
		return;
	_clean_m2v2_check(check);
	g_free(check);
}

void
m2v2_check_feed_with_bean_list(struct m2v2_check_s *check, GSList *beans)
{
	for (; beans ;beans=beans->next)
		_hook_dispatch_beans(check, beans->data);
}

GError*
m2v2_check_consistency(struct m2v2_check_s *check)
{
	guint count_errors = 0;

	GRID_TRACE2("<%s> Checking [%s] a[%u] h[%u] co[%u] cu[%u]",
			__FUNCTION__, hc_url_get(check->url, HCURL_WHOLE),
			check->aliases->len, check->headers->len,
			check->contents->len, check->chunks->len);

	for (guint i = 0; i < check->aliases->len ;++i) {
		GError *err = _check_alias(check, g_ptr_array_index(check->aliases, i));
		if (NULL != err) {
			++ count_errors;
			GRID_WARN("Erroneous ALIAS [%s] : (%d) %s",
					hc_url_get(check->url, HCURL_WHOLE),
					err->code, err->message);
			g_clear_error(&err);
		}
	}

	if (check->flaws->len) {
		GRID_WARN("Checking [%s] found [%u] flaws",
				hc_url_get(check->url, HCURL_WHOLE), check->flaws->len);
		for (guint i=0; i < check->flaws->len ;++i) {
			struct m2v2_check_error_s *flaw = check->flaws->pdata[i];
			GRID_NOTICE("FLAW: path[%s] version[%"G_GINT64_FORMAT"]"
					" type=%d code=%d %s",
					ALIASES_get_alias(flaw->alias)->str,
					ALIASES_get_version(flaw->alias),
					flaw->type, flaw->original_error->code,
					flaw->original_error->message);
		}
	}

	if (!count_errors)
		return NULL;
	return NEWERROR(500, "Check failed, check for flaws");
}

static guint
_count_meaningful_flaws(struct m2v2_check_s *check, guint32 mask)
{
	guint count_meaningful = 0;

	for (guint i=0; i < check->flaws->len ; ++i) {
		struct m2v2_check_error_s *flaw = check->flaws->pdata[i];
		switch (flaw->type) {
			case M2CHK_CHUNK_DUPLI_GAP:
				if (mask & M2V2_CHECK_GAPS)
					++ count_meaningful;
				break;

			case M2CHK_CHUNK_DUPLI_BADPOS:
			case M2CHK_CHUNK_DUPLI_SIZE:
			case M2CHK_CHUNK_DUPLI_HASH:
			case M2CHK_CHUNK_DUPLI_TOOMUCH:
			case M2CHK_CHUNK_DUPLI_TOOFEW:
				++ count_meaningful;
				break;

			case M2CHK_CHUNK_DUPLI_BAD_DISTANCE:
				if (mask & M2V2_CHECK_DIST)
					++ count_meaningful;
				break;

			case M2CHK_CHUNK_RAIN_BADPOS:
			case M2CHK_CHUNK_RAIN_TOOMUCH:
			case M2CHK_CHUNK_RAIN_TOOFEW:
			case M2CHK_CHUNK_RAIN_LOST:
			case M2CHK_CHUNK_RAIN_BAD_DISTANCE:
				if (mask & M2V2_CHECK_DIST)
					++ count_meaningful;
				break;

			case M2CHK_CONTENT_SIZE_MISMATCH:
				++ count_meaningful;
				break;

			case M2CHK_CONTENT_STGCLASS:
				if (mask & M2V2_CHECK_STGCLS)
					++ count_meaningful;
				break;

			case M2CHK_RAWX_UNKNOWN:
				if (mask & M2V2_CHECK_SRVINFO)
					++ count_meaningful;
				break;
		}
	}

	return count_meaningful;
}

GError*
m2db_check_alias_beans_list(struct hc_url_s *url, GSList *beans,
		struct check_args_s *args)
{
	struct m2v2_check_s check;
	GError *err = NULL;

	_init_m2v2_check(&check, url, args);
	for (; beans ;beans = beans->next)
		_hook_dispatch_beans(&check, beans->data);

	if (NULL == (err = m2v2_check_consistency(&check))) {
		if (0 < _count_meaningful_flaws(&check, args->mask_checks))
			err = NEWERROR(CODE_CONTENT_CORRUPTED, "Flaws found");
	}
	_clean_m2v2_check(&check);
	return err;
}

guint32
m2db_get_mask_check_put(struct namespace_info_s *ni)
{
	guint32 result = M2V2_CHECK_GAPS | M2V2_CHECK_DIST
		| M2V2_CHECK_STGCLS;
	if (!ni || !ni->options)
		return result;

	gchar *v;

	v = gridcluster_get_nsinfo_strvalue(ni, "meta2_check.put.GAPS", "true");
	if (!metautils_cfg_get_bool(v, TRUE))
		result &= ~M2V2_CHECK_GAPS;
	g_free(v);

	v = gridcluster_get_nsinfo_strvalue(ni, "meta2_check.put.DISTANCE", "true");
	if (!metautils_cfg_get_bool(v, TRUE))
		result &= ~M2V2_CHECK_DIST;
	g_free(v);

	v = gridcluster_get_nsinfo_strvalue(ni, "meta2_check.put.STGCLASS", "true");
	if (!metautils_cfg_get_bool(v, TRUE))
		result &= ~M2V2_CHECK_STGCLS;
	g_free(v);

	v = gridcluster_get_nsinfo_strvalue(ni, "meta2_check.put.SRVINFO", "false");
	if (metautils_cfg_get_bool(v, FALSE))
		result |= M2V2_CHECK_SRVINFO;
	g_free(v);

	return result;
}

