#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "polcheck"
#endif

#include <string.h>

#include <neon/ne_uri.h>
#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <cluster/lib/gridcluster.h>
#include <resolver/hc_resolver.h>
#include <client/c/lib/rainx_remote.h>

#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_lb.h>

#include "../lib/content_check.h"
#include "../lib/http_pipe.h"
#include "./policycheck_repair.h"

//------------------------------------------------------------------------------
// Data-structures helpers
//------------------------------------------------------------------------------

#define GA_APPEND(D,S,I) do { \
	void *p = &g_array_index((S), int, (I)); \
	g_array_append_vals((D), p, 1); \
} while (0)

struct slice_s { guint start, length; };

static GArray *
_ga_hollow_empty(GArray *src)
{
	return g_array_sized_new(FALSE, FALSE,
			g_array_get_element_size(src), src->len);
}

static GArray *
_ga_hollow_copy(GArray *src)
{
	GArray *copy = _ga_hollow_empty(src);

	for (guint i=0; i < src->len ;++i)
		GA_APPEND(copy, src, i);

	return copy;
}

// Sorts the array in place and returns it.
static GArray *
_ga_sort(GCompareFunc cmp, GArray *src)
{
	g_array_sort(src, cmp);
	return src;
}

// Only (really) works with a sorted array! A sequence in the array is a set
// of consecutive items, wich 2 by 2 give 0 through the comparison function
static struct slice_s
_ga_longest_sequence(GArray *src, GCompareFunc cmp)
{
	struct slice_s longest = {0,0}, tmp = {0,0};

	if (src->len < 2) {
		longest.start = 0;
		longest.length = src->len;
		return longest;
	}

	void *last = & g_array_index(src, int, 0);
	for (guint i=1; i < src->len ;++i) {
		void *current = &g_array_index(src, int, i);
		if (0 == cmp(current, last))
			++ tmp.length;
		else {
			// check if we found a new longest sequence
			if (tmp.length > longest.length)
				memcpy(&longest, &tmp, sizeof(struct slice_s));
			// Restart the current sequence
			tmp.start = i;
			tmp.length = 1;
		}
		last = current;
	}

	if (tmp.length > longest.length)
		memcpy(&longest, &tmp, sizeof(struct slice_s));
	return longest;
}

// Buils two arrays : a first with a copy of the elements in the specified range
// and a second with the elements out of this range.
static void
_ga_splice(GArray *src, guint start, guint length,
		GArray **rin, GArray **rout)
{
	GArray *in, *out;
	in = _ga_hollow_empty(src);
	out = _ga_hollow_empty(src);

	for (guint i=0; i<start && i<src->len ;++i)
		GA_APPEND(out, src, i);

	for (guint i=start; i<start+length && i<src->len ;++i)
		GA_APPEND(in, src, i);

	for (guint i=start+length; i<src->len ;++i)
		GA_APPEND(out, src, i);

	*rin = in;
	*rout = out;
}

static inline guint
_quorum_length(guint len)
{
	return 1 + ((len % 2) ? len+1 : len) / 2;
}

// Detects a quorum : we sort a copy of the original array, according to the
// comparison function provided, and then alongside a single run of the array
// we will detect the longest sequence of elements on wich the comparison
// function returns 0.
static gboolean
_get_quorum(GArray *src, GCompareFunc cmp, GArray **quorum, GArray **bad)
{
	GArray *sorted_copy = _ga_sort(cmp, _ga_hollow_copy(src));
	struct slice_s longest = _ga_longest_sequence(sorted_copy, cmp);

	if (longest.length <= _quorum_length(src->len)) {
		g_array_free(sorted_copy, TRUE);
		*quorum = *bad = NULL;
		return FALSE;
	}
	else {
		_ga_splice(sorted_copy, longest.start, longest.length, quorum, bad);
		g_array_free(sorted_copy, TRUE);
		return TRUE;
	}
}

static GSList*
_gslist_keep_tail(GSList *src, guint n)
{
	GSList *tail, *nth;
	if (!(nth = g_slist_nth(src, n-1)))
		return NULL;
	tail = nth->next;
	nth->next = NULL;
	return tail;
}

static GSList*
_gslist_poll_n(GSList **src, guint n)
{
	GSList *shuffled = metautils_gslist_shuffle(*src);
	*src = _gslist_keep_tail(shuffled, n);
	return shuffled;
}


//------------------------------------------------------------------------------
// HTTP helpers
//------------------------------------------------------------------------------

static GError *
_request_prepare(const gchar *m, const gchar *u, ne_session **ps, ne_request **pr)
{
	GError *err = NULL;
	ne_uri uri;

	memset(&uri, 0, sizeof(uri));
	ne_uri_parse(u, &uri);

	if (!(*ps = ne_session_create("http", uri.host, uri.port)))
		err = NEWERROR(500, "Cannot open a new WebDAV session");
	else {
		ne_set_connect_timeout(*ps, 10);
		ne_set_read_timeout(*ps, 30);

		if (!(*pr = ne_request_create(*ps, m, uri.path))) {
			err = NEWERROR(500, "Cannot open a new WebDAV session");
			ne_session_destroy(*ps);
			*ps = NULL;
		}
	}

	ne_uri_free(&uri);
	return err;
}

static GError *
_request_dispatch(ne_session *session, ne_request *request)
{
	int ne_rc = ne_request_dispatch(request);
	switch (ne_rc) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2)
				return NEWERROR(1000 + ne_get_status(request)->code,
					"Download error: %s", ne_get_error(session));
			return NULL;
		case NE_ERROR:
			return NEWERROR(500, "Caller error: %s", ne_get_error(session));
		case NE_TIMEOUT:
			return NEWERROR(10060, "Timeout: %s", ne_get_error(session));
		case NE_CONNECT:
			return NEWERROR(10061, "Connection error: %s", ne_get_error(session));
		case NE_AUTH:
			return NEWERROR(500, "Authentication error: %s", ne_get_error(session));
		default:
			return NEWERROR(500, "Unexpected error: %s", ne_get_error(session));
	}
}

//------------------------------------------------------------------------------
// Initial test download
//------------------------------------------------------------------------------

static GSList *
_pairs_extract_srvinfo(struct grid_lbpool_s *lbpool, GArray *pairs)
{
	GSList *result = NULL;

	for (guint i=0; i < pairs->len ;i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(pairs, m2v2_chunk_pair_t, i);
		gchar *url = extract_url_from_chunk(pair->chunk);
		if (NULL != url) {
			struct service_info_s *rawx;
			rawx = grid_lbpool_get_service_from_url( lbpool, "rawx", url);
			g_free(url);
			if (NULL != rawx)
				result = g_slist_prepend(result, rawx);
		}
	}

	return result;
}

static GSList*
_pairs_extract_contents(GArray *pairs)
{
	GSList *contents = NULL;
	for (guint i=0; i < pairs->len ;++i) {
		m2v2_chunk_pair_t *pair = &g_array_index(pairs, m2v2_chunk_pair_t, i);
		contents = g_slist_prepend(contents, pair);
	}
	return g_slist_reverse(contents);
}

static char *
_get_chunk_id(struct service_info_s *rawx)
{
	void _append(GString *gstr, const gchar *s) {
		if (gstr->str[gstr->len - 1] != '/' && *s != '/')
			g_string_append_c(gstr, '/');
		g_string_append(gstr, s);
	}

	gchar *strvol, straddr[STRLEN_ADDRINFO], strid[65];

	grid_addrinfo_to_string(&(rawx->addr), straddr, sizeof(straddr));
	strvol = metautils_rawx_get_volume(rawx);
	SHA256_randomized_string(strid, sizeof(strid));

	GString *gstr = g_string_new("http://");
	_append(gstr, straddr);
	_append(gstr, strvol);
	_append(gstr, strid);

	g_free(strvol);

	return g_string_free(gstr, FALSE);
}

static m2v2_chunk_pair_t *
_forge_pair_copy_DUPLI(m2v2_chunk_pair_t *src, struct service_info_s *rawx)
{
	m2v2_chunk_pair_t *result = g_malloc0(sizeof(m2v2_chunk_pair_t));
	char *cid = _get_chunk_id(rawx);
	result->chunk = _bean_dup(src->chunk);
	CHUNKS_set2_id(result->chunk, cid);
	result->content = _bean_dup(src->content);
	CONTENTS_set2_chunk_id(result->content, cid);
	g_free(cid);
	return result;
}

static GSList *
_get_additional_pairs_DUPLI(struct policy_check_s *pc, m2v2_chunk_pair_t *src,
		GSList *used_loc, gint count, guint dist)
{
	struct service_info_s **array = NULL;
	GSList * result = NULL;

	struct lb_next_opt_ext_s opt;
	memset(&opt, '\0', sizeof(opt));
	opt.req.max = count;
	opt.req.distance = dist;
	opt.req.duplicates = FALSE;
	opt.req.strict_stgclass = FALSE;
	opt.srv_inplace = used_loc;

	struct grid_lb_iterator_s *iter = grid_lbpool_get_iterator(pc->lbpool, "rawx");
	if (!grid_lb_iterator_next_set2(iter, &array, &opt)) {
		GRID_ERROR("Cannot get enough Rawx to satisfy the policy");
		return NULL;
	}

	for (guint i = 0; i < g_strv_length((char **)array); i++)
		result = g_slist_prepend(result, _forge_pair_copy_DUPLI(src, array[i]));

	service_info_cleanv(array, FALSE);
	return result;
}

static void
_clear_chunk_pair(gpointer pair)
{
	if (!pair)
		return;

	_bean_clean(((m2v2_chunk_pair_t*)pair)->content);
	_bean_clean(((m2v2_chunk_pair_t*)pair)->chunk);

	g_free(pair);
}

static GError*
_copy_chunk(const gchar *from, const gchar*to)
{
	GError *err = NULL;
	struct http_pipe_s *p = NULL;
	p = http_pipe_create(from, to);
	err = http_pipe_run(p);
	http_pipe_destroy(p);
	return err;
}

static void
_duplicate_and_ref(struct policy_check_s *pc, struct m2v2_check_error_s *flaw)
{
	GError *e = NULL;
	GSList *beans = NULL;
	struct meta1_service_url_s *m2u = NULL;
	GArray *pairs = flaw->param.chunk_dupli_toofew.pairs;
	gint count = flaw->param.chunk_dupli_toofew.count;
	guint dist = flaw->param.chunk_dupli_toofew.dist;
	m2v2_chunk_pair_t *pair = &g_array_index(pairs, m2v2_chunk_pair_t, 0);
	if (!pair) {
		GRID_ERROR("Cannot repair, no valid copy available");
		return;
	}

	GSList *used_loc = _pairs_extract_srvinfo(pc->lbpool, pairs);
	GSList *new_pairs = _get_additional_pairs_DUPLI(pc, pair, used_loc,
			count, dist);

	for (GSList *l = new_pairs; l; l = l->next) {
		if (!l->data)
			continue;
		m2v2_chunk_pair_t *p2 = l->data;
		e = _copy_chunk(CHUNKS_get_id(pair->chunk)->str,
				CHUNKS_get_id(p2->chunk)->str);
		if (NULL != e)
			break;
		else {
			beans = g_slist_prepend(beans, pair->chunk);
			beans = g_slist_prepend(beans, pair->content);
			beans = g_slist_prepend(beans, p2->chunk);
			beans = g_slist_prepend(beans, p2->content);
		}
	}

	if (e == NULL) {
		/* We need the entire content */
		beans = g_slist_prepend(beans, flaw->header);
		beans = g_slist_prepend(beans, flaw->alias);
		/* Send reconstruction informations to the META-2 */
		m2u = meta1_unpack_url(pc->m2urlv[0]);
		e = m2v2_remote_execute_OVERWRITE(m2u->host, NULL, pc->url, beans);
	}

	if (e != NULL) {
		GRID_ERROR("Failed to upload new copies : %s", e->message);
		g_clear_error(&e);
	}
	g_slist_free_full(new_pairs, _clear_chunk_pair);
	g_slist_free_full(used_loc, (GDestroyNotify) g_free);
	g_slist_free(beans);
	meta1_service_url_clean(m2u);
}

// Calls m2v2_remote_execute_RAW_DEL() on the given list of beans, and just
// print a WARNING if an error occurs.
static void
_unref_in_m2v2(gchar **urlv, struct hc_url_s *url, GSList *beans)
{
	struct meta1_service_url_s *m2u = NULL;
	m2u = meta1_unpack_url(urlv[0]);
	GError *err = m2v2_remote_execute_RAW_DEL(m2u->host, NULL, url, beans);
	if (NULL != err) {
		GRID_WARN("REPAIR failed : failed to unref %u contents : (%d) %s",
				g_slist_length(beans), err->code, err->message);
		g_clear_error(&err);
	}
	meta1_service_url_clean(m2u);
}

// Only unref the chunks from the meta2, because of the deduplication they are
// maybe still referenced by other (versions of) contents_header. In facts, it
// is only necessary to drop the contents linking the chunks to the headers.
static void
_unref_exceeding_contents_in_m2v2(struct policy_check_s *pc, GArray *pairs,
		gint count)
{
	GSList *kept = NULL, *excluded = NULL;
	GRID_TRACE2("%s(%p,%p,%d)", __FUNCTION__, pc, pairs, count);

	// Poll some contents for the deletion
	for (guint i=0; i<pairs->len ;++i) {
		struct m2v2_chunk_pair_s *pair;
		pair = &g_array_index(pairs, struct m2v2_chunk_pair_s, i);
		excluded = g_slist_prepend(excluded, pair->content);
	}
	kept = _gslist_poll_n(&excluded, count);

	// Now trigger the deletion on the meta2
	_unref_in_m2v2(pc->m2urlv, pc->url, excluded);

	g_slist_free(excluded);
	g_slist_free(kept);
}

static void
_unref_one_content_in_m2v2(struct policy_check_s *pc, m2v2_chunk_pair_t *pair)
{
	GSList *singleton = g_slist_prepend(NULL, pair->content);
	_unref_in_m2v2(pc->m2urlv, pc->url, singleton);
	g_slist_free(singleton);
}

// Extract a quorum of pairs based on the given comparison function, and
// unref all the contents out of that quorum.
static void
_unref_outof_quorum(struct policy_check_s *pc, GArray *pairs,
		GCompareFunc cmp)
{
	GArray *quorum, *out;
	if (_get_quorum(pairs, cmp, &quorum, &out)) {
		GSList *broken = _pairs_extract_contents(out);
		if (broken) {
			_unref_in_m2v2(pc->m2urlv, pc->url, broken);
			g_slist_free(broken);
		}
		g_array_free(quorum, TRUE);
		g_array_free(out, TRUE);
	}
}

// Extract a quorum of pairs based on the chunk's hash, and unref all the
// contents out of the quorum.
static void
_unref_outof_quorum_size(struct policy_check_s *pc, GArray *pairs)
{
	gint cmp(gpointer p0, gpointer p1) {
		gint64 s0 = CHUNKS_get_size(((m2v2_chunk_pair_t*)p0)->chunk);
		gint64 s1 = CHUNKS_get_size(((m2v2_chunk_pair_t*)p1)->chunk);
		return s1 > s0 ? 1 : (s1 < s0 ? -1 : 0);
	}
	_unref_outof_quorum(pc, pairs, (GCompareFunc)cmp);
}

// Extract a quorum of pairs based on the chunk's size, and unref all the
// contents out of the quorum.
static void
_unref_outof_quorum_hash(struct policy_check_s *pc, GArray *pairs)
{
	gint cmp(gpointer p0, gpointer p1) {
		GByteArray *h0, *h1;
		h0 = CHUNKS_get_hash(((m2v2_chunk_pair_t*)p0)->chunk);
		h1 = CHUNKS_get_hash(((m2v2_chunk_pair_t*)p1)->chunk);
		return metautils_gba_cmp(h0, h1);
	}
	_unref_outof_quorum(pc, pairs, (GCompareFunc)cmp);
}

static void
_tell_content_is_lost(struct policy_check_s *pc, struct m2v2_check_error_s *flaw)
{
	(void) pc;
	(void) flaw;
	GRID_WARN("ALIAS CORRUPTED");
}

static void
_repair_missing_rain_chunks(struct policy_check_s *pc,
		struct m2v2_check_error_s *flaw)
{
	GRID_INFO("Starting RAIN reconstruction");
	GError *err = NULL;
	struct rainx_rec_params_s params = {
			flaw->param.rain_toofew.metachunk_pos,
			flaw->alias,
			flaw->header,
			flaw->param.rain_toofew.pairs_data,
			flaw->param.rain_toofew.pairs_parity,
			flaw->param.rain_toofew.pairs_unavailable};
	err = rainx_reconstruct(pc->url, pc->nsinfo, &params, NULL, TRUE, FALSE);
	if (err != NULL) {
		GRID_ERROR("Failed to reconstruct: %s", err->message);
		g_clear_error(&err);
	} else {
		GRID_INFO("RAIN reconstruction succeeded");
	}
}

static gint
_find_unwanted_location(GArray *locations, guint distance_requested)
{
	gboolean error_found = FALSE;
	guint max_errors_pos = 0;
	gint errors[locations->len];
	memset((void*)errors, 0, locations->len * sizeof(gint));
	for (guint i=1; i < locations->len ;++i) {
		for (guint j=0; j < i; ++j) {
			char *l0 = (&((struct chunk_location_s*)locations->data)[j])->location;
			char *l1 = (&((struct chunk_location_s*)locations->data)[i])->location;
			guint distance = distance_between_location(l0, l1);
			if (distance_requested > distance) {
				errors[i]++;
				errors[j]++;
				error_found = TRUE;
			}
		}
	}
	for (guint i = 1; i < locations->len; ++i) {
		if (errors[i] > errors[max_errors_pos]) {
			max_errors_pos = i;
		}
	}
	if (error_found)
		return (gint)max_errors_pos;
	else
		return -1;
}

// TODO: make this func more generic so we can use it for rawx-mover
static GError*
_move_chunks(struct policy_check_s *pc, struct m2v2_check_error_s *flaw,
		struct storage_policy_s *stgpol,
		GSList *chunks_to_move, GSList *chunks_to_keep)
{
	GError *err = NULL;
	GSList *spares = NULL; // keeps spare chunks (to free with data)
	GSList *spare_contents = NULL; // keeps content beans (to free with data)
	GSList *old_contents = NULL; // keeps content beans that should be deleted
	GSList *all_beans = NULL; // all beans of the content (to free without data)
	struct meta1_service_url_s *m1u = NULL;

	// Add chunks_to_keep chunks and contents to the all_beans list
	for (GSList *l = chunks_to_keep; l != NULL; l = l->next) {
		m2v2_chunk_pair_t *pair = l->data;
		all_beans = g_slist_prepend(all_beans, pair->chunk);
		all_beans = g_slist_prepend(all_beans, pair->content);
	}

	// Get spare chunks
	err = get_conditioned_spare_chunks2(pc->lbpool, stgpol, all_beans,
			NULL, &spares, TRUE);
	if (err != NULL) {
		goto _move_chunks_cleanup;
	} else if (g_slist_length(spares) < g_slist_length(chunks_to_move)) {
		err = NEWERROR(CODE_PLATFORM_ERROR, "Did not get enough spare chunks");
		goto _move_chunks_cleanup;
	}

	// Add spare chunks and contents to the all_beans list
	for (GSList *l1 = chunks_to_move, *l2 = spares;
			l1 != NULL;
			l1 = l1->next, l2 = l2->next) {
		m2v2_chunk_pair_t *old = l1->data;
		struct bean_CHUNKS_s *spare = l2->data;
		struct bean_CONTENTS_s *spare_content = NULL;

		err = _copy_chunk(CHUNKS_get_id(old->chunk)->str,
				CHUNKS_get_id(spare)->str);
		if (err != NULL) {
			g_prefix_error(&err, "Failed to copy chunk: ");
			goto _move_chunks_cleanup;
		}

		spare_content = _bean_dup(old->content);
		spare_contents = g_slist_prepend(spare_contents, spare_content);
		CHUNKS_set_hash(spare, CHUNKS_get_hash(old->chunk));
		CHUNKS_set_size(spare, CHUNKS_get_size(old->chunk));
		CHUNKS_set_ctime(spare, CHUNKS_get_ctime(old->chunk));
		CONTENTS_set_chunk_id(spare_content, CHUNKS_get_id(spare));
		all_beans = g_slist_prepend(all_beans, spare);
		all_beans = g_slist_prepend(all_beans, spare_content);
		old_contents = g_slist_prepend(old_contents, old->content);
	}

	// Add alias and content header to the all beans list
	all_beans = g_slist_prepend(all_beans, flaw->header);
	all_beans = g_slist_prepend(all_beans, flaw->alias);

	// Update alias with new chunk beans
	m1u = meta1_unpack_url(pc->m2urlv[0]);
	err = m2v2_remote_execute_OVERWRITE(m1u->host, NULL, pc->url, all_beans);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to reference new chunks: ");
		goto _move_chunks_cleanup;
	}

	// Unreference old chunk beans
	err = m2v2_remote_execute_RAW_DEL(m1u->host, NULL, pc->url,
			old_contents);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to unreference old chunks: ");
	}

_move_chunks_cleanup:

	meta1_service_url_clean(m1u);
	_bean_cleanl2(spares);
	_bean_cleanl2(spare_contents);
	g_slist_free(all_beans);
	g_slist_free(old_contents);

	return err;
}

static void
_repair_bad_distance_chunks(struct policy_check_s *pc,
		struct m2v2_check_error_s *flaw)
{
	gchar *loc = NULL;
	GError *err = NULL;
	GArray *pairs = NULL;
	GArray *locations = NULL;
	GSList *chunks_to_move = NULL; // Pointers from "pairs" array
	GSList *chunks_to_keep = NULL; // Pointers from "pairs" array
	m2v2_chunk_pair_t *pair = NULL;
	struct storage_policy_s *stgpol = NULL;
	const struct data_security_s *datasec = NULL;
	gint error_pos = 0;
	gint distance_requested = 1; // FIXME: load it from policy
	stgpol = storage_policy_init(pc->nsinfo,
			CONTENTS_HEADERS_get_policy(flaw->header)->str);
	datasec = storage_policy_get_data_security(stgpol);
	distance_requested = data_security_get_int64_param(datasec,
			DS_KEY_DISTANCE, 1);

	// Put all chunk pairs in the same array
	if (flaw->type == M2CHK_CHUNK_DUPLI_BAD_DISTANCE) {
		pairs = flaw->param.chunk_dupli_dist.pairs;
		g_array_ref(pairs);
	} else if (flaw->type == M2CHK_CHUNK_RAIN_BAD_DISTANCE) {
		pairs = g_array_new(FALSE, FALSE, sizeof(m2v2_chunk_pair_t));
		g_array_append_vals(pairs, flaw->param.rain_dist.pairs_data->data,
				flaw->param.rain_dist.pairs_data->len);
		g_array_append_vals(pairs, flaw->param.rain_dist.pairs_parity->data,
				flaw->param.rain_dist.pairs_parity->len);
	} else {
		err = NEWERROR(CODE_BAD_REQUEST, "Unknown flaw type: %d", flaw->type);
		goto _repair_cleanup;
	}

	// Compute location of all chunks
	locations = g_array_new(FALSE, FALSE, sizeof(struct chunk_location_s));
	for (guint i = 0; i < pairs->len; ++i) {
		pair = &g_array_index(pairs, m2v2_chunk_pair_t, i);
		loc = location_from_chunk(pair->chunk, pc->lbpool);
		if (loc != NULL) {
			struct chunk_location_s location = {pair, loc};
			g_array_append_val(locations, location);
		} else {
			err = NEWERROR(CODE_PLATFORM_ERROR,
					"Unable to find location of chunk %s",
					CHUNKS_get_id(pair->chunk)->str);
			goto _repair_cleanup;
		}
		loc = NULL;
	}

	// Find problematic locations and put them apart
	do {
		error_pos = _find_unwanted_location(locations, distance_requested);
		if (error_pos != -1) {
			struct chunk_location_s *location = &g_array_index(locations,
					struct chunk_location_s, error_pos);
			chunks_to_move = g_slist_prepend(chunks_to_move,
					location->chunk_pair);
			g_free(location->location);
			g_array_remove_index_fast(locations, error_pos);
		}
	} while (locations->len > 1 && error_pos != -1);

	// Build a list with chunks to keep
	for (guint i = 0; i < locations->len; ++i) {
		struct chunk_location_s *location = &g_array_index(locations,
				struct chunk_location_s, i);
		chunks_to_keep = g_slist_prepend(chunks_to_keep, location->chunk_pair);
	}

	// Call meta2 to move the chunks
	err = _move_chunks(pc, flaw, stgpol, chunks_to_move, chunks_to_keep);

_repair_cleanup:
	for (guint i = 0; i < locations->len ;++i) {
		g_free(g_array_index(locations, struct chunk_location_s, i).location);
	}
	g_array_unref(locations);
	g_array_unref(pairs);
	g_slist_free(chunks_to_move);
	g_slist_free(chunks_to_keep);
	storage_policy_clean(stgpol);

	if (err != NULL) {
		GRID_ERROR("Failed to repair: %s", err->message);
		g_clear_error(&err);
	} else {
		GRID_INFO("Success");
	}
}

static void
_repair_bad_stgclass(struct policy_check_s *pc, struct m2v2_check_error_s *flaw)
{
	GError *err = NULL;
	GSList *chunks_to_move = NULL;
	GSList *chunks_to_keep = NULL;
	m2v2_chunk_pair_t *pair = NULL;
	GArray *bad_pairs = flaw->param.stgclass.bad_pairs;
	GArray *all_pairs = flaw->param.stgclass.all_pairs;
	struct storage_policy_s *stgpol = NULL;
	stgpol = storage_policy_init(pc->nsinfo,
			CONTENTS_HEADERS_get_policy(flaw->header)->str);

	gint comp_pair(m2v2_chunk_pair_t *a, m2v2_chunk_pair_t *b)
	{
		return (gint)(((void*)a->chunk) - ((void*)b->chunk));
	}

	for (guint i = 0; i < bad_pairs->len; ++i) {
		pair = &g_array_index(bad_pairs, m2v2_chunk_pair_t, i);
		chunks_to_move = g_slist_prepend(chunks_to_move, pair);
	}

	for (guint i = 0; i < all_pairs->len; ++i) {
		pair = &g_array_index(all_pairs, m2v2_chunk_pair_t, i);
		if (NULL == g_slist_find_custom(chunks_to_move, pair,
				(GCompareFunc)comp_pair)) {
			chunks_to_keep = g_slist_prepend(chunks_to_keep, pair);
		}
	}
	err = _move_chunks(pc, flaw, stgpol, chunks_to_move, chunks_to_keep);

	g_slist_free(chunks_to_move);
	g_slist_free(chunks_to_keep);
	storage_policy_clean(stgpol);

	if (err != NULL) {
		GRID_ERROR("Failed to repair: %s", err->message);
		g_clear_error(&err);
	} else {
		GRID_INFO("Success");
	}
}

// All the information necessary for the rebuild should be available in
// the 'flaw' structure (concerned chunks an contents, header, alias),
// or at least all the information is publicly accessible in the 'pc'
// structure.
static void
_repair_single_flaw(struct policy_check_s *pc, struct m2v2_check_error_s *flaw)
{
	GRID_INFO("Flaw being repaired");
	switch (flaw->type) {
		case M2CHK_CHUNK_DUPLI_BADPOS:
			_unref_one_content_in_m2v2(pc, &flaw->param.dupli_badpos.pair);
			break;
		case M2CHK_CHUNK_DUPLI_GAP:
			_tell_content_is_lost(pc, flaw);
			break;
		case M2CHK_CHUNK_DUPLI_HASH:
			_unref_outof_quorum_hash(pc, flaw->param.chunk_dupli_hashes.pairs);
			break;
		case M2CHK_CHUNK_DUPLI_SIZE:
			_unref_outof_quorum_size(pc, flaw->param.chunk_dupli_sizes.pairs);
			break;
		case M2CHK_CHUNK_DUPLI_TOOMUCH:
			_unref_exceeding_contents_in_m2v2(pc,
					flaw->param.chunk_dupli_toomuch.pairs,
					flaw->param.chunk_dupli_toomuch.count);
			break;
		case M2CHK_CHUNK_DUPLI_TOOFEW:
			_duplicate_and_ref(pc, flaw);

			break;
		case M2CHK_CHUNK_DUPLI_BAD_DISTANCE:
			_repair_bad_distance_chunks(pc, flaw);
			break;

		case M2CHK_CHUNK_RAIN_BADPOS:
			_unref_one_content_in_m2v2(pc, &flaw->param.rain_badpos.pair);
			break;
		case M2CHK_CHUNK_RAIN_TOOMUCH:
			_tell_content_is_lost(pc, flaw);
			break;
		case M2CHK_CHUNK_RAIN_TOOFEW:
			_repair_missing_rain_chunks(pc, flaw);
			break;
		case M2CHK_CHUNK_RAIN_LOST:
			_tell_content_is_lost(pc, flaw);
			break;
		case M2CHK_CHUNK_RAIN_BAD_DISTANCE:
			_repair_bad_distance_chunks(pc, flaw);
			break;

		case M2CHK_CONTENT_SIZE_MISMATCH:
			_tell_content_is_lost(pc, flaw);
			break;

		case M2CHK_CONTENT_STGCLASS:
			_repair_bad_stgclass(pc, flaw);
			break;
		case M2CHK_RAWX_UNKNOWN:
			/* TODO : move to another location, then re-register */
			GRID_WARN("not implemented");
			break;
	}
}


//------------------------------------------------------------------------------
// Initial test download
//------------------------------------------------------------------------------

static GError *
download_and_check_chunk_bean(struct bean_CHUNKS_s *chunk)
{
	int md5_data_handler(void *u, const char *b, const size_t blen) {
		if (b && blen)
			g_checksum_update((GChecksum*)u, (guint8*)b, blen);
		return 0;
	}

	GError *err = NULL;
	GChecksum *checksum = NULL;
	ne_session *session = NULL;
	ne_request *request = NULL;

	GRID_DEBUG("Checking the MD5 of [%s]", CHUNKS_get_id(chunk)->str);

	// Prepare the DL context
	err = _request_prepare("GET", CHUNKS_get_id(chunk)->str, &session, &request);
	if (NULL != err)
		return err;
	checksum = g_checksum_new(G_CHECKSUM_MD5);

	ne_add_response_body_reader(request, ne_accept_2xx, md5_data_handler, checksum);
	err = _request_dispatch(session, request);
	ne_request_destroy(request);
	request = NULL;
	ne_session_destroy(session);
	session = NULL;

	if (NULL != err) {
		g_checksum_free(checksum);
		checksum = NULL;
		return err;
	}

	// Check the metadata are identical
	guint8 buf[32];
	gsize buflen = sizeof(buf);
	g_checksum_get_digest(checksum, buf, &buflen);
	g_checksum_free(checksum);
	checksum = NULL;

	GByteArray *h = CHUNKS_get_hash(chunk);
	if (buflen != h->len)
		err = NEWERROR(500, "Hash mismatch (length)");
	else if (0 != memcmp(h->data, buf, buflen))
		err = NEWERROR(500, "Hash mismatch (value)");

	// TODO Force the storage policy
	return err;
}

static void
_check_chunks_availability(struct policy_check_s *pc, GPtrArray *unavailable)
{
	for (guint i=0; i < pc->check->chunks->len ;) {
		struct bean_CHUNKS_s *chunk = g_ptr_array_index(pc->check->chunks, i);
		GError *err = download_and_check_chunk_bean(chunk);
		if (NULL != err) {
			int code = err->code;
			GRID_ERROR("Chunk unreachable [%s]: (%d) %s",
					CHUNKS_get_id(chunk)->str, code, err->message);
			g_clear_error(&err);
			if (code == 10060 || code == 10061) {
				// Unknown status
				++ i;
			}
			else {
				// To be unreferenced
				g_ptr_array_remove_index_fast(pc->check->chunks, i);
				g_ptr_array_add(unavailable, chunk);
			}
		}
		else {
			GRID_DEBUG("Chunk OK [%s]", CHUNKS_get_id(chunk)->str);
			++i;
		}
	}
}

GError *
policy_load_beans(struct policy_check_s *pc)
{
	gboolean done = FALSE;
	GError *err = NULL;

	err = hc_resolve_reference_service(pc->resolver, pc->url, "meta2", &pc->m2urlv);
	g_assert(err != NULL || pc->m2urlv != NULL);
	if (err != NULL) {
		g_prefix_error(&err, "Meta2 resolution error: ");
		return err;
	}

	for (gchar **u = pc->m2urlv; !done && !err && *u ;++u) {
		struct meta1_service_url_s *m1u;
		GSList *beans = NULL;

		if (!*u || !(m1u = meta1_unpack_url(*u)))
			continue;

		err = m2v2_remote_execute_GET(m1u->host, NULL, pc->url, 0, &beans);
		meta1_service_url_clean(m1u);

		if (NULL != err) {
			int code = err->code;
			GRID_ERROR("META2 request error : (%d) %s", err->code, err->message);
			if (code != CODE_CONTENT_NOTFOUND)
				g_clear_error(&err);
		}
		else {
			m2v2_check_feed_with_bean_list(pc->check, beans);
			_bean_cleanl2(beans);
			done = TRUE;
		}
	}

	if (!done && !err)
		err = NEWERROR(500, "META2 content location failure");
	if (err) {
		if (pc->m2urlv) {
			g_strfreev(pc->m2urlv);
			pc->m2urlv = NULL;
		}
	}
	return err;
}

static GError*
_policy_check_repair(struct policy_check_s *pc)
{
	GRID_WARN("Now managing %u detected flaws", pc->check->flaws->len);

	for (guint i=0; i < pc->check->flaws->len ;++i) {
		struct m2v2_check_error_s *flaw;
		if (!(flaw = g_ptr_array_index(pc->check->flaws, i)))
			continue;
		_repair_single_flaw(pc, flaw);
	}

	return NULL;
}

GError*
policy_check_and_repair(struct policy_check_s *pc)
{
	GError *err = NULL;

	_check_chunks_availability(pc, pc->check->unavail_chunks);

	if (NULL != (err = m2v2_check_consistency(pc->check))) {
		GRID_WARN("Check error");
		return err;
	}

	GRID_INFO("Check done: %u flaws found", pc->check->flaws->len);
	if (!pc->check_only && pc->check->flaws->len)
		err = _policy_check_repair(pc);
	return err;
}

