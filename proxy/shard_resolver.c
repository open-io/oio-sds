/*
OpenIO SDS sharding resolver
Copyright (C) 2021-2022 OVH SAS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <core/internals.h>
#include <core/lrutree.h>
#include <core/oio_core.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <proxy/shard_resolver.h>
#include <resolver/resolver_variables.h>

struct shard_resolver_s
{
	GMutex lock;
	struct lru_tree_s *roots;
};

static gint
_shard_cmp(gconstpointer a, gconstpointer b)
{
	struct bean_SHARD_RANGE_s *shard1 = (struct bean_SHARD_RANGE_s *) a;
	struct bean_SHARD_RANGE_s *shard2 = (struct bean_SHARD_RANGE_s *) b;

	gboolean shard1_is_fake = FALSE;
	GByteArray *shard1_cid = SHARD_RANGE_get_cid(shard1);
	if (!shard1_cid || shard1_cid->len == 0) {
		shard1_is_fake = TRUE;
	}
	if (shard1_is_fake) {
		GString *path = SHARD_RANGE_get_lower(shard1);
		GString *lower = SHARD_RANGE_get_lower(shard2);
		GString *upper = SHARD_RANGE_get_upper(shard2);
		if (lower->len && g_strcmp0(path->str, lower->str) <= 0) {
			return -1;
		}
		if (upper->len && g_strcmp0(path->str, upper->str) > 0) {
			return 1;
		}
		return 0;
	}

	// Sort by lower (and upper)
	GString *shard1_lower = SHARD_RANGE_get_lower(shard1);
	GString *shard1_upper = SHARD_RANGE_get_upper(shard1);
	GString *shard2_lower = SHARD_RANGE_get_lower(shard2);
	GString *shard2_upper = SHARD_RANGE_get_upper(shard2);
	gint res = g_strcmp0(shard1_lower->str, shard2_lower->str);
	if (res) {
		return res;
	}
	res = g_strcmp0(shard1_upper->str, shard2_upper->str);
	if (res) {
		if (res < 0 && shard1_upper->len == 0) {
			return 1;
		}
		if (res > 0 && shard2_upper->len == 0) {
			return -1;
		}
	}
	return res;
}

struct shard_resolver_s*
shard_resolver_create(void)
{
	struct shard_resolver_s *resolver = g_malloc0(
			sizeof(struct shard_resolver_s));
	resolver->roots = lru_tree_create(
			(GCompareFunc)g_strcmp0, g_free,
			(GDestroyNotify)lru_tree_destroy, 0);
	g_mutex_init(&resolver->lock);
	return resolver;
}

void
shard_resolver_destroy(struct shard_resolver_s *resolver)
{
	if (!resolver) {
		return;
	}
	if (resolver->roots) {
		lru_tree_destroy(resolver->roots);
		resolver->roots = NULL;
	}
	g_mutex_clear(&resolver->lock);
	g_free(resolver);
}

gpointer
shard_resolver_get_cached(struct shard_resolver_s *resolver,
		struct oio_url_s *url)
{
	if (!resolver || !resolver->roots || !url) {
		return NULL;
	}
	const gchar *root_cid = oio_url_get(url, OIOURL_HEXID);
	const gchar *path = oio_url_get(url, OIOURL_PATH);
	if (!root_cid || !path) {
		return NULL;
	}
	GRID_DEBUG("Searching cached shard for the path '%s' the root %s",
			path, root_cid);

	struct lru_tree_s *shards = NULL;
	gpointer search = NULL, result = NULL, shard = NULL;

	// Create fake shard
	search = _bean_create(&descr_struct_SHARD_RANGE);
	SHARD_RANGE_set2_lower(search, path);
	SHARD_RANGE_set2_upper(search, path);

	g_mutex_lock(&resolver->lock);
	shards = lru_tree_get(resolver->roots, root_cid);
	if (shards) {
		shard = lru_tree_get(shards, search);
		if (shard) {
			GRID_DEBUG("Cached shard found managing path '%s' for the root %s",
					path, root_cid);
			result = _bean_dup(shard);
		} else {
			GRID_DEBUG("No cached shard manages path '%s' for the root %s",
					path, root_cid);
		}
	} else {
		GRID_DEBUG("No cached shard for the root %s", root_cid);
	}
	g_mutex_unlock(&resolver->lock);
	_bean_clean(search);

	return result;
}

void
shard_resolver_store(struct shard_resolver_s *resolver,
		struct oio_url_s *url, gpointer shard)
{
	if (!oio_resolver_cache_enabled) {
		return;
	}
	if (!resolver || !resolver->roots || !url || !shard) {
		return;
	}
	const gchar *root_cid = oio_url_get(url, OIOURL_HEXID);
	if (!root_cid) {
		return;
	}
	GRID_DEBUG("Caching shard with range between '%s' and '%s' "
			"for the root %s",
			SHARD_RANGE_get_lower(shard)->str,
			SHARD_RANGE_get_upper(shard)->str,
			root_cid);

	struct lru_tree_s *shards = NULL;
	gpointer value = _bean_dup(shard);

	g_mutex_lock(&resolver->lock);
	shards = lru_tree_get(resolver->roots, root_cid);
	if (!shards) {
		shards = lru_tree_create(_shard_cmp, _bean_clean, NULL, 0);
		lru_tree_insert(resolver->roots, g_strdup(root_cid), shards);
	}
	// /!\WARNING/!\ Use the value as the key
	lru_tree_insert(shards, value, value);
	// Check that the number of shards to keep in the cache is not exceeded
	if (oio_shard_resolver_shards_default_max > 0) {
		lru_tree_remove_exceeding(shards,
				oio_shard_resolver_shards_default_max);
	}
	g_mutex_unlock(&resolver->lock);
}

void
shard_resolver_forget(struct shard_resolver_s *resolver,
		struct oio_url_s *url, gpointer shard)
{
	if (!oio_resolver_cache_enabled) {
		return;
	}
	if (!resolver || !resolver->roots || !url || !shard) {
		return;
	}
	const gchar *root_cid = oio_url_get(url, OIOURL_HEXID);
	if (!root_cid) {
		return;
	}
	GRID_DEBUG("Removing cached shard with range between '%s' and '%s' "
			"for the root %s",
			SHARD_RANGE_get_lower(shard)->str,
			SHARD_RANGE_get_upper(shard)->str,
			root_cid);

	g_mutex_lock(&resolver->lock);
	gpointer shards = lru_tree_get(resolver->roots, root_cid);
	if (shards) {
		// Do not keep an entry empty
		lru_tree_remove(shards, shard);
		if (lru_tree_count(resolver->roots) == 0) {
			lru_tree_remove(resolver->roots, root_cid);
		}
	}
	g_mutex_unlock(&resolver->lock);
}

void
shard_resolver_forget_root(struct shard_resolver_s *resolver,
		struct oio_url_s *url)
{
	if (!oio_resolver_cache_enabled) {
		return;
	}
	if (!resolver || !resolver->roots || !url) {
		return;
	}
	const gchar *root_cid = oio_url_get(url, OIOURL_HEXID);
	if (!root_cid) {
		return;
	}

	g_mutex_lock(&resolver->lock);
	lru_tree_remove(resolver->roots, root_cid);
	g_mutex_unlock(&resolver->lock);
}

guint
shard_resolver_expire(struct shard_resolver_s *resolver)
{
	if (!resolver || !resolver->roots) {
		return 0;
	}

	guint count = 0;
	g_mutex_lock(&resolver->lock);
	const gint64 now = oio_ext_monotonic_time();
	if (oio_shard_resolver_root_default_ttl > 0) {
		count = lru_tree_remove_older(resolver->roots,
				OLDEST(now, oio_shard_resolver_root_default_ttl));
	}
	g_mutex_unlock(&resolver->lock);
	return count;
}

guint
shard_resolver_purge(struct shard_resolver_s *resolver)
{
	if (!resolver || !resolver->roots) {
		return 0;
	}

	guint count = 0;
	g_mutex_lock(&resolver->lock);
	if (oio_shard_resolver_root_default_max > 0) {
		count = lru_tree_remove_exceeding(resolver->roots,
				oio_shard_resolver_root_default_max);
	}
	g_mutex_unlock(&resolver->lock);
	return count;
}

void
shard_resolver_flush(struct shard_resolver_s *resolver)
{
	if (!resolver || !resolver->roots) {
		return;
	}

	g_mutex_lock(&resolver->lock);
	lru_tree_remove_exceeding(resolver->roots, 0);
	g_mutex_unlock(&resolver->lock);
}
