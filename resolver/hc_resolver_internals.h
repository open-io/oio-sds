#ifndef HC_RESOLVER__INTERNALS__H
# define HC_RESOLVER__INTERNALS__H 1
# include <resolver/hc_resolver.h>
# include <glib.h>

#ifndef  HC_RESOLVER_DEFAULT_MAX_SERVICES
# define HC_RESOLVER_DEFAULT_MAX_SERVICES 200000
#endif

#ifndef  HC_RESOLVER_DEFAULT_TTL_SERVICES
# define HC_RESOLVER_DEFAULT_TTL_SERVICES 3600
#endif

// No expiration and no max for content of META0 & Conscience
#ifndef  HC_RESOLVER_DEFAULT_MAX_CSM0
# define HC_RESOLVER_DEFAULT_MAX_CSM0 0
#endif

#ifndef  HC_RESOLVER_DEFAULT_TTL_CSM0
# define HC_RESOLVER_DEFAULT_TTL_CSM0 0
#endif

struct lru_tree_s;

struct cached_element_s
{
	time_t use;
	guint32 count_elements;
	gchar s[]; /* Must be the last! */
};

struct lru_ext_s
{
	struct lru_tree_s *cache;
	time_t ttl;
	guint max;
};

struct hc_resolver_s
{
	GMutex *lock;
	struct lru_ext_s services;
	struct lru_ext_s csm0;
	time_t bogonow;
	enum hc_resolver_flags_e flags;
};

#endif /* HC_RESOLVER__INTERNALS__H */
