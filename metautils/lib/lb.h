/*!
 * @file lb.h
 */
#ifndef GRID__LB_H
# define GRID__LB_H 1

#include <metautils/lib/metatypes.h>

struct namespace_info_s;
struct service_info_s;
struct addr_info_s;

/**
 * @defgroup metautils_lb Load-Balancing
 * @ingroup metautils_utils
 * @{
 */

/* Service pool features ---------------------------------------------------- */

/*!
 * A hidden structure representing a pool for a given service type.
 */
struct grid_lb_s;

/*!
 * thread-safe structure managing several service pools, and holding the
 * load-balancing policies.
 */
struct grid_lbpool_s;

/*!
 * A way to iterate on services from a mono-type pool.
 */
struct grid_lb_iterator_s;

/*! Used to iterate over service_info while reloading the pool.
 *
 * @param p_si
 * @return
 */
typedef gboolean (*service_provider_f) (struct service_info_s **p_si);

/* Mono-service pool features ---------------------------------------------- */

void grid_lb_set_SD_shortening(struct grid_lb_s *lb, gboolean on);

void grid_lb_set_shorten_ratio(struct grid_lb_s *lb, gdouble ratio);

/*! Create a service pool ready to work
 *
 * @param ns
 * @param srvtype
 * @return
 */
struct grid_lb_s* grid_lb_init(const gchar *ns, const gchar *srvtype);

/*! Sets a hook to be called each time a resource is got from the
 * load-balancer. This helps providing lazy/timeout (re)loading.
 *
 * @param lb
 * @param use_hook
 */
void grid_lb_set_use_hook(struct grid_lb_s *lb, void (*use_hook)(void));

/*! frees the structure and all ots components. lb is invalid after.
 *
 * @param lb
 */
void grid_lb_clean(struct grid_lb_s *lb);

/*! Internally calls a flush then feeds all the services coming
 * out of the provider hook.
 *
 * @param lb
 * @param provide
 */
void grid_lb_reload(struct grid_lb_s *lb, service_provider_f provide);

/**
 * @param lb not NULL
 * @return the number of elements in the given pool, after shorten ratio.
 */
gsize grid_lb_count(struct grid_lb_s *lb);

/**
 * @param lb not NULL
 * @return the number of elements in the given pool.
 */
gsize grid_lb_count_all(struct grid_lb_s *lb);

/*! Tests if a service is still available. Unavailable means either
 * absent, a score less or equal to zero. This function performs
 * a check on the service type.
 *
 * @param lb
 * @param si
 * @return
 */
gboolean grid_lb_is_srv_available(struct grid_lb_s *lb,
		const struct service_info_s *si);

/*! Idem for a given service
 *
 * @see grid_lb_is_srv_available()
 * @param lb
 * @param ai
 * @return
 */
gboolean grid_lb_is_addr_available(struct grid_lb_s *lb,
		const struct addr_info_s *ai);

struct service_info_s* grid_lb_get_service_from_url(struct grid_lb_s *lb,
		const gchar *url);

struct service_info_s* grid_lb_get_service_from_addr(struct grid_lb_s *lb,
		const struct addr_info_s *ai);

/* Iterators features ------------------------------------------------------ */

/*!
 * @param lb
 */
struct grid_lb_iterator_s* grid_lb_iterator_single_run(struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_scored_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_random(struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_random(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_scored_random(
		struct grid_lb_s *lb);

typedef gboolean (*service_filter) (struct service_info_s *si, gpointer hook_data);

/*! Build an iterator based on another iterator. The concurrency is managed
 * internally.
 *
 * @param main
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_share(struct grid_lb_iterator_s *i);

/*!
 * If no type is provided, the default is choosen (RR).
 *
 * Types accepted:
 * - SINGLE : simple iterator, run the services once
 * - RR (default) : simple round-robin
 * - WRR : weighted round-robin (using the service's weight)
 * - SRR : weighted round-robin (using the service's score)
 * - RAND : simple random pick
 * - WRAND : weighted random-pick (using the service's weight)
 * - SRAND : weighted random-pick (using the service's score)
 *
 * @param lb
 * @param type
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_init(struct grid_lb_s *lb,
		const gchar *type);

/*! Get the next service from the iterator.
 * @see service_info_clean()
 * @param iter
 * @param si
 * @return
 */
gboolean grid_lb_iterator_next(struct grid_lb_iterator_s *iter,
		struct service_info_s **si);

/*! Get the next service from the iterator.
 * @see service_info_clean()
 * @param iter
 * @param si
 * @param use_shorten_ratio Use (or not) shorten ratio
 * @return
 */
gboolean grid_lb_iterator_next_shorten(struct grid_lb_iterator_s *iter,
		struct service_info_s **si, gboolean use_shorten_ratio);

struct lb_next_opt_filter_s
{
	service_filter hook;
	gpointer data;
};

struct lb_next_opt_simple_s
{
	/** Number of services to get */
	guint max;

	/** Required distance between services */
	guint distance;

	/** Is it allowed to choose several times the same service */
	gboolean duplicates;

	 /** Wanted rawx storage class */
	const struct storage_class_s *stgclass;

	/** Prevent storage class fallbacks */
	gboolean strict_stgclass;
};

struct lb_next_opt_s
{
	/* core requirements */
	struct lb_next_opt_simple_s req;

	/* Additional custom constraints of the services. It is checked for each
	 * probed service, once it already matches the constraints based on the
	 * distance, duplicates, etc. */
	struct lb_next_opt_filter_s filter;
};

struct lb_next_opt_ext_s
{
	/* core requirements */
	struct lb_next_opt_simple_s req;

	/* Additional explicit constraint based on services already polled.
	 * This is typically used to check the distance between a new services
	 * with old ones. */
	GSList *srv_inplace;

	/* Additional explicit constraint */
	GSList *srv_forbidden;

	/* Still another custom filter */
	struct lb_next_opt_filter_s filter;
};

/*!
 * Returns 'max' different services.
 *
 * @param iter not NULL
 * @param si not NULL, set with a NULL-terminated array of (service_info_s*).
 * @param opt Options for the set of services
 * @return FALSE if not satisfiable
 */
gboolean grid_lb_iterator_next_set(struct grid_lb_iterator_s *iter,
		struct service_info_s ***si, struct lb_next_opt_s *opt);

gboolean grid_lb_iterator_next_set2(struct grid_lb_iterator_s *iter,
		struct service_info_s ***si, struct lb_next_opt_ext_s *opt);

/*!
 * @param iter
 * @param si
 * @return
 */
gboolean grid_lb_iterator_is_srv_available(struct grid_lb_iterator_s *iter,
		const struct service_info_s *si);

/*!
 * @param iter
 * @param ai
 * @return
 */
gboolean grid_lb_iterator_is_addr_available(struct grid_lb_iterator_s *iter,
		const struct addr_info_s *ai);

/*!
 * @param iter
 * @param url
 * @return
 */
gboolean grid_lb_iterator_is_url_available(struct grid_lb_iterator_s *iter,
		const gchar *url);

/*! Clean the iterator and all its internals structures
 *
 * @param iter
 */
void grid_lb_iterator_clean(struct grid_lb_iterator_s *iter);

/*!
 * Tests if the storage class of a service complies with
 * a specific storage class.
 *
 * @param wanted_class The class we want to match to
 * @param si The service description
 * @param strict If false, accept equivalent storage classes
 * @return TRUE if storage class match, FALSE otherwise
 */
gboolean grid_lb_check_storage_class(const gchar *wanted_class,
		struct service_info_s *si);

/*!
 * @param iter
 * @param val
 */
void grid_lb_iterator_configure(struct grid_lb_iterator_s *iter,
		const gchar *val);

/**
 * @param opts
 * @param lb
 */
void grid_lb_configure_options(struct grid_lb_s *lb, const gchar *opts);

/* Multi-services pool features --------------------------------------------- */

const gchar* grid_lbpool_namespace(struct grid_lbpool_s *glp);

/*!
 * Create a lbpool ready to use
 * @param ns Not NULL
 */
struct grid_lbpool_s* grid_lbpool_create(const gchar *ns);

/*!
 * Frees the memory used by the lbpool
 * @param glp no-op if NULL
 */
void grid_lbpool_destroy(struct grid_lbpool_s *glp);

/*!
 * Ensure the type is managed and configures it if special configuration is
 * present in the conscience configuration.
 *
 * @param glp
 * @param ni
 */
void grid_lbpool_reconfigure(struct grid_lbpool_s *glp,
		struct namespace_info_s *ni);

/**
 * @param glp
 * @param srvtype
 * @param cfg
 */
void grid_lbpool_configure_string(struct grid_lbpool_s *glp,
		const gchar *srvtype, const gchar *cfg);

/*!
 * @see grid_lb_reload()
 * @param glp
 * @param srvtype
 * @param provider
 */
void grid_lbpool_reload(struct grid_lbpool_s *glp, const gchar *srvtype,
		service_provider_f provider);

/**
 * @param glp
 * @param srvtype
 * @return
 */
struct grid_lb_iterator_s* grid_lbpool_get_iterator(struct grid_lbpool_s *glp,
		const gchar *srvtype);

struct service_info_s* grid_lbpool_get_service_from_url(struct grid_lbpool_s *glp,
		const gchar *srvtype, const gchar *url);

/*! @} */

#endif /* GRID__LB_H */
