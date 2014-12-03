/*!
 * @file lb.h
 */
#ifndef GRID__LB_H
# define GRID__LB_H 1

#include <metautils/lib/metatypes.h>

struct namespace_info_s;
struct service_info_s;
struct addr_info_s;
struct json_object;


/**
 * @defgroup metautils_lb Load-Balancing
 * @ingroup metautils_utils
 * @{
 */

/* Service pool features ---------------------------------------------------- */

/*! A hidden structure representing a pool for a given service type. */
struct grid_lb_s;

/*! thread-safe structure managing several service pools, and holding the
 * load-balancing policies. */
struct grid_lbpool_s;

/*! A way to iterate on services from a mono-type pool. */
struct grid_lb_iterator_s;

/*! Used to iterate over service_info while reloading the pool. */
typedef gboolean (*service_provider_f) (struct service_info_s **p_si);


/* Mono-service pool features ---------------------------------------------- */

/*! Create a service pool ready to work */
struct grid_lb_s* grid_lb_init(const gchar *ns, const gchar *srvtype);

/*! frees the structure and all ots components. lb is invalid after. */
void grid_lb_clean(struct grid_lb_s *lb);

/*! Configures the standard-deviation shortening. Shortens to the index where
 * the service's score is the average + standard deviation. When several
 * shortenings are configured, the strongest is taken into consideration. */
void grid_lb_set_SD_shortening(struct grid_lb_s *lb, gboolean on);

/*! Configures the fixed-ratio shortening. When several shortenings are
 * configured, the strongest is taken into consideration. */
void grid_lb_set_shorten_ratio(struct grid_lb_s *lb, gdouble ratio);

/*! Sets a hook to be called each time a resource is got from the
 * load-balancer. This helps providing lazy/timeout (re)loading. */
void grid_lb_set_use_hook(struct grid_lb_s *lb, void (*use_hook)(void));

/*! Internally calls a flush then feeds all the services coming
 * out of the provider hook. */
void grid_lb_reload(struct grid_lb_s *lb, service_provider_f provide);

/*! Reloads the pool with the given JSON services. */
GError*  grid_lb_reload_json_object(struct grid_lb_s *lb,
		struct json_object *obj);

/*! Reloads the pool with the given JSON encoded services. */
GError*  grid_lb_reload_json(struct grid_lb_s *lb, const gchar *encoded);

/*! Returns the number of elements in the given pool, after shorten ratio. */
gsize grid_lb_count(struct grid_lb_s *lb);

/** Returns the number of elements in the given pool. */
gsize grid_lb_count_all(struct grid_lb_s *lb);

/*! Tests if a service is still available. Unavailable means either
 * absent, a score less or equal to zero. This function performs
 * a check on the service type. */
gboolean grid_lb_is_srv_available(struct grid_lb_s *lb,
		const struct service_info_s *si);

/*! Idem for a given service. @see grid_lb_is_srv_available() */
gboolean grid_lb_is_addr_available(struct grid_lb_s *lb,
		const struct addr_info_s *ai);

struct service_info_s* grid_lb_get_service_from_url(struct grid_lb_s *lb,
		const gchar *url);

struct service_info_s* grid_lb_get_service_from_addr(struct grid_lb_s *lb,
		const struct addr_info_s *ai);

/*! Reconfigures the pool, Acquires/Releases the lock on pool. */
void grid_lb_configure_options(struct grid_lb_s *lb, const gchar *opts);


/* Iterators features ------------------------------------------------------ */

/*!
 * If no type is provided, the default is choosen (RR).
 *
 * Types accepted:
 * - SINGLE : simple iterator, run the services once
 * - RR (default) : simple round-robin
 * - WRR : weighted round-robin (using the service's weight)
 * - SRR : synonym for WRR
 * - RAND : simple random pick
 * - WRAND : weighted random-pick (using the service's weight)
 * - SRAND : synonym for WRAND
 *
 * @param lb
 * @param type
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_init(struct grid_lb_s *lb,
		const gchar *type);

/*! @see grid_lb_iterator_init() */
struct grid_lb_iterator_s* grid_lb_iterator_single_run(struct grid_lb_s *lb);

/*! @see grid_lb_iterator_init() */
struct grid_lb_iterator_s* grid_lb_iterator_round_robin(struct grid_lb_s *lb);

/*! @see grid_lb_iterator_init() */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_round_robin(struct grid_lb_s *lb);

/*! @see grid_lb_iterator_init() */
struct grid_lb_iterator_s* grid_lb_iterator_random(struct grid_lb_s *lb);

/*! @see grid_lb_iterator_init() */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_random(struct grid_lb_s *lb);

/*! Build an iterator based on another iterator. The concurrency is managed
 * internally. */
struct grid_lb_iterator_s* grid_lb_iterator_share(struct grid_lb_iterator_s *i);

/*! Clean the iterator and all its internals structures */
void grid_lb_iterator_clean(struct grid_lb_iterator_s *iter);

/*! @see grid_lb_configure_options() */
void grid_lb_iterator_configure(struct grid_lb_iterator_s *iter,
		const gchar *val);

/*!  */
gboolean grid_lb_iterator_is_srv_available(struct grid_lb_iterator_s *iter,
		const struct service_info_s *si);

/*!  */
gboolean grid_lb_iterator_is_addr_available(struct grid_lb_iterator_s *iter,
		const struct addr_info_s *ai);

/*!  */
gboolean grid_lb_iterator_is_url_available(struct grid_lb_iterator_s *iter,
		const gchar *url);

/* Polling ----------------------------------------------------------------- */

typedef gboolean (*service_filter) (struct service_info_s *si, gpointer hook_data);

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

/*! @see grid_lb_iterator_next_set() */
gboolean grid_lb_iterator_next_set2(struct grid_lb_iterator_s *iter,
		struct service_info_s ***si, struct lb_next_opt_ext_s *opt);


/* Multi-services pool features --------------------------------------------- */

/*! Create a lbpool ready to use (no service declared). */
struct grid_lbpool_s* grid_lbpool_create(const gchar *ns);

/*! Frees the memory used by the lbpool */
void grid_lbpool_destroy(struct grid_lbpool_s *glp);

/*! Returns the NS name associated to this pool. */
const gchar* grid_lbpool_namespace(struct grid_lbpool_s *glp);

/*! Ensure each type is managed according to the NS configuration. */
void grid_lbpool_reconfigure(struct grid_lbpool_s *glp,
		struct namespace_info_s *ni);

/*! Ensure the type is managed according to the given configuration */
void grid_lbpool_configure_string(struct grid_lbpool_s *glp,
		const gchar *srvtype, const gchar *cfg);

/*! Ensure the type is managed (pool+iterator) abd return the pool. */
struct grid_lb_s * grid_lbpool_ensure_lb (struct grid_lbpool_s *glp,
		const gchar *srvtype);

/*! Returns the pool for the given type, or NULL if unknown */
struct grid_lb_s * grid_lbpool_get_lb (struct grid_lbpool_s *glp,
		const gchar *srvtype);

/*! Ensure the type is managed (pool+iterator) abd return the iterator. */
struct grid_lb_iterator_s * grid_lbpool_ensure_iterator (
		struct grid_lbpool_s *glp, const gchar *srvtype);

/*! Return the iterator for the given type, if managed (or NULL otherwise) */
struct grid_lb_iterator_s* grid_lbpool_get_iterator(
		struct grid_lbpool_s *glp, const gchar *srvtype);

/*! @see grid_lb_reload() */
void grid_lbpool_reload(struct grid_lbpool_s *glp, const gchar *srvtype,
		service_provider_f provider);

/*! @see grid_lb_reload() */
GError* grid_lbpool_reload_json_object(struct grid_lbpool_s *glp, const gchar *srvtype,
		struct json_object *obj);

/*! @see grid_lb_reload() */
GError* grid_lbpool_reload_json(struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *encoded);

/*!  */
struct service_info_s* grid_lbpool_get_service_from_url(
		struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *url);

/*! @} */

#endif /* GRID__LB_H */
