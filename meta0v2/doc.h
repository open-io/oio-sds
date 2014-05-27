
/**
 * @page meta0v2
 */

/**
 * @defgroup meta0v2_backend Backend
 * @ingroup meta0v2
 * @brief
 * @details
 */

/**
 * @defgroup meta0v2_gridd Gridd request dispatcher
 * @ingroup meta0v2
 * @brief
 * @details
 */

/**
 * @defgroup meta0v2_remote Client for RPC
 * @ingroup meta0v2
 * @brief
 * @details
 */

/** 
 * @defgroup meta0v2_utils Content handling features
 * @ingroup meta0v2
 * @brief META0 cache handling features
 *
 * @details Let's consider a meta0 cache. A set of container's ID prefixes
 * associated to META1 addresses. Historically only one address was associated
 * to each prefix and a dedicated structure (meta0_info_t) was used to store and
 * serialize the mappings. The in-memory cache quite easy because we only used
 * the prefix (2 bytes) to access the address in an array.
 *
 * Now the access needs are more sophisticated. The replication of the META1
 * now allows several addresses for each PREFIX, and this number might vary.
 * Furthermore, there is no official limitation on this number. An array was
 * not sufficient anymore.
 *
 * In addition, we sometimes want to collect all the prefixes for a single
 * META1.
 *
 * Then we consider the same information but mapped by different ways:
 * - a GSList of meta0_info_t, the legacy structures
 * - a GTree mapping META1 url's (text) to GArray (of guint16 prefixes)
 * - a GPtrArray of 65536 entries (the possible values of the prefix)
 *
 * The first is used by existing codecs.
 * The second is use to quickly access the prefixes by URL
 * The third is the evolution of the previous flat array of addresses.
 *
 * The purpose of the present file is to provides an API for useful
 * conversions.
 */

