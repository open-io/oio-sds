/*!
 * @file
 */

#ifndef GRID__SVCPOLICY_H
# define GRID__SVCPOLICY_H 1
# include <glib.h>

/**
 * @defgroup metautils_svcpolicy Configuration policies for services load-balanced
 * @ingroup metautils_utils
 * @{
 */

/* forward declaration */
struct hashstr_s;

/* hidden structures */
struct service_update_policies_s;

/*! Tells how to update a service in place
 */
enum service_update_policy_e
{
	SVCUPD_NOT_SPECIFIED = 0, /*!< do not touch the services in place */
	SVCUPD_NONE,   /*!< do not touch services in place */
	SVCUPD_APPEND, /*!< keep down services, append a new if all are down */
	SVCUPD_REPLACE /*!< Replace the last service down is none is up */
};

/*!
 * @return
 */
struct service_update_policies_s* service_update_policies_create(void);

/*!
 * @param pol
 */
void service_update_policies_destroy(struct service_update_policies_s *pol);

/**
 * @param pol
 * @param htype
 * @return
 */
gboolean service_update_tagfilter2(struct service_update_policies_s *pol,
		const struct hashstr_s *htype, gchar **pname, gchar **pvalue);
/**
 * @param pol
 * @param htype
 * @return
 */
gboolean service_update_tagfilter(struct service_update_policies_s *pol,
		const gchar *type, gchar **pname, gchar **pvalue);

/*!
 * @param pol
 * @param htype
 * @return
 */
enum service_update_policy_e service_howto_update2(
		struct service_update_policies_s *pol,
		const struct hashstr_s *htype);

/*!
 * @param pol
 * @param type
 * @return
 * @see service_howto_update2()
 */
enum service_update_policy_e service_howto_update(
		struct service_update_policies_s *pol,
		const gchar *type);

/*!
 * @param pol
 * @param htype
 * @return 0 if unspecified, or the number of expected replicas
 */
guint service_howmany_replicas2(
		struct service_update_policies_s *pol,
		struct hashstr_s *htype);

/*!
 * @param pol
 * @param type
 * @return 0 if unspecified, or the number of expected replicas
 * @see service_howmany_replicas2()
 */
guint service_howmany_replicas(
		struct service_update_policies_s *pol,
		const gchar *type);

/*!
 * @param pol
 * @param htype
 * @return 0 if unspecified, or the number of expected replicas
 */
guint service_howmany_distance2(
		struct service_update_policies_s *pol,
		struct hashstr_s *htype);

/*!
 * @param pol
 * @param type
 * @return 0 if unspecified, or the number of expected replicas
 * @see service_howmany_replicas2()
 */
guint service_howmany_distance(
		struct service_update_policies_s *pol,
		const gchar *type);

/*!
 * @param pol
 * @param cfg
 * @return
 */
GError* service_update_reconfigure(struct service_update_policies_s *pol,
		const gchar *cfg);

/*!
 * @param pol
 * @return
 */
gchar* service_update_policies_dump(struct service_update_policies_s *pol);

/*! @} */

#endif /* GRID__SVCPOLICY_H */
