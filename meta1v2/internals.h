#ifndef META1__INTERNALS_H
# define META1__INTERNALS_H 1

/**
 * @addtogroup meta1v2_misc 
 * @{
 */

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>


#define CONNECT_RETRY_DELAY 3

# ifndef META1_EVT_TOPIC
#  define META1_EVT_TOPIC "redc.meta1"
# endif

/**
 * @param reqname
 * @param cid
 * @param err
 * @return
 */
MESSAGE meta1_create_message(const gchar *reqname, const container_id_t cid,
		GError **err);


/**
 * @param req
 * @param fname
 * @param addr
 * @param err
 * @return
 */
gboolean meta1_enheader_addr_list(MESSAGE req, const gchar *fname,
		GSList *addr, GError **err);

/** @} */

#endif
