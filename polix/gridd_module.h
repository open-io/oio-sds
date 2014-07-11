#ifndef __GRIDD_MODULE_H
#define __GRIDD_MODULE_H

enum event_status_e {
	ES_ERROR_DEF = -2,
	ES_ERROR_TMP = -1,
	ES_NOTFOUND  = 0,
	ES_WORKING   = 1,
	ES_DONE      = 2
};

#ifdef MODULE_NAME
# undef MODULE_NAME
#endif
#define MODULE_NAME "polix"

#ifndef  META2_EVTFIELD_NAMESPACE
#  define META2_EVTFIELD_NAMESPACE "NS"
#endif
#ifndef  META2_EVTFIELD_CPATH
#  define META2_EVTFIELD_CPATH "CPATH"
#endif
#ifndef  META2_EVTFIELD_CID
#  define META2_EVTFIELD_CID "CID"
#endif
#ifndef META2_EVTFIELD_M2ADDR
#  define META2_EVTFIELD_M2ADDR "M2ADDR"
#endif
#ifndef META2_EVTFIELD_URL
#  define META2_EVTFIELD_URL "URL"
#endif
#ifndef META2_EVTFIELD_CHUNKS
#  define  META2_EVTFIELD_CHUNKS "CHUNKS"
#endif


//gboolean reply_set_status_code(struct reply_context_s *ctx, const gchar *str_ueid,
//	    enum event_status_e *status, GError **error);

#endif
