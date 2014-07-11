#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.path_info"
#endif

#include "./metautils_internals.h"
#include "./PathInfo.h"
#include "./PathInfoSequence.h"
#include "./asn_PathInfo.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(PathInfo_t),
	sizeof(path_info_t),
	&asn_DEF_PathInfoSequence,
	(abstract_converter_f) path_info_ASN2API,
	(abstract_converter_f) path_info_API2ASN,
	(abstract_asn_cleaner_f) path_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"path_info"
};

DEFINE_MARSHALLER_GBA(path_info_marshall_gba);
DEFINE_MARSHALLER(path_info_marshall);
DEFINE_UNMARSHALLER(path_info_unmarshall);
DEFINE_BODY_MANAGER(path_info_concat, path_info_unmarshall);

