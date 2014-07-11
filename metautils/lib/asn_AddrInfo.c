#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.addr_info.asn"
#endif

#include <arpa/inet.h>
#include <errno.h>

#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_AddrInfo.h"

gboolean
addr_info_ASN2API(const AddrInfo_t * asn, addr_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	api->port = 0;
	if (asn->port) {
		/*
			For compatibility reasons with GRID V1 
			we need to handle 32bits port
			this should be removed in GRID V2
		*/
		if (asn->port->size > 2) {
			guint32 port32;
			asn_INTEGER_to_uint32(asn->port, &port32);
			api->port = htonl(port32);
		} else {
			guint16 port16;
			asn_INTEGER_to_uint16(asn->port, &port16);
			api->port = htons(port16);
		}
	}

	switch (asn->ip.present) {
	case AddrInfo__ip_PR_ipv4:
		api->type = TADDR_V4;
		if (asn->ip.choice.ipv4.buf)
			memcpy(&(api->addr), asn->ip.choice.ipv4.buf, MIN(4, asn->ip.choice.ipv4.size));
		break;

	case AddrInfo__ip_PR_ipv6:
		api->type = TADDR_V6;
		if (asn->ip.choice.ipv6.buf)
			memcpy(&(api->addr), asn->ip.choice.ipv6.buf, MIN(16, asn->ip.choice.ipv6.size));
		break;

	case AddrInfo__ip_PR_NOTHING:
		return FALSE;
	}

	return TRUE;
}


gboolean
addr_info_API2ASN(const addr_info_t * api, AddrInfo_t * asn)
{
	gchar str_addr[128];

	if (!api || !asn)
		return FALSE;

	asn->ip.present = AddrInfo__ip_PR_NOTHING;

	switch (api->type) {
	case TADDR_V4:
		OCTET_STRING_fromBuf(&(asn->ip.choice.ipv4), (char *) &(api->addr), 4);
		asn->ip.present = AddrInfo__ip_PR_ipv4;
		break;

	case TADDR_V6:
		OCTET_STRING_fromBuf(&(asn->ip.choice.ipv6), (char *) &(api->addr), 16);
		asn->ip.present = AddrInfo__ip_PR_ipv6;
		break;

	default:
		g_assert_not_reached();
		memset(str_addr, 0x00, sizeof(str_addr));
		addr_info_to_string(api, str_addr, sizeof(str_addr));
		WARN("Invalid address (%i) type for '%s'", api->type, str_addr);
		return FALSE;
	}

	asn->port = NULL;
	asn->port = g_try_new0(INTEGER_t, 1);
	if (!asn->port)
		return FALSE;

	/*
		For compatibility reasons with GRID V1 
		we need to handle 32bits port
		this should be removed in GRID V2
	*/
	if (0 != asn_uint32_to_INTEGER(asn->port, ntohl(api->port)))
		return FALSE;

	return TRUE;
}


void
addr_info_cleanASN(AddrInfo_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_AddrInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_AddrInfo, asn);

	errno = 0;
}

