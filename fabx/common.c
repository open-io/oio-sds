/*
OpenIO SDS fabx
Copyright (C) 2018-2019 CEA "CEA <info@cea.fr>"
Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS

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

#include "common.h"

guint64 caps = FI_MSG;

int
fi_lookup(const char *host, const char *port,
		gboolean local, struct fi_info **result)
{
	struct fi_info *out = NULL;
	struct fi_info *hints = fi_allocinfo();
	*result = NULL;

	hints->caps = caps;
	hints->addr_format = FI_SOCKADDR;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->domain_attr->data_progress = FI_PROGRESS_AUTO;
    hints->domain_attr->control_progress = FI_PROGRESS_AUTO;
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->rx_attr->msg_order = FI_ORDER_SAS;

	int rc = fi_getinfo(FI_VERSION(1, 6),
			host, port,
			local ? FI_SOURCE : 0,
			hints, &out);
	if (rc != 0)
		return rc;

	for (struct fi_info *fi0 = out; fi0; fi0 = fi0->next) {
		if (((fi0->caps & caps) == caps)
				&& fi0->ep_attr->protocol == FI_PROTO_SOCK_TCP
				&& fi0->addr_format == FI_SOCKADDR_IN
				&& fi0->ep_attr->type == FI_EP_MSG) {
			*result = fi_dupinfo(fi0);
			break;
		}
	}

	fi_freeinfo(hints);
	fi_freeinfo(out);
	return (*result == NULL) ? -FI_ENODATA : 0;
}

