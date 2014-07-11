#include "internals.h"

MESSAGE
meta2_remote_build_request(GError **err, GByteArray *id, char *name)
{
        MESSAGE msg=NULL;

        message_create(&msg, err);
	if (!msg)
		return NULL;

        if (id)
                message_set_ID (msg, id->data, id->len, err);
        if (name)
                message_set_NAME (msg, name, strlen(name), err);

        return msg;
}

