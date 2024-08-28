package global

import (
	"openio-sds/rawx/defs"
	"openio-sds/rawx/utils"
)

var XattrBufferPool = utils.NewBufferPool(defs.XattrBufferTotalSizeDefault, defs.XattrBufferSizeDefault)
