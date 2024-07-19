// OpenIO SDS Go rawx
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package defs

const (
	AttrNameFullPrefix = "user.oio.content.fullpath:"
)

const (
	AttrNameContainerID        = "user.grid.content.container"
	AttrNameContentPath        = "user.grid.content.path"
	AttrNameContentVersion     = "user.grid.content.version"
	AttrNameContentID          = "user.grid.content.id"
	AttrNameContentChunkMethod = "user.grid.content.chunk_method"
	AttrNameContentStgPol      = "user.grid.content.storage_policy"
	AttrNameMetachunkChecksum  = "user.grid.metachunk.hash"
	AttrNameMetachunkSize      = "user.grid.metachunk.size"
	AttrNameChunkID            = "user.grid.chunk.id"
	AttrNameChunkPosition      = "user.grid.chunk.position"
	AttrNameChunkChecksum      = "user.grid.chunk.hash"
	AttrNameChunkSize          = "user.grid.chunk.size"
	AttrNameCompression        = "user.grid.compression"
)

const (
	CompressionOff     = "off"
	CompressionLzw     = "lzw"
	CompressionZlib    = "zlib"
	CompressionDeflate = "deflate"
)

const (
	HeaderNameFullpath            = "X-oio-Chunk-Meta-Full-Path"
	HeaderNameContainerID         = "X-oio-Chunk-Meta-Container-Id"
	HeaderNameContentPath         = "X-oio-Chunk-Meta-Content-Path"
	HeaderNameContentVersion      = "X-oio-Chunk-Meta-Content-Version"
	HeaderNameContentID           = "X-oio-Chunk-Meta-Content-Id"
	HeaderNameContentStgPol       = "X-oio-Chunk-Meta-Content-Storage-Policy"
	HeaderNameContentChunkMethod  = "X-oio-Chunk-Meta-Content-Chunk-Method"
	HeaderNameChunkPosition       = "X-oio-Chunk-Meta-Chunk-Pos"
	HeaderNameChunkSize           = "X-oio-Chunk-Meta-Chunk-Size"
	HeaderNameChunkChecksum       = "X-oio-Chunk-Meta-Chunk-Hash"
	HeaderNameMetachunkSize       = "X-oio-Chunk-Meta-Metachunk-Size"
	HeaderNameMetachunkChecksum   = "X-oio-Chunk-Meta-Metachunk-Hash"
	HeaderNameNonOptimalPlacement = "X-oio-Chunk-Meta-Non-Optimal-Placement"
	HeaderNameChunkID             = "X-oio-Chunk-Meta-Chunk-Id"
)

const (
	HeaderNameCheckHash = "X-oio-check-hash"
	HeaderNameOioReqId  = "X-oio-req-id"
	HeaderLenOioReqId   = 63
	HeaderNameTransId   = "X-trans-id"
	HeaderNameError     = "X-Error"
)

const (
	// Use this value to disable a call to fadvise()
	ConfigFadviseNone = iota

	// Just tell the kernel that further accesses will consume the file
	// sequentially, using FADV_SEQUENTIAL
	ConfigFadviseYes = iota

	// Use this value to advise the kernel to avoid caching the file
	// using FADV_DONTNEED
	ConfigFadviseNoCache = iota

	// Use this value to advise the kernel to keep the fie in cache
	// using FADV_WILLNEED + the general FADV_SEQUENTIAL
	ConfigFadviseCache = iota
)

const (
	ConfigDefaultShallowCopy = false
	ConfigDefaultFallocate   = false
	ConfigDefaultSyncFile    = false
	ConfigDefaultSyncDir     = false

	// By default, no fadvise() will be called before committing a chunk
	ConfigDefaultFadviseUpload = ConfigFadviseNone

	// By default, no fadvise() will be called before download a chunk
	ConfigDefaultFadviseDownload = ConfigFadviseNone

	// Is HTTP "Connection: keep-alive" allowed in replies?
	// Set this value to false to make the RAWX server deny reusing
	// connections.
	ConfigDefaultHttpKeepalive = true

	// Are events allowed
	ConfigDefaultEvents = true

	// By default, should the Nagle algorithm be suspended when a connection
	// is established. Only works for HTTP/1.* when a raw TCP connection is
	// used.
	ConfigDefaultNoDelay = false

	// By default, should the TCP_CORK be set (resp. removed) when a connection
	// becomes active (resp. inactive). Only works for HTTP/1.* when a raw TCP
	// connection is used.
	ConfigDefaultCork = false

	// By default, should the O_NONBLOCK flag be set when opening a file?
	// It turns out that the impact on Go is not weak. The presence of the
	// flag induces many syscalls.
	ConfigDefaultOpenNonblock = false
)

const (
	// Default length of the Go channel in front of the access log goroutine.
	ConfigDefaultAccessLogQueueLength = 4096

	// Should successful GET requests be logged by default
	ConfigDefaultAccessLogGet = true

	// Should successful PUT requests be logged by default
	ConfigDefaultAccessLogPut = true

	// Should successful POST requests be logged by default
	ConfigDefaultAccessLogPost = true

	// Should successful DELETE requests be logged by default
	ConfigDefaultAccessLogDelete = true
)

const (
	// Default size (in bytes) of each buffer allocated for xattr operations
	XattrBufferSizeDefault = 16 * 1024

	// Total amount (in bytes) of buffers allocated for xattr operations
	XattrBufferTotalSizeDefault = 4 * 1024 * 1024
)

const (
	// Default size (in bytes) of each buffer allocated for the upload
	UploadBufferSizeDefault = 2 * 1024 * 1024

	// Total amount (in bytes) of buffers allocated for uploads
	UploadBufferTotalSizeDefault = 128 * 1024 * 1024

	// Size (in bytes) used as a threshold to allow read().
	// In other words: we do not read() if the available space in the buffer is less than this value
	UploadBatchSize int = 2048

	// Maximum size (in bytes) of the upload buffer
	UploadBufferSizeMax int = 8 * 1024 * 1024

	// Minimum size (in bytes) of the upload buffer
	UploadBufferSizeMin int = 32768

	// Specifies the extension size when Fallocate is called to prepare file placeholders
	UploadExtensionSize int64 = 16 * 1024 * 1024
)

const (
	HashWidthDefault = 3
	HashDepthDefault = 1

	PutOpenModeDefault  = 0644
	PutMkdirModeDefault = 0755
)

const (
	ChecksumAlways = iota
	ChecksumNever  = iota
	ChecksumSmart  = iota
)

const (
	DirOioEtc          = "/etc/oio"
	PathOioConfigFile  = DirOioEtc + "/sds.conf"
	PathOioConfigDir   = DirOioEtc + "/sds.conf.d"
	PathOioConfigLocal = ".oio/sds.conf"
)

const (
	FolderNonOptimalPlacement = "non_optimal_placement"
	FolderOrphans             = "orphans"
)

const (
	ConfigOioEventAgent     = "event-agent"
	ConfigOioEventAgentRawx = "event-agent.rawx"
	ConfigOioEventExchange  = "events.amqp.exchange_name"
	ConfigOioEventTopic     = "events.kafka.topic_name"
)

const (
	// How long (in seconds) might a client take to send the request headers
	TimeoutReadHeader = 60

	// How long (in seconds) might a client take to send its whole request
	TimeoutReadRequest = 900

	// How long (in seconds) might it takes to emit the whole reply
	TimeoutWrite = 900

	// How long (in seconds) might a connection stay idle (between two requests)
	TimeoutIdle = 3600
)

const (
	// Number of connection attempts to the event broker
	EventConnAttempts = 3

	// How long (in seconds) the connection to the event broker may take
	EventConnTimeout = 0.5

	// How long (in seconds) the sending of an event may take
	EventSendTimeout = 5
)

const (
	ECMethodPrefix = "ec/"
)

const (
	EventTypeNewChunk = "storage.chunk.new"

	EventTypeDelChunk = "storage.chunk.deleted"

	// Parallelism factor in situations of single targets
	NotifierSingleMultiplier = 4

	// Parallelism factor in situations of multiple targets
	NotifierMultipleMultiplier = 1

	// Number of slots in the channel feeding the notifier backends
	NotifierPipeSizeDefault = 32768
)

const (
	BeanstalkTubeDefault = "oio"
)

const (
	// Error code returned when the client closes the connection before
	// sending the whole request body
	HttpStatusClientClosedRequest = 499
)

const (
	ConfigPrefixKafka = "kafka_"
)

const (
	StatsdPrefixDefault = "openio.rawx"
)
