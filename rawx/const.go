// OpenIO SDS Go rawx
// Copyright (C) 2019-2020 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

const (
	OioVersion = "4.2"
)

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
	AttrNameOioVersion         = "user.grid.oio.version"
	AttrNameCompression        = "user.grid.compression"
)

const (
	compressionOff     = "off"
	compressionLzw     = "lzw"
	compressionZlib    = "zlib"
	compressionDeflate = "deflate"
)

const (
	HeaderNameFullpath           = "X-oio-Chunk-Meta-Full-Path"
	HeaderNameContainerID        = "X-oio-Chunk-Meta-Container-Id"
	HeaderNameContentPath        = "X-oio-Chunk-Meta-Content-Path"
	HeaderNameContentVersion     = "X-oio-Chunk-Meta-Content-Version"
	HeaderNameContentID          = "X-oio-Chunk-Meta-Content-Id"
	HeaderNameContentStgPol      = "X-oio-Chunk-Meta-Content-Storage-Policy"
	HeaderNameContentChunkMethod = "X-oio-Chunk-Meta-Content-Chunk-Method"
	HeaderNameChunkPosition      = "X-oio-Chunk-Meta-Chunk-Pos"
	HeaderNameChunkSize          = "X-oio-Chunk-Meta-Chunk-Size"
	HeaderNameChunkChecksum      = "X-oio-Chunk-Meta-Chunk-Hash"
	HeaderNameMetachunkSize      = "X-oio-Chunk-Meta-Metachunk-Size"
	HeaderNameMetachunkChecksum  = "X-oio-Chunk-Meta-Metachunk-Hash"
	HeaderNameChunkID            = "X-oio-Chunk-Meta-Chunk-Id"
	HeaderNameXattrVersion       = "X-oio-Chunk-Meta-Oio-Version"
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
	configFadviseNone = iota

	// Just tell the kernel that further accesses will consume the file
	// sequentially, using FADV_SEQUENTIAL
	configFadviseYes = iota

	// Use this value to advise the kernel to avoid caching the file
	// using FADV_DONTNEED
	configFadviseNocache = iota

	// Use this value to advise the kernel to keep the fie in cache
	// using FADV_WILLNEED + the general FADV_SEQUENTIAL
	configFadviseCache = iota
)

const (
	configDefaultFallocate = false
	configDefaultSyncFile  = false
	configDefaultSyncDir   = false

	// By default, no fadvise() will be called before commiting a chunk
	configDefaultFadviseUpload = configFadviseNone

	// By default, no fadvise() will be called before download a chunk
	configDefaultFadviseDownload = configFadviseNone

	// Is HTTP "Connection: keep-alive" allowed in replies?
	// Set this value to false to make the RAWX server deny reusing
	// connections.
	configDefaultHttpKeepalive = true

	// Are events allowed
	configDefaultEvents = true

	// By default, should the Nagle algorithm be suspended when a connection
	// is established. Only works for HTTP/1.* when a raw TCP connection is
	// used.
	configDefaultNoDelay = false

	// By default, should the TCP_CORK be set (resp. removed) when a connection
	// becomes active (resp. inactive). Only works for HTTP/1.* when a raw TCP
	// connection is used.
	configDefaultCork = false

	// By default, should the O_NONBLOCK flag be set when opening a file?
	// It turns out that the impact on Go is not weak. The presence of the
	// flag induces many syscalls.
	configDefaultOpenNonblock = false
)

const (
	// Default length of the Go channel in front of the access log goroutine.
	configAccessLogQueueDefaultLength = 4096

	// Should successful GET requests be logged by default
	configAccessLogDefaultGet = true

	// Should successful PUT requests be logged by default
	configAccessLogDefaultPut = true

	// Should successful DELETE requests be logged by default
	configAccessLogDefaultDelete = true
)

const (
	// Default size (in bytes) of each buffer allocated for xattr operations
	xattrBufferSizeDefault = 2 * 1024

	// Total amount (in bytes) of buffers allocated for xattr operations
	xattrBufferTotalSizeDefault = 256 * 1024

	// Default size (in bytes) of each buffer allocated for the upload
	uploadBufferSizeDefault = 2 * 1024 * 1024

	// Total amount (in bytes) of buffers allocated for uploads
	uploadBufferTotalSizeDefault = 128 * 1024 * 1024

	// Size (in bytes) used as a threshold to allow read().
	// In other words: we do not read() if the available space in the buffer is less than this value
	uploadBatchSize int = 2048

	// Maximum size (in bytes) of the upload buffer
	uploadBufferSizeMax int = 8 * 1024 * 1024

	// Minimum size (in bytes) of the upload buffer
	uploadBufferSizeMin int = 32768

	// Specifies the extension size when Fallocate is called to prepare file placeholders
	uploadExtensionSize int64 = 16 * 1024 * 1024
)

const (
	hashWidth    = 3
	hashDepth    = 1
	putOpenMode  = 0644
	putMkdirMode = 0755
)

const (
	checksumAlways = iota
	checksumNever  = iota
	checksumSmart  = iota
)

const (
	oioEtcDir          = "/etc/oio"
	oioConfigFilePath  = oioEtcDir + "/sds.conf"
	oioConfigDirPath   = oioEtcDir + "/sds.conf.d"
	oioConfigLocalPath = ".oio/sds.conf"
)

const (
	oioConfigEventAgent = "event-agent"
)

const (
	timeoutReadHeader = 60

	// How long (in seconds) might a client take to send its whole request
	timeoutReadRequest = 900

	// How long (in seconds) might it takes to emit the whole reply
	timeoutWrite = 900

	// How long (in seconds) might a connection stay idle (between two requests)
	timeoutIdle = 3600
)

const (
	ECMethodPrefix = "ec/"
)

const (
	eventTypeNewChunk = "storage.chunk.new"

	eventTypeDelChunk = "storage.chunk.deleted"

	// Parallelism factor in situations of single targets
	notifierSingleMultiplier = 4

	// Parallelism factor in situations of multiple targets
	notifierMultipleMultiplier = 1

	// Number of slots in the channel feeding the notifier backends
	notifierDefaultPipeSize = 32768

	beanstalkNotifierDefaultTube = "oio"
)
