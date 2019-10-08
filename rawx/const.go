// OpenIO SDS Go rawx
// Copyright (C) 2019 OpenIO SAS
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
	AttrNameCompression        = "user.grid.compression"
	AttrNameOioVersion         = "user.grid.oio.version"
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
	configDefaultFallocate = true
	configDefaultSyncFile  = false
	configDefaultSyncDir   = false
)

const (
	// Default size (in KiB) of the buffer allocated for the upload
	uploadBufferDefault int = 2048

	// Size (in bytes) used as a threshold to allow read().
	// In other words: we do not read() if the available space in the buffer is less than this value
	uploadBatchSize int = 2048

	// Maximum size (in bytes) of the upload buffer
	uploadBufferSizeMax int = 8 * 1024 * 1024

	// Minimum size (in bytes) of the upload buffer
	uploadBufferSizeMin int = 65536

	// Specifies the extension size when Fallocate is called to prepare file placeholders
	uploadExtensionSize int64 = 64 * 1024 * 1024
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
