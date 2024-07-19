// OpenIO SDS Go rawx
// Copyright (C) 2024 OVH SAS

package main

import (
	"encoding/json"
	"openio-sds/rawx/utils"
	"reflect"
	"strings"
	"testing"
	"time"

	"openio-sds/rawx/defs"
)

// Validates that the struct can be encoded.
// It, for any reason, a field would be made private (losing its capital letter),
// it wouldn't be encoded/decoded.
func TestNotifierCodec(t *testing.T) {
	r := func() string { return utils.RandomString(16, defs.HexaCharacters) }
	original := encodableEvent{
		EventType: defs.EventTypeDelChunk,
		When:      time.Now().Unix(),
		RequestId: r(),
		Data: eventPayload{
			VolumeId:       r(),
			ChunkHash:      r(),
			ChunkId:        r(),
			ChunkMethod:    r(),
			ChunkPosition:  r(),
			ChunkSize:      r(),
			ContainerId:    r(),
			ContentId:      r(),
			ContentPath:    r(),
			ContentVersion: r(),
			FullPath:       r(),
			MetaChunkHash:  r(),
			MetaChunkSize:  r(),
			ServiceId:      r(),
			StgPol:         r(),
		},
	}

	buf := strings.Builder{}
	_ = json.NewEncoder(&buf).Encode(original)
	t.Log(buf.String())
	var decoded encodableEvent
	_ = json.NewDecoder(strings.NewReader(buf.String())).Decode(&decoded)
	// DeepEqual compares both exported and unexported, as stated in its documentation
	if !reflect.DeepEqual(original, decoded) {
		t.Fatal("original != decoded")
	}
}
