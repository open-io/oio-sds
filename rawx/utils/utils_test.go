// OpenIO SDS Go rawx
// Copyright (C) 2024 OVH SAS
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

package utils

import "testing"

func TestChunkIdValidator(t *testing.T) {
	if !IsValidChunkId("0000E122BD649923098E2FC3681078F44962BFB4775E512AD2BC64CEFFBE62BA") {
		t.Fatal("unexpectedly invalid chunk id")
	}
	if IsValidChunkId("0000E122BD649923098E2FC3681078F44962BFB4775E512AD2BC64CEFFBE62BA.pending") {
		t.Fatal("unexpectedly valid pending chunk name")
	}
	if IsValidChunkId("0000E122BD649923098E2FC3681078F44962BFB4775E512AD2BC64CEFFBE62B") {
		t.Fatal("unexpectedly valid short chunk name")
	}
	if IsValidChunkId("0000E122BD649923098E2FC3681078F44962BFB4775E512AD2BC64CEFFBE62BX") {
		t.Fatal("unexpectedly valid non-hexa chunk name")
	}
	if IsValidChunkId(".") {
		t.Fatal("unexpectedly valid special path")
	}
	if IsValidChunkId("") {
		t.Fatal("unexpectedly valid empty chunk name")
	}
	if IsValidChunkId("0000E122BD649923098E") {
		t.Fatal("unexpectedly valid chunk id")
	}
}
