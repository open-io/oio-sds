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

package logger

import (
	"bytes"
	"log"
)

type EventLogEvent struct {
	Topic string
	Event string
}

func (evt EventLogEvent) String() string {
	var output bytes.Buffer
	err := EventLogTemplate.Execute(&output, evt)

	if err != nil {
		log.Printf("Error while executing eventLogTemplate: %v", err)
		return ""
	}
	return output.String()
}

func LogEvent(evt EventLogEvent) {
	logger.WriteEvent(evt.String())
}
