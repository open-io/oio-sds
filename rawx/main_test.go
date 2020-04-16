// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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

import (
	"flag"
	"os"
	"testing"
)

var syslogID string
var conf string

func init() {
	flag.StringVar(&syslogID, "test.syslog", "", "Activates syslog traces with the given identifier")
	flag.StringVar(&conf, "test.conf", "", "Path to configuration file")
	flag.Parse()
}

func TestSystem(t *testing.T) {
	os.Args = []string{os.Args[0], "-D", "FOREGROUND", "-s", syslogID, "-f", conf}
	main()
}
