#!/usr/bin/python

# config.py, local configuation management
# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import glob, os
import ConfigParser as configparser

def places():
	yield "/etc/oio/sds.conf"
	for f in glob.glob("/etc/oio/sds.conf.d/*"):
		yield f
	yield os.path.expanduser("~/.oio/sds.conf")

def load():
	cfg = configparser.RawConfigParser()
	cfg.read(places())
	return cfg

