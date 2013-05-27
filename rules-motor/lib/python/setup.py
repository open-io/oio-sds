# Copyright (C) 2013 AtoS Worldline
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

#!/usr/bin/python

import sys
import string

def howto_install_setuptools():
	print """Error: You need setuptools Python package!"""

try:
	from setuptools import setup
	params = {
		'zip_safe': True
		}
except ImportError:
	for arg in sys.argv:
		if string.find(arg, 'egg') != -1:
			howto_install_setuptools()
			sys.exit(1)
	from distutils.core import setup
	params = {}

params.update({
	'name': 'python rules motor',
	'version': '0.0.1b',
	'description': 'rules motor python part',
	'author': 'Xin Lin',
	'license': 'Proprietary',
	'packages': ['pymotor']
	})

apply(setup, (), params);
